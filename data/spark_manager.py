"""
This module handles PySpark session management and DataFrame operations.
"""
import logging
import os
import sys
import time
from typing import Any, List, Optional

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F

# Get the logger
logger = logging.getLogger("alert_analysis")

def setup_spark(memory: str = "16g") -> SparkSession:
    """Set up and configure a SparkSession with optimized settings for stability and performance."""
    from pyspark.sql import SparkSession
    import sys
    import os
    
    # Set Python executable for both driver and workers
    python_exe = sys.executable
    os.environ["PYSPARK_PYTHON"] = python_exe
    os.environ["PYSPARK_DRIVER_PYTHON"] = python_exe
    
    # Create temp directory if it doesn't exist
    temp_dir = "C:/temp/spark-temp"
    os.makedirs(temp_dir, exist_ok=True)
    
    # Calculate available memory for optimal settings
    import psutil
    system_memory = psutil.virtual_memory().total / (1024 * 1024 * 1024)  # GB
    
    # Use at most 75% of available system memory
    max_memory = min(int(system_memory * 0.75), 32)  # Cap at 32GB
    driver_memory = f"{max_memory}g"
    executor_memory = f"{max_memory}g"
    offheap_memory = f"{max_memory // 2}g"
    
    logger.info(f"Configuring Spark with driver/executor memory: {driver_memory}, offheap: {offheap_memory}")
    
    # Create a SparkSession with settings optimized for stability
    spark = SparkSession.builder \
        .appName("Alert Analysis") \
        .config("spark.driver.memory", driver_memory) \
        .config("spark.executor.memory", executor_memory) \
        .config("spark.python.worker.memory", "4g") \
        .config("spark.driver.maxResultSize", "8g") \
        .config("spark.pyspark.python", python_exe) \
        .config("spark.pyspark.driver.python", python_exe) \
        .config("spark.jars", "postgresql-42.7.5.jar") \
        .config("spark.python.worker.timeout", "3600") \
        .config("spark.network.timeout", "3600s") \
        .config("spark.executor.heartbeatInterval", "240s") \
        .config("spark.sql.shuffle.partitions", "200") \
        .config("spark.sql.adaptive.enabled", "true") \
        .config("spark.memory.offHeap.enabled", "true") \
        .config("spark.memory.offHeap.size", offheap_memory) \
        .config("spark.local.dir", temp_dir) \
        .config("spark.driver.extraJavaOptions", "-XX:+UseG1GC -XX:+HeapDumpOnOutOfMemoryError") \
        .config("spark.executor.extraJavaOptions", "-XX:+UseG1GC -XX:+HeapDumpOnOutOfMemoryError") \
        .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer") \
        .config("spark.kryoserializer.buffer.max", "1g") \
        .config("spark.default.parallelism", "32") \
        .config("spark.sql.files.maxPartitionBytes", "134217728") \
        .config("spark.sql.autoBroadcastJoinThreshold", "52428800") \
        .config("spark.sql.execution.arrow.pyspark.enabled", "true") \
        .config("spark.sql.execution.arrow.maxRecordsPerBatch", "10000") \
        .config("spark.driver.extraJavaOptions", "-Dlog4j.rootCategory=ERROR") \
        .config("spark.executor.extraJavaOptions", "-Dlog4j.rootCategory=ERROR") \
        .config("spark.ui.showConsoleProgress", "false") \
        .getOrCreate()
    
    # Suppress excessive logging
    spark.sparkContext.setLogLevel("ERROR")
    
    logger.info(f"Initialized Spark session with {spark.sparkContext.defaultParallelism} default parallelism")
    return spark

def validate_spark_dataframe(df: DataFrame, required_columns: List[str]) -> bool:
    """
    Validate that a Spark DataFrame has required columns.
    
    Parameters:
    - df: Spark DataFrame to validate
    - required_columns: List of column names required in the DataFrame
    
    Returns:
    - True if all required columns are present, False otherwise
    """
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        logger.error(f"Missing required columns: {missing_columns}")
        return False
    return True

def save_results(
    spark: SparkSession, 
    df: DataFrame, 
    output_path: str, 
    format_type: str, 
    logger: Optional[logging.Logger] = None
) -> bool:
    """
    Save DataFrame results with consistent column ordering.
    
    Parameters:
    - spark: SparkSession
    - df: DataFrame to save
    - output_path: Path to save the results to
    - format_type: Format to save the results in (csv, parquet, json)
    - logger: Optional logger instance
    
    Returns:
    - True if successful, False otherwise
    """
    start_time = time.time()
    
    if logger:
        logger.info(f"Saving results to {output_path} in {format_type} format")
    
    try:
        # IMPORTANT: Ensure consistent column ordering
        # First get all columns except the scores
        all_columns = df.columns
        score_columns = ["anomaly_score", "classification"]
        other_columns = [col for col in all_columns if col not in score_columns]
        
        # Reorder columns with scores at the end
        ordered_columns = other_columns + score_columns
        
        # Create a new DataFrame with the desired column order
        df = df.select(ordered_columns)
        
        # Get row count for partitioning decision
        row_count = df.count()
        
        # For single file output, ensure we have a directory path vs file path
        dir_path = output_path
        file_name = None

        # If path has extension, separate dir path and filename
        if '.' in os.path.basename(output_path):
            dir_path = os.path.dirname(output_path) or '.'
            file_name = os.path.basename(output_path)
        
        # Create temp directory for output
        temp_output = f"{dir_path}/temp_output_{int(time.time())}"
        
        if format_type.lower() == "csv":
            # Always coalesce to 1 file if user specified a filename (not directory)
            if file_name:
                df.coalesce(1).write.mode("overwrite").option("header", "true").csv(temp_output)
            else:
                # Use partitioning for larger datasets without filename
                if row_count > 100000:
                    num_output_files = max(min(row_count // 500000, 20), 4)
                    df.repartition(num_output_files).write.mode("overwrite").option("header", "true").csv(temp_output)
                else:
                    df.coalesce(1).write.mode("overwrite").option("header", "true").csv(temp_output)
            
            # If specific filename was provided, rename the output part file
            if file_name:
                # Find the data file (part-00000...)
                import glob
                part_files = glob.glob(f"{temp_output}/part-*")
                if part_files:
                    # Read the file content
                    from shutil import copyfile                   
                    # Create the target path
                    if not os.path.exists(dir_path):
                        os.makedirs(dir_path)
                    
                    # Copy the file to the desired name
                    copyfile(part_files[0], output_path)
                    
                    # Clean up temp directory
                    import shutil
                    shutil.rmtree(temp_output, ignore_errors=True)
                    
                    if logger:
                        logger.info(f"Created single CSV file at {output_path}")
        elif format_type.lower() == "parquet":
            # Use snappy compression
            df.coalesce(1).write.mode("overwrite").option("compression", "snappy").parquet(output_path)
            if logger:
                logger.info(f"Created Parquet file at {output_path}")
        elif format_type.lower() == "json":
            df.coalesce(1).write.mode("overwrite").json(output_path)
            if logger:
                logger.info(f"Created JSON file at {output_path}")
        else:
            if logger:
                logger.warning(f"Unsupported format: {format_type}. Defaulting to CSV.")
            df.coalesce(1).write.mode("overwrite").option("header", "true").csv(output_path)
        
        if logger:
            logger.info(f"Results saved successfully in {time.time() - start_time:.2f} seconds")
        return True
    except Exception as e:
        if logger:
            logger.error(f"Error saving results: {str(e)}")
        else:
            print(f"Error saving results: {str(e)}")
        return False

def get_spark_session() -> Optional[SparkSession]:
    """
    Get the active Spark session if it exists, or create a new one.
    
    Returns:
    - SparkSession object or None if Spark is not available
    """
    try:
        spark = SparkSession.getActiveSession()
        if spark is None:
            # No active session, create a new one
            spark = setup_spark()
        return spark
    except Exception as e:
        logger.error(f"Error getting or creating Spark session: {str(e)}")
        return None

def stop_spark(spark: Optional[SparkSession] = None) -> None:
    """
    Safely stop the Spark session.
    
    Parameters:
    - spark: Optional SparkSession to stop. If None, attempts to get active session.
    """
    try:
        if spark is None:
            spark = SparkSession.getActiveSession()
        
        if spark is not None:
            spark.stop()
            logger.info("Spark session stopped")
    except Exception as e:
        logger.error(f"Error stopping Spark session: {str(e)}")

def add_derived_columns(spark_df):
    """Add derived columns needed for analysis to a DataFrame"""
    import pyspark.sql.functions as F
    
    if spark_df is None:
        logger.error("Cannot add derived columns to None DataFrame")
        return None
        
    # Add hour_of_day column if it doesn't exist
    if "timestamp" in spark_df.columns:
        if "hour_of_day" not in spark_df.columns:
            spark_df = spark_df.withColumn("hour_of_day", F.hour(F.to_timestamp("timestamp")))
        
        # Add is_weekend column (1=Sunday, 7=Saturday in PySpark's dayofweek)
        spark_df = spark_df.withColumn("is_weekend", F.dayofweek(F.to_timestamp("timestamp")).isin([1, 7]))
    
    # Ensure proper types for numeric fields
    if "occurrence" in spark_df.columns:
        spark_df = spark_df.withColumn("occurrence", F.col("occurrence").cast("int"))
    
    if "dest_port" in spark_df.columns:
        spark_df = spark_df.withColumn("dest_port", F.col("dest_port").cast("int"))
    
    if "hour_of_day" in spark_df.columns:
        spark_df = spark_df.withColumn("hour_of_day", F.col("hour_of_day").cast("int"))
    
    return spark_df

def optimize_partitioning(spark_df, input_count=None):
    """
    Optimize partitioning for a Spark DataFrame based on data size.
    
    Parameters:
    - spark_df: The Spark DataFrame to optimize
    - input_count: Optional pre-computed count of records (to avoid recounting)
    
    Returns:
    - Optimized DataFrame with appropriate partitioning
    """
    if input_count is None:
        try:
            input_count = spark_df.count()
        except:
            # If counting fails, use a conservative estimate
            logger.warning("Unable to count records, using default partitioning")
            return spark_df
    
    # Get current partitioning
    current_partitions = spark_df.rdd.getNumPartitions()
    
    # Calculate optimal partitions - 1 partition per ~50K records, min 16, max 1000
    if input_count > 100000:
        optimal_partitions = min(max(16, input_count // 50000), 1000)
        
        # Only repartition if significantly different
        if abs(optimal_partitions - current_partitions) > 4:
            logger.info(f"Repartitioning from {current_partitions} to {optimal_partitions} partitions")
            return spark_df.repartition(optimal_partitions)
    
    return spark_df