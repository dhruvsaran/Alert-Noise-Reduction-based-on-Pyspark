"""
Alert Analysis System - Main Application Entry

This application analyzes security alerts using user behavior profiles
to detect anomalous activity.
"""
# Set Hadoop home directory at the very beginning before any other imports
import os
os.environ["HADOOP_HOME"] = r"C:\hadoop"
os.environ["PATH"] = r"C:\hadoop\bin;" + os.environ["PATH"]

# Create log directory if it doesn't exist
os.makedirs("logs", exist_ok=True)

import json
import logging
import sys
import argparse
import time
from typing import Dict, Any

# Import from modules
from config.logging_config import setup_logging, setup_udf_logger
from core.scoring import compute_alert_anomaly_score
from core.classification import classify_alert, DEFAULT_NORMAL_THRESHOLD, DEFAULT_ANOMALOUS_THRESHOLD
from data.db_connector import read_alerts_from_postgres, read_alerts_from_file, read_profiles_from_postgres
from data.spark_manager import setup_spark, validate_spark_dataframe, add_derived_columns
from data.profile_cache import ProfileCache, load_all_profiles
from utils.helpers import debug_single_alert, get_source_ips_from_alert, monitor_system_resources
from models.alert import Alert
from models.profile import UserProfile, load_profiles_from_json

# Import PySpark
from pyspark.sql import functions as F
from pyspark.sql.types import StructType, StructField, StringType, FloatType

# Set up logging
logger = setup_logging()

def save_results(results_df, export_path, export_format="csv", export_details=False):
    """Save processing results to file with error handling."""
    try:
        logger.info(f"Saving results to {export_path} in {export_format} format")
        
        # For CSV output, ensure we get a single file not a directory
        if export_format.lower() == "csv":
            # Create a temporary directory path
            import os
            import uuid
            import glob
            import shutil
            
            # Create a unique temp directory name
            temp_dir = f"temp_csv_{uuid.uuid4().hex}"
            
            # Write to the temp directory with a single partition
            results_df.coalesce(1).write.mode("overwrite").option("header", "true").csv(temp_dir)
            
            # Find the part file in the temp directory
            part_files = glob.glob(f"{temp_dir}/part-*.csv")
            if not part_files:
                part_files = glob.glob(f"{temp_dir}/part-*")
            
            if part_files:
                # Make sure destination directory exists
                os.makedirs(os.path.dirname(os.path.abspath(export_path)), exist_ok=True)
                
                # Copy the part file to the desired output path
                shutil.copy(part_files[0], export_path)
                
                # Clean up the temp directory
                shutil.rmtree(temp_dir)
                logger.info(f"Successfully saved results to {export_path}")
            else:
                logger.error(f"No output files found in temporary directory")
                
        elif export_format.lower() == "parquet":
            # For Parquet format
            results_df.write.mode("overwrite").parquet(export_path)
            
        elif export_format.lower() == "json":
            # For JSON format - also making this a single file
            results_df.coalesce(1).write.mode("overwrite").json(export_path)
            
        else:
            # Default to CSV if format not recognized
            logger.warning(f"Unrecognized export format {export_format}, defaulting to CSV")
            results_df.coalesce(1).write.mode("overwrite").option("header", "true").csv(export_path)
            
    except Exception as e:
        logger.error(f"Error saving results: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())

def list_log_files():
    """List all log batch files in the system."""
    import glob
    log_files = glob.glob("logs/alert_analysis_detailed_batch_*.log")
    return sorted(log_files)

def combine_log_files(output_file="combined_logs.log"):
    """Combine all batch log files into a single file with proper numerical ordering."""
    import glob
    import shutil
    import re
    
    # Look for batch log files
    log_files = glob.glob("logs/alert_analysis_detailed_batch_*.log")
    
    # Use numerical sorting instead of alphabetical
    def extract_number(filename):
        match = re.search(r'batch_(\d+)', filename)
        if match:
            return int(match.group(1))
        return 0
    
    # Sort numerically by batch number
    log_files.sort(key=extract_number)
    
    print(f"Combining log files into {output_file}...")
    print(f"Found {len(log_files)} log batch files to combine")
    
    if not log_files:
        print("No log batch files to combine")
        return False
    
    # Create output file
    with open(output_file, 'wb') as outfile:
        for log_file in log_files:
            try:
                print(f"Adding {log_file} to combined log...")
                with open(log_file, 'rb') as infile:
                    # Use efficient copy - better than line-by-line reading
                    shutil.copyfileobj(infile, outfile, 1024*1024*10)  # 10MB buffer
                outfile.write(b"\n")  # Add newline between files
            except Exception as e:
                print(f"Error processing {log_file}: {e}")
    
    print(f"Combined {len(log_files)} log files into {output_file}")
    return True

def process_alerts(
    alerts_source,    # Path to file or DataFrame
    personalities_data: Dict[str, Dict], 
    normal_threshold: float = DEFAULT_NORMAL_THRESHOLD,
    anomalous_threshold: float = DEFAULT_ANOMALOUS_THRESHOLD,
    export_path: str = "alerts_scored.csv",
    export_format: str = "csv",
    export_details: bool = False
):
    """
    Process alerts using PySpark with proper logging in UDFs.
    
    Parameters:
    - alerts_source: Path to alerts file or Spark DataFrame
    - personalities_data: Dictionary mapping usernames to their personality profiles
    - normal_threshold: Threshold below which alerts are considered normal
    - anomalous_threshold: Threshold above which alerts are considered anomalous
    - export_path: Path to save the results
    - export_format: Format to save the results (csv, parquet, json)
    - export_details: Whether to include detailed component scores in output
    
    Returns:
    - True if successful, False otherwise
    """
    # Initialize Spark
    if isinstance(alerts_source, str):
        # Path to file provided - initialize Spark & load file
        logger.info(f"Starting alert analysis on file: {alerts_source} using PySpark")
        spark = setup_spark()
        spark_df = read_alerts_from_file(spark, alerts_source)
    else:
        # DataFrame was provided directly
        logger.info("Starting alert analysis on provided Spark DataFrame")
        spark_df = alerts_source
        spark = spark_df.sparkSession

    try:
        # Count before processing
        input_count = spark_df.count()
        logger.info(f"Loaded {input_count} alerts for processing")
 
        # Broadcast the personalities data to all nodes
        personalities_broadcast = spark.sparkContext.broadcast(personalities_data) 
        
        # Add derived columns for analysis
        spark_df = add_derived_columns(spark_df)
        
        # Define UDF with its own logger
        @F.udf(returnType=StringType())
        def calculate_scores(targetusername, timestamp, source_ip, severity, rule_name, 
                           hour_of_day, is_weekend, duration=None, source_ips=None, 
                           occurrence=None, dest_ip=None, alert_type=None, id=None, dest_port=None):
            """UDF to calculate anomaly score with efficient multi-file logging"""
            # Get alert ID for sampling
            alert_id = 0
            try:
                if id is not None:
                    alert_id = int(id)
            except (ValueError, TypeError):
                pass
            
            # Log all alerts in detail for now
            should_log_detail = True
            
            # Get logger with appropriate settings
            udf_logger = setup_udf_logger(minimal=not should_log_detail, max_lines_per_file=1000000)
            
            # Import modules inside UDF for serialization
            import json
            import traceback
            import logging
            from datetime import datetime
            
            # THIS IS THE KEY FIX - Temporarily replace the alert_analysis logger's handlers
            # with the UDF logger's handlers during this UDF execution
            main_logger = logging.getLogger("alert_analysis")
            original_handlers = main_logger.handlers
            original_level = main_logger.level
            
            try:
                # Direct all logging from core modules to our UDF logger
                main_logger.handlers = udf_logger.handlers
                main_logger.setLevel(udf_logger.level)
                
                # Ensure non-None values with proper types
                hour = int(hour_of_day) if hour_of_day is not None else 0
                is_weekend_bool = bool(is_weekend) if is_weekend is not None else False
                occurrence_int = int(occurrence) if occurrence is not None else 0
                dest_port_int = int(dest_port) if dest_port is not None and dest_port != '' else 0
                
                # Recreate alert_row dict
                alert_row = {
                    "targetusername": str(targetusername) if targetusername is not None else "",
                    "timestamp": str(timestamp) if timestamp is not None else "",
                    "hour_of_day": hour,
                    "is_weekend": is_weekend_bool,
                    "source_ip": str(source_ip) if source_ip is not None else "",
                    "severity": str(severity) if severity is not None else "",
                    "duration": str(duration) if duration is not None else "1 min",
                    "source_ips": str(source_ips) if source_ips is not None else "",
                    "occurrence": occurrence_int,
                    "dest_ip": str(dest_ip) if dest_ip is not None else "",
                    "rule_name": str(rule_name) if rule_name is not None else "",
                    "alert_type": str(alert_type) if alert_type is not None else "",
                    "id": str(id) if id is not None else "",
                    "dest_port": dest_port_int
                }
                
                # Get user's personality profile
                personality = personalities_broadcast.value.get(str(targetusername), {})
                
                try:
                    # Create an Alert object for processing
                    alert_obj = Alert.from_dict(alert_row)

                    # Calculate anomaly score - import functions directly in UDF
                    from core.scoring import compute_alert_anomaly_score
                    from core.classification import classify_alert

                    anomaly_score = compute_alert_anomaly_score(alert_row, personality)
                    classification = classify_alert(anomaly_score, normal_threshold, anomalous_threshold, id)
                    
                    # Return as JSON string
                    return json.dumps({
                        "score": float(anomaly_score),
                        "classification": classification
                    })
                except Exception as e:
                    error_msg = f"Error: {str(e)}"
                    stack_trace = traceback.format_exc()
                    udf_logger.error(f"[Alert:{id}] {error_msg}")
                    udf_logger.error(f"[Alert:{id}] {stack_trace}")
                    
                    return json.dumps({
                        "score": 0.0,
                        "classification": "Error",
                        "error": error_msg
                    })
            finally:
                # CRITICAL: Restore the original handlers to avoid affecting other UDFs
                main_logger.handlers = original_handlers
                main_logger.setLevel(original_level)
                
        # Apply UDF to calculate scores
        spark_df = spark_df.withColumn(
            "result_json",
            calculate_scores(
                F.col("targetusername"),
                F.col("timestamp"),
                F.col("source_ip"),
                F.col("severity"),
                F.col("rule_name"),
                F.col("hour_of_day"),
                F.col("is_weekend"),
                F.col("duration"),
                F.col("source_ips"),
                F.col("occurrence"),
                F.col("dest_ip"),
                F.col("alert_type"),
                F.col("id"),
                F.col("dest_port")
            )
        )
        
        # Extract score and classification from JSON
        result_schema = StructType([
            StructField("score", FloatType()),
            StructField("classification", StringType()),
            StructField("error", StringType(), True)
        ])
        
        result_df = spark_df.withColumn(
            "parsed", 
            F.from_json(F.col("result_json"), result_schema)
        ).withColumn(
            "anomaly_score", 
            F.col("parsed.score")
        ).withColumn(
            "classification", 
            F.col("parsed.classification")
        )
        
        # Add error column if details requested
        if export_details:
            result_df = result_df.withColumn("error", F.col("parsed.error"))
            
        # Drop temporary columns
        result_df = result_df.drop("parsed", "result_json")
        
        # Save results with consistent ordering
        save_results(result_df, export_path, export_format, export_details)
        
        # Count results
        result_count = result_df.count()
        logger.info(f"Alert analysis complete - processed {result_count} alerts")
        
        # Stop Spark session when done
        spark.stop()
        
        return True
        
    except Exception as e:
        logger.error(f"Error in PySpark alert processing: {str(e)}")
        if 'spark' in locals():
            spark.stop()
        raise


def get_user_inputs():
    """
    Get inputs from user through interactive prompts.
    
    Returns:
    - Namespace-like object with user input values
    """
    # Import settings at the beginning of the function
    from config.settings import (
        DEFAULT_NORMAL_THRESHOLD, DEFAULT_ANOMALOUS_THRESHOLD,
        DEFAULT_PG_HOST, DEFAULT_PG_PORT, DEFAULT_PG_DBNAME,
        DEFAULT_PG_USER, DEFAULT_PG_PASSWORD, DEFAULT_PG_TABLE,
        DEFAULT_PG_PERSONALITY_TABLE
    )
    
    # Create a simple namespace to simulate args
    class Args:
        pass
    
    args = Args()
    
    # Default values
    args.normal_threshold = DEFAULT_NORMAL_THRESHOLD
    args.anomalous_threshold = DEFAULT_ANOMALOUS_THRESHOLD
    args.save_output = True
    args.output = "scored_alerts.csv"
    args.format = "csv"
    args.details = False
    
    # Ask about thresholds
    try:
        normal_threshold_input = input(f"\nNormal threshold [default: {DEFAULT_NORMAL_THRESHOLD}]: ").strip()
        if normal_threshold_input:
            args.normal_threshold = float(normal_threshold_input)
            
        anomalous_threshold_input = input(f"Anomalous threshold [default: {DEFAULT_ANOMALOUS_THRESHOLD}]: ").strip()
        if anomalous_threshold_input:
            args.anomalous_threshold = float(anomalous_threshold_input)
            
        # Validate thresholds
        if not (0 <= args.normal_threshold <= args.anomalous_threshold <= 1):
            print("Error: Thresholds must be between 0 and 1, with normal_threshold <= anomalous_threshold")
            print("Using default values instead.")
            args.normal_threshold = DEFAULT_NORMAL_THRESHOLD
            args.anomalous_threshold = DEFAULT_ANOMALOUS_THRESHOLD
    except ValueError:
        print("Invalid threshold values. Using defaults.")
        args.normal_threshold = DEFAULT_NORMAL_THRESHOLD
        args.anomalous_threshold = DEFAULT_ANOMALOUS_THRESHOLD
    
    # Ask about data source
    print("\nAlert data source:")
    print("1. PostgreSQL database")
    print("2. CSV file")
    data_source = input("Select data source (1/2) [default: 1]: ").strip() or "1"

    args.use_postgres = (data_source == "1")
    
    if args.use_postgres:
        # PostgreSQL configuration - Use settings.py defaults
        print("\nPostgreSQL connection details:")
        host = input(f"PostgreSQL host [default: {DEFAULT_PG_HOST}]: ").strip() or DEFAULT_PG_HOST
        port = input(f"PostgreSQL port [default: {DEFAULT_PG_PORT}]: ").strip() or DEFAULT_PG_PORT
        dbname = input(f"PostgreSQL database name [default: {DEFAULT_PG_DBNAME}]: ").strip() or DEFAULT_PG_DBNAME
        user = input(f"PostgreSQL username [default: {DEFAULT_PG_USER}]: ").strip() or DEFAULT_PG_USER
        password = input(f"PostgreSQL password [default: {DEFAULT_PG_PASSWORD}]: ").strip() or DEFAULT_PG_PASSWORD 
        table = input(f"PostgreSQL table name [default: {DEFAULT_PG_TABLE}]: ").strip() or DEFAULT_PG_TABLE
        
        args.postgres_config = {
            'host': host,
            'port': port,
            'dbname': dbname,
            'user': user,
            'password': password,
            'table': table
        }
        args.alerts = None
    else:
        # CSV file path
        args.alerts = input("\nPath to alerts CSV file [default: simulated_alerts.csv]: ").strip() or "simulated_alerts.csv"
        args.postgres_config = None
    
    # Ask about personality profiles source
    print("\nPersonality profiles source:")
    print("1. JSON file")
    print("2. PostgreSQL database")
    profile_source = input("Select profile source (1/2) [default: 1]: ").strip() or "1"
    
    if profile_source == "1":
        # JSON file
        args.personalities = input("\nPath to personality profiles JSON [default: personality_profiles.json]: ").strip() or "personality_profiles.json"
        args.profiles_from_postgres = False
    else:
        # PostgreSQL for profiles too
        args.profiles_from_postgres = True
        print("\nUsing the same PostgreSQL connection for profiles")
        args.profiles_table = input(f"PostgreSQL profiles table name [default: {DEFAULT_PG_PERSONALITY_TABLE}]: ").strip() or DEFAULT_PG_PERSONALITY_TABLE
        
        # Copy connection details from alerts if they were set
        if hasattr(args, 'postgres_config'):
            args.host = args.postgres_config['host']
            args.port = args.postgres_config['port']
            args.dbname = args.postgres_config['dbname']
            args.user = args.postgres_config['user']
            args.password = args.postgres_config['password']
        else:
            # Set connection details directly
            args.host = DEFAULT_PG_HOST
            args.port = DEFAULT_PG_PORT
            args.dbname = DEFAULT_PG_DBNAME
            args.user = DEFAULT_PG_USER
            args.password = DEFAULT_PG_PASSWORD
    
    # Ask about saving results
    save = input("\nSave scored results? (y/n) [default: y]: ").lower().strip() or "y"
    args.save_output = (save == "y")
    
    if args.save_output:
        args.output = input("Output file path [default: scored_alerts.csv]: ").strip() or "scored_alerts.csv"
        args.format = input("Output format (csv/parquet/json) [default: csv]: ").lower().strip() or "csv"
        
        # Ask about including detailed scores
        details = input("Include detailed component scores? (y/n) [default: n]: ").lower().strip() or "n"
        args.details = (details == "y")
    
    return args


def parse_args():
    """
    Parse command line arguments.
    
    Returns:
    - Parsed command line arguments
    """
    parser = argparse.ArgumentParser(description="Analyze security alerts based on user behavior profiles")
    
    parser.add_argument("-a", "--alerts", default="simulated_alerts.csv", help="Path to alerts CSV file")
    parser.add_argument("-p", "--personalities", default="personality_profiles.json", help="Path to personalities JSON file")
    parser.add_argument("-o", "--output", default="alerts_scored.csv", help="Output file path")
    parser.add_argument("-f", "--format", choices=["csv", "json", "parquet"], default="csv", help="Output format")
    parser.add_argument("--normal-threshold", type=float, default=DEFAULT_NORMAL_THRESHOLD, 
                        help=f"Threshold for normal classification (default: {DEFAULT_NORMAL_THRESHOLD})")
    parser.add_argument("--anomalous-threshold", type=float, default=DEFAULT_ANOMALOUS_THRESHOLD, 
                        help=f"Threshold for anomalous classification (default: {DEFAULT_ANOMALOUS_THRESHOLD})")
    parser.add_argument("-d", "--details", action="store_true", help="Include detailed component scores in output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    
    # PostgreSQL options
    parser.add_argument("--use-postgres", action="store_true", help="Use PostgreSQL as data source")
    parser.add_argument("--host", default="localhost", help="PostgreSQL host")
    parser.add_argument("--port", default="5432", help="PostgreSQL port")
    parser.add_argument("--dbname", default="postgres", help="PostgreSQL database name")
    parser.add_argument("--user", default="postgres", help="PostgreSQL username")
    parser.add_argument("--password", default="casey2003", help="PostgreSQL password")
    parser.add_argument("--table", default="alerts", help="PostgreSQL table name")
    parser.add_argument("--profiles-from-postgres", action="store_true", help="Read profiles from PostgreSQL")
    parser.add_argument("--profiles-table", default="profiles", help="PostgreSQL profiles table name")
    
    return parser.parse_args()


def main():
    """
    Main execution function with added resource monitoring.
    """
    # Try to get interactive inputs first
    if sys.stdin.isatty():  # Check if running in interactive mode
        args = get_user_inputs()
    else:
        # Fall back to command line arguments
        args = parse_args()
    
    # Configure logging
    if getattr(args, 'verbose', False):
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    logger.info("Starting alert analysis tool with PySpark")
    monitor_system_resources()  # Log initial resource state
    
    try:
        # Load personalities data
        if getattr(args, 'profiles_from_postgres', False):
            # Initialize Spark FIRST - before any data access
            spark = setup_spark()
            
            # Import the newly added function
            from data.db_connector import read_personality_profiles_from_postgres
            from config.settings import DEFAULT_PG_HOST, DEFAULT_PG_PORT, DEFAULT_PG_DBNAME, DEFAULT_PG_USER, DEFAULT_PG_PASSWORD, DEFAULT_PG_PERSONALITY_TABLE
            
            # Read profiles from PostgreSQL using settings from settings.py
            logger.info("Loading personality profiles from PostgreSQL")
            profiles_data = read_personality_profiles_from_postgres(
                spark, 
                getattr(args, 'host', DEFAULT_PG_HOST),
                getattr(args, 'port', DEFAULT_PG_PORT),
                getattr(args, 'dbname', DEFAULT_PG_DBNAME),
                getattr(args, 'user', DEFAULT_PG_USER), 
                getattr(args, 'password', DEFAULT_PG_PASSWORD),
                getattr(args, 'profiles_table', DEFAULT_PG_PERSONALITY_TABLE)
            )
            
            # Convert raw profile data to UserProfile objects
            personalities_data_objects = {}
            for username, profile_data in profiles_data.items():
                try:
                    # Create UserProfile instance from raw data
                    profile = UserProfile.from_dict(profile_data)
                    personalities_data_objects[username] = profile
                except Exception as e:
                    logger.warning(f"Error creating profile object for user {username}: {str(e)}")
                    # Use raw data as fallback
                    personalities_data_objects[username] = profile_data
            
            # Replace the profiles_data with objects
            personalities_data = personalities_data_objects
        else:
            # Load from JSON file
            logger.info(f"Loading personality profiles from {args.personalities}")
            # Use our profile loader
            personalities_data = load_profiles_from_json(args.personalities)
            
        logger.info(f"Loaded {len(personalities_data)} personality profiles")
        
        # Initialize Profile Cache
        profile_cache = ProfileCache()
        for username, profile_data in personalities_data.items():
            profile_cache.update_profile(username, profile_data)
        
        # Convert UserProfile objects to dictionaries for compatibility
        personalities_data_dict = {}
        for username, profile in personalities_data.items():
            if hasattr(profile, 'to_dict'):
                # If it's a UserProfile object, convert to dict
                personalities_data_dict[username] = profile.to_dict()
            else:
                # If it's already a dict, use as is
                personalities_data_dict[username] = profile

        # Initialize Spark if not already done
        if 'spark' not in locals():
            spark = setup_spark()
        
        # Choose data source based on user selection
        if getattr(args, 'use_postgres', False):
            # Read from PostgreSQL
            pg_config = getattr(args, 'postgres_config', {})
            if not pg_config:
                # If not set in interactive mode, use command line args
                pg_config = {
                    'host': getattr(args, 'host', 'localhost'),
                    'port': getattr(args, 'port', '5432'),
                    'dbname': getattr(args, 'dbname', 'postgres'),
                    'user': getattr(args, 'user', 'postgres'),
                    'password': getattr(args, 'password', 'casey2003'),
                    'table': getattr(args, 'table', 'alerts')
                }
                
            spark_df = read_alerts_from_postgres(
                spark, 
                pg_config['host'],
                pg_config['port'],
                pg_config['dbname'],
                pg_config['user'], 
                pg_config['password'],
                pg_config['table']
            )
            
            # Process the DataFrame directly
            process_alerts(
                spark_df,  # Pass DataFrame directly
                personalities_data_dict,  # Use dictionaries instead of UserProfile objects
                normal_threshold=args.normal_threshold,
                anomalous_threshold=args.anomalous_threshold,
                export_path=args.output,
                export_format=args.format,
                export_details=getattr(args, 'details', False)
            )

        else:
            # Process from file path
            process_alerts(
                args.alerts,  # Pass path string
                personalities_data_dict,  # Use dictionaries instead of UserProfile objects
                normal_threshold=args.normal_threshold,
                anomalous_threshold=args.anomalous_threshold,
                export_path=args.output,
                export_format=args.format,
                export_details=getattr(args, 'details', False)
            )
        logger.info(f"Analysis complete. Results saved to {args.output}")
        logger.info("Monitoring system resources after processing")
        monitor_system_resources()
        
        # After processing completes, before combining logs:
        from config.logging_config import check_log_files
        print("Checking log files before combining...")
        check_log_files()
        
        # Combine logs after processing completes
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        combined_file = f"combined_logs_{timestamp}.log"
        logger.info(f"Combining log files into {combined_file}")
        print(f"Combining log files into {combined_file}...")
        combine_log_files(combined_file)
        logger.info(f"Log files combined successfully")
        
    except Exception as e:
        logger.error(f"Error in alert analysis: {str(e)}")
        logger.exception("Stack trace:")
        sys.exit(1)  
    sys.exit(0)


if __name__ == "__main__":
    main()