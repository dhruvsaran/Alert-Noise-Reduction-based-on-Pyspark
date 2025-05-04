"""
This module handles database connections and data retrieval for the alert analysis system.
"""
import logging
import urllib.parse
from typing import Dict, Any, Optional
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F

# Get the logger
logger = logging.getLogger("alert_analysis")

def read_alerts_from_postgres(
    spark: SparkSession,
    host: str = "localhost", 
    port: str = "5432", 
    dbname: str = "postgres", 
    user: str = "postgres", 
    password: str = "casey2003", 
    table: str = "alerts"
) -> DataFrame:
    """
    Read alerts from PostgreSQL with optimized partitioning for large datasets.
    
    Parameters:
    - spark: SparkSession instance
    - host: PostgreSQL host
    - port: PostgreSQL port
    - dbname: Database name
    - user: Database username
    - password: Database password
    - table: Table name containing alerts
    
    Returns:
    - DataFrame with alerts
    """
    logger.info(f"Reading alerts from PostgreSQL table: {table}")
    
    try:
        # URL encode the password for JDBC connection string
        encoded_password = urllib.parse.quote_plus(password)
        
        # Build JDBC URL
        jdbc_url = f"jdbc:postgresql://{host}:{port}/{dbname}"
        
        # Get table size to determine partitioning
        conn = spark.read.format("jdbc") \
            .option("url", jdbc_url) \
            .option("user", user) \
            .option("password", password) \
            .option("driver", "org.postgresql.Driver") \
            .option("query", f"SELECT COUNT(*) as count FROM {table}") \
            .load()
        
        count = conn.collect()[0]['count']
        
        # Calculate optimal number of partitions (1 partition per ~100k rows, min 4, max 100)
        num_partitions = min(max(4, count // 100000), 100)
        
        logger.info(f"Using {num_partitions} partitions for {count} rows")
        
        # For large datasets, use partitioning with ID column
        if count > 100000:
            # Check if 'id' column exists
            columns_df = spark.read.format("jdbc") \
                .option("url", jdbc_url) \
                .option("user", user) \
                .option("password", password) \
                .option("driver", "org.postgresql.Driver") \
                .option("query", "SELECT column_name FROM information_schema.columns WHERE table_name = '" + table.split('.')[-1] + "'") \
                .load()
            
            columns = [row['column_name'] for row in columns_df.collect()]
            
            if 'id' in columns:
                partition_column = 'id'
                bounds_query = f"SELECT MIN(id) as lbound, MAX(id) as ubound FROM {table}"
            elif 'timestamp' in columns:
                partition_column = 'timestamp'
                bounds_query = f"SELECT MIN(timestamp) as lbound, MAX(timestamp) as ubound FROM {table}"
            else:
                logger.warning(f"No suitable partition column found for {table}. Using non-partitioned read.")
                partition_column = None
            
            if partition_column:
                bounds_df = spark.read.format("jdbc") \
                    .option("url", jdbc_url) \
                    .option("user", user) \
                    .option("password", password) \
                    .option("driver", "org.postgresql.Driver") \
                    .option("query", bounds_query) \
                    .load()
                
                bounds = bounds_df.collect()[0]
                lbound = bounds['lbound']
                ubound = bounds['ubound']
                
                # Read with partitioning
                df = spark.read \
                    .format("jdbc") \
                    .option("url", jdbc_url) \
                    .option("dbtable", table) \
                    .option("user", user) \
                    .option("password", password) \
                    .option("driver", "org.postgresql.Driver") \
                    .option("partitionColumn", partition_column) \
                    .option("lowerBound", lbound) \
                    .option("upperBound", ubound + 1) \
                    .option("numPartitions", num_partitions) \
                    .load()
            else:
                # Fallback to simple read
                df = spark.read \
                    .format("jdbc") \
                    .option("url", jdbc_url) \
                    .option("dbtable", table) \
                    .option("user", user) \
                    .option("password", password) \
                    .option("driver", "org.postgresql.Driver") \
                    .load()
        else:
            # For smaller tables, don't use partitioning
            df = spark.read \
                .format("jdbc") \
                .option("url", jdbc_url) \
                .option("dbtable", table) \
                .option("user", user) \
                .option("password", password) \
                .option("driver", "org.postgresql.Driver") \
                .load()
        
        logger.info(f"Successfully read {df.count()} alerts from PostgreSQL")
        return df
    except Exception as e:
        logger.error(f"Error reading from PostgreSQL: {str(e)}")
        raise

def read_alerts_from_file(spark: SparkSession, file_path: str) -> DataFrame:
    """
    Read alerts from file with optimized partitioning for large datasets.
    
    Parameters:
    - spark: SparkSession
    - file_path: Path to the alerts file (CSV, JSON, Parquet)
    
    Returns:
    - DataFrame with alerts
    """
    logger.info(f"Reading alerts from file: {file_path}")
    
    try:
        # Load file based on extension
        if file_path.lower().endswith('.csv'):
            # Add repartitioning for large files
            df = spark.read.option("header", "true").option("inferSchema", "true").csv(file_path)
            count = df.count()
            # Repartition based on data size
            if count > 100000:
                # Calculate optimal partitions: ~100k rows per partition, min 16, max 1000
                num_partitions = min(max(16, count // 100000), 1000)
                logger.info(f"Repartitioning large dataset ({count} rows) to {num_partitions} partitions")
                df = df.repartition(num_partitions)
                
        elif file_path.lower().endswith('.parquet'):
            df = spark.read.parquet(file_path)
            # Check partitioning on parquet as well
            count = df.count()
            if count > 100000:
                num_partitions = min(max(16, count // 100000), 1000)
                logger.info(f"Repartitioning parquet dataset ({count} rows) to {num_partitions} partitions")
                df = df.repartition(num_partitions)
                
        elif file_path.lower().endswith('.json'):
            df = spark.read.json(file_path)
            # Same for JSON
            count = df.count()
            if count > 100000:
                num_partitions = min(max(16, count // 100000), 1000)
                logger.info(f"Repartitioning JSON dataset ({count} rows) to {num_partitions} partitions")
                df = df.repartition(num_partitions)
                
        else:
            logger.warning(f"Unknown file type for {file_path}, attempting to read as CSV")
            df = spark.read.option("header", "true").option("inferSchema", "true").csv(file_path)
        
        logger.info(f"Successfully read {df.count()} alerts from file")
        return df
        
    except Exception as e:
        logger.error(f"Error reading alerts from file: {str(e)}")
        raise

def read_profiles_from_postgres(
    spark: SparkSession,
    host: str = "localhost", 
    port: str = "5432", 
    dbname: str = "postgres", 
    user: str = "postgres", 
    password: str = "casey2003", 
    table: str = "profiles"
) -> Dict[str, Dict[str, Any]]:
    """
    Read user behavior profiles from PostgreSQL database.
    
    Parameters:
    - spark: Active SparkSession
    - host: PostgreSQL host
    - port: PostgreSQL port
    - dbname: Database name
    - user: Database username
    - password: Database password
    - table: Table name containing profiles
    
    Returns:
    - Dictionary mapping usernames to their behavior profiles
    """
    logger.info(f"Reading user profiles from PostgreSQL table: {table}")
    
    try:
        # Build JDBC URL
        jdbc_url = f"jdbc:postgresql://{host}:{port}/{dbname}"
        
        # Read profiles table
        profiles_df = spark.read \
            .format("jdbc") \
            .option("url", jdbc_url) \
            .option("dbtable", table) \
            .option("user", user) \
            .option("password", password) \
            .option("driver", "org.postgresql.Driver") \
            .load()
        
        # Convert to dictionary mapping username -> profile
        profiles_dict = {}
        
        for row in profiles_df.collect():
            username = row.get("username", None)
            if not username:
                continue
                
            # Assume profile data is stored in a column called 'profile_json'
            # which contains a JSON string representation of the profile
            profile_json = row.get("profile_json", None)
            if profile_json:
                import json
                try:
                    profile_data = json.loads(profile_json)
                    profiles_dict[username] = profile_data
                except Exception as e:
                    logger.warning(f"Error parsing profile JSON for user {username}: {str(e)}")
        
        logger.info(f"Successfully loaded {len(profiles_dict)} user profiles")
        return profiles_dict
        
    except Exception as e:
        logger.error(f"Error reading profiles from PostgreSQL: {str(e)}")
        raise

def read_personality_profiles_from_postgres(
    spark: SparkSession,
    host: str = "172.16.23.111", 
    port: str = "5432", 
    dbname: str = "postgres", 
    user: str = "postgres", 
    password: str = "tspasswordsocleus", 
    table: str = "public.personality_windows"
) -> Dict[str, Dict[str, Any]]:
    """
    Read user personality profiles directly from the personality_windows PostgreSQL table.
    
    Parameters:
    - spark: Active SparkSession
    - host: PostgreSQL host
    - port: PostgreSQL port
    - dbname: Database name
    - user: Database username
    - password: Database password
    - table: Table name containing personality profiles
    
    Returns:
    - Dictionary mapping usernames to their personality profiles
    """
    logger.info(f"Reading personality profiles from PostgreSQL table: {table}")
    
    try:
        # Build JDBC URL
        jdbc_url = f"jdbc:postgresql://{host}:{port}/{dbname}"
        
        # Read profiles table
        profiles_df = spark.read \
            .format("jdbc") \
            .option("url", jdbc_url) \
            .option("dbtable", table) \
            .option("user", user) \
            .option("password", password) \
            .option("driver", "org.postgresql.Driver") \
            .load()
        
        # Convert to dictionary mapping username -> profile
        profiles_dict = {}
        
        # Get column names for later use
        column_names = profiles_df.columns
        
        for row in profiles_df.collect():
            row_dict = row.asDict()  # Convert Row to dictionary
            
            # Extract username - required field
            username = row_dict.get("username")
            if not username:
                logger.warning(f"Skipping row without username")
                continue

            # Create profile dictionary from row
            profile = {}
            
            # Handle different field types appropriately
            for field in column_names:
                if field != "username":  # Skip username as it's the key
                    value = row_dict.get(field)
                    
                    # Handle JSON fields stored as strings
                    if field in ["hourly_activity_distribution", "source_ip_logon_fail_rate", 
                                "eventid_distribution", "unique_failed_ip_count", "protocol_usage", 
                                "direction_ratio"]:
                        if value and isinstance(value, str):
                            try:
                                import json
                                profile[field] = json.loads(value)
                            except:
                                profile[field] = value
                        else:
                            profile[field] = value
                    
                    # Handle array fields
                    elif field in ["known_source_ip_set", "common_dest_ports", "common_source_ips", 
                                  "most_used_applications"]:
                        if value and isinstance(value, str):
                            if value.startswith('[') and value.endswith(']'):
                                try:
                                    import json
                                    profile[field] = json.loads(value)
                                except:
                                    # Fall back to string parsing if JSON fails
                                    profile[field] = [item.strip(' "\'') for item in value.strip('[]').split(',')]
                            else:
                                profile[field] = [item.strip(' "\'') for item in value.split(',')]
                        else:
                            profile[field] = value
                            
                    # For the profile_data field which contains the full JSON
                    elif field == "profile_data" and value:
                        try:
                            import json
                            if isinstance(value, str):
                                profile_data = json.loads(value)
                                # Add all fields from profile_data if not already present
                                for k, v in profile_data.items():
                                    if k not in profile:
                                        profile[k] = v
                        except Exception as e:
                            logger.warning(f"Error parsing profile_data for {username}: {str(e)}")
                            
                    # All other fields go as-is
                    else:
                        profile[field] = value
            
            # Ensure we have the username in the profile
            profile["username"] = username
            
            # Add to the dictionary
            profiles_dict[username] = profile
            
        logger.info(f"Successfully loaded {len(profiles_dict)} personality profiles from PostgreSQL")
        return profiles_dict
        
    except Exception as e:
        logger.error(f"Error reading personality profiles from PostgreSQL: {str(e)}")
        logger.exception("Stack trace:")
        raise