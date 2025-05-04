# Alert Analysis System with PySpark

**Python 3.11 | PySpark 3.5.1 | PostgreSQL 15.x**

## Table of Contents
- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Project Workflow](#project-workflow)
- [System Architecture](#system-architecture)
- [Application Components](#application-components)
- [Setup Instructions](#setup-instructions)
- [Configuration](#configuration)
- [Optimizations](#optimizations)
- [Troubleshooting](#troubleshooting)

## Project Overview

This project provides a comprehensive solution for analyzing security alerts using user behavior profiles to detect anomalous activity. It leverages Apache Spark's distributed computing capabilities to efficiently process large volumes of security alerts and identify potential threats based on sophisticated scoring algorithms.

## Key Features

- **High-Performance Log Processing**: Custom rotating file handler optimized for Spark UDFs
- **User Behavior Profiling**: Compares alerts against known user behavior patterns
- **Anomaly Scoring**: Multi-component analysis for nuanced anomaly detection
- **PostgreSQL Integration**: Direct connection to security alert databases
- **Configurable Thresholds**: Customizable sensitivity for normal/anomalous classifications
- **Distributed Processing**: PySpark implementation for handling large alert volumes

### Techniques Used

- **UDF (User-Defined Functions)**: For distributed anomaly score calculation
- **Multi-Stage Scoring**: Combined time, location, severity, and behavior pattern analysis
- **Performance Buffering**: Memory-efficient logging with background flushing
- **Context-Aware Processing**: User profile consideration in anomaly detection
- **Resource Optimization**: Memory and thread management for Spark environments

## Project Workflow

1. **Data Collection**: Retrieve security alerts from PostgreSQL database or CSV files
2. **User Profile Loading**: Load personality profiles for behavioral baselining
3. **Alert Processing**: Distribute alerts across Spark executors with derived features
4. **Anomaly Score Calculation**: Apply multi-component analysis for comprehensive scoring
5. **Alert Classification**: Categorize as Normal, Suspicious, or Anomalous based on thresholds
6. **Results Export**: Save processed results with optional detailed component scores

## System Architecture

### Config Module

#### Settings (`settings.py`)
- **Threshold Settings**: `DEFAULT_NORMAL_THRESHOLD`, `DEFAULT_ANOMALOUS_THRESHOLD`
- **PostgreSQL Connection Parameters**: Host, port, credentials, table names
- **System Paths**: Hadoop home directory for HDFS compatibility

#### Logging Infrastructure (`logging_config.py`)
- **`HighPerformanceFileHandler`**: Custom handler with buffered writing and rotation
- **Logger Setup Functions**: `setup_udf_logger()`, `setup_logging()`
- **Log Management**: `check_log_files()`, `clean_old_log_files()`, `combine_log_files()`

### Core Module

#### Scoring Engine (`scoring.py`)
- **`compute_alert_anomaly_score(alert_row, personality)`**: Master function orchestrating the entire scoring process
- **`analyze_timestamp(alert_row, personality, context)`**: Evaluates unusual timing patterns based on user's historical behavior
- **`analyze_location(alert_row, personality, context)`**: Checks source IPs against known locations 
- **`check_ip_anomalies(source_ips, personality, context)`**: Advanced analysis for scenarios with mixed known/unknown IPs
- **`analyze_severity(alert_row, personality, context)`**: Weights alerts based on reported severity levels
- **`analyze_resource_access(alert_row, personality, context)`**: Detects access to unusual resources
- **`analyze_frequency(alert_row, personality, context)`**: Identifies abnormally high activity rates
- **`check_admin_action(alert_row, personality, context)`**: Special handling for privileged operations
- **`check_brute_force(alert_row, personality, context)`**: Detects potential brute force attack patterns
- **`get_dynamic_weights(rule_name, has_unknown_ips)`**: Intelligent weighting system that adapts based on alert context
- **`parse_duration(duration_str)`**: Standardizes duration strings into minutes for consistent processing

#### Classification (`classification.py`)
- **`classify_alert(score, threshold_normal, threshold_anomalous, alert_id)`**: Assigns severity labels:
  - **Normal**: Score below configurable threshold (default: 0.35)
  - **Suspicious**: Score between thresholds
  - **Anomalous**: Score above configurable threshold (default: 0.7)
- Includes detailed logging of classification decisions with alert context
- Supports customizable thresholds for environment-specific tuning

### Data Module

#### Database Connector (`db_connector.py`)

Provides optimized database access with smart partitioning:

- **`read_alerts_from_postgres(spark, host, port, dbname, user, password, table)`**:
  - Reads security alerts from PostgreSQL with adaptive partitioning
  - Dynamically selects partition columns (id or timestamp)
  - Calculates optimal partition count based on table size (1 per ~100k rows)
  - Implements bounds-based partitioning for large datasets (>100k rows)

- **`read_alerts_from_file(spark, file_path)`**:
  - Handles multiple file formats (CSV, Parquet, JSON)
  - Auto-detects file type from extension
  - Implements optimized partitioning for large files
  - Provides format-specific optimizations

- **`read_profiles_from_postgres(spark, host, port, dbname, user, password, table)`**:
  - Loads generic user profiles from PostgreSQL
  - Parses JSON profile data from database

- **`read_personality_profiles_from_postgres(spark, host, port, dbname, user, password, table)`**:
  - Specialized function for personality profile loading
  - Sophisticated type handling for complex fields:
    - Parses JSON fields (hourly_activity_distribution, source_ip_logon_fail_rate)
    - Handles array fields (known_source_ip_set, common_dest_ports)
    - Processes nested profile data

#### Spark Manager (`spark_manager.py`)

Manages Spark session lifecycle and DataFrame operations:

- **`get_spark_session(memory="16g", use_existing=True)`**:
  - Creates optimized Spark sessions with memory-aware configuration
  - Reuses existing sessions when available
  - Configures memory based on system capabilities (up to 75% of available RAM)

- **`setup_spark(memory="16g")`**:
  - Detailed Spark configuration with optimizations for:
    - Memory management (driver, executor, off-heap)
    - GC tuning with G1 garbage collector
    - Network timeouts to prevent disconnections
    - Kryo serialization for improved performance
    - Arrow integration for Python/JVM data transfer efficiency

- **`add_derived_columns(spark_df)`**:
  - Enhances DataFrame with time-based features
  - Adds hour_of_day from timestamp
  - Calculates is_weekend flag
  - Ensures proper data types for numeric fields

- **`save_results(spark, df, output_path, format_type, logger)`**:
  - Handles consistent column ordering with scores at the end
  - Implements format-specific optimizations (CSV, Parquet, JSON)
  - Smart partitioning based on row count
  - Single-file output for smaller datasets
  - Handles file naming and paths intelligently

- **`optimize_partitioning(spark_df, input_count)`**:
  - Automatically calculates optimal partition count (1 per ~50k records)
  - Prevents unnecessary repartitioning with threshold checks

#### Profile Cache (`profile_cache.py`)

Provides efficient user profile management with multi-level caching:

- **`ProfileCache` Class**:
  - In-memory caching with configurable TTL (time-to-live)
  - Disk-based persistence for resilience
  - Thread-safe profile updates
  - Automatic cache expiration and refresh
  - JSON serialization of profile objects

- **`get_personality_profile(username)`**:
  - Convenience function for profile lookups
  - Returns cached profile or empty dict if not found

- **`load_all_profiles(file_path)`**:
  - Batch loading of profiles from JSON file
  - Updates cache with new profiles
  - Handles serialization errors with graceful fallbacks

The data module implements several key optimizations:

1. **Smart Partitioning**: Dynamically adjusts partitioning based on data size
2. **Memory Management**: Configures Spark based on available system resources
3. **Multi-level Caching**: Combines in-memory and disk caching for profiles
4. **Type Handling**: Sophisticated handling of complex field types
5. **Format Detection**: Automatically detects and handles various file formats

### Models Module

#### Alert Model (`alert.py`)

A comprehensive object-oriented representation of security alerts:

- **`Alert` Class**:
  - Full representation of security alert attributes
  - Automatic timestamp parsing for derived time features:
    - `_extract_hour_from_timestamp()`: Extracts hour (0-23) from alert time
    - `_is_weekend_from_timestamp()`: Determines if the alert occurred on a weekend
  - Conversion methods between objects and dictionaries:
    - `to_dict()`: Serializes alert object to dictionary
    - `from_dict()`: Creates alert object from dictionary
  - Helper methods for analyzing alert data:
    - `get_source_ips()`: Intelligently parses source IPs from different alert types
  - Support for additional fields via flexible constructor
  - Storage of analysis results:
    - `anomaly_score`: Calculated anomaly score
    - `classification`: Final alert classification
    - `component_scores`: Individual component analysis results

#### Profile Model (`profile.py`)

A rich data model representing user behavior patterns:

- **`UserProfile` Class**:
  - Comprehensive representation of user behavior patterns:
    - **Time-based patterns**: Hourly activity distribution, office hour ratios
    - **Location patterns**: Known IP addresses and their failure rates
    - **Authentication patterns**: Logon failure statistics
    - **Network patterns**: Commonly accessed ports
    - **Administrative patterns**: Account and group modification statistics
  - Helper methods for profile management:
    - `add_known_ip()`: Safely adds new trusted IP addresses
    - `update_hourly_activity()`: Updates activity levels for specific hours
    - `is_ip_known()`: Quick verification of IP trustworthiness
    - `get_ip_failure_rate()`: Retrieves historical failure rate for an IP
    - `is_port_common()`: Checks if a port is commonly accessed by the user
  - Serialization support:
    - `to_dict()`: Converts profile to dictionary for storage/transmission
    - `from_dict()`: Creates profile object from dictionary data
  - Role-based profile differentiation
  - Extension support via additional fields

- **Profile Loading Functions**:
  - `load_profiles_from_json()`: Loads and validates multiple profiles from JSON files
  - Error handling with detailed logging for profile loading issues
  - Automatic username assignment for consistent identification

The models module provides structured, object-oriented representations of key data entities:

1. **Type Safety**: Proper type hints and validation throughout
2. **Encapsulation**: Business logic tied directly to relevant data
3. **Serialization**: Easy conversion between objects and storage formats
4. **Derived Attributes**: Automatic calculation of time-based features
5. **Flexible Extension**: Support for additional fields beyond core schema

These models ensure consistent handling of alert and user profile data throughout the application, providing a stable foundation for the anomaly detection logic.

### Utils Module

#### Helper Functions (`helpers.py`)
- IP extraction, time formatting, and resource monitoring

## Application Components

### Main Application (`main.py`)

The central controller coordinating all system components:

- **Command-Line Interface**:
  - Dual interface supporting both interactive prompts and CLI arguments
  - Comprehensive argument parsing with sensible defaults
  - Interactive wizard for ease of use in exploration scenarios

- **Data Pipeline Management**:
  - Flexible data source selection (PostgreSQL or file-based)
  - User profile loading from multiple sources
  - Distributed processing coordination

- **UDF Implementation**:
  - **`calculate_scores(targetusername, timestamp, ...)`**: Core UDF for distributed processing that:
    - Handles logger swapping for proper distributed logging
    - Maintains context across distributed execution
    - Implements error recovery with detailed tracking
    - Returns structured results as JSON for downstream processing
    - Ensures proper cleanup of resources

- **Processing Flow**:
  - Initializes the environment and logging infrastructure
  - Loads and broadcasts user personality profiles
  - Sets up Spark session with optimized configuration
  - Adds derived columns for enhanced analysis
  - Applies UDF for distributed score calculation
  - Extracts and formats results from JSON strings
  - Saves processed results in requested format

- **Resource Management**:
  - System resource monitoring (CPU, memory, disk)
  - Log file cleanup and combination
  - Proper error handling with detailed logging

### Utility Functions (`utils/helpers.py`)

Collection of helper functions that support the core processing:

- **`get_source_ips_from_alert(alert_row)`**:
  - Intelligently extracts source IPs from different alert types
  - Rule-specific handling for various IP formats
  - Handles multiple IPs in comma-separated fields
  - Returns normalized list of clean IP strings

- **`format_time_window(start_time, end_time)`**:
  - Creates human-readable time ranges
  - Smart formatting based on same/different days
  - Error handling for invalid timestamp formats
  - Used in logging and user-facing outputs

- **`monitor_system_resources()`**:
  - Tracks CPU utilization percentages
  - Monitors memory usage in GB and percentage
  - Analyzes disk space availability
  - Provides warnings for resource constraints
  - Helps diagnose performance bottlenecks during processing

These modules work together to orchestrate the entire alert processing pipeline, ensuring efficient handling of large alert volumes while maintaining detailed logging and error handling.

## System Workflow

1. **Startup and Configuration**:
   - Parse command-line arguments or collect interactive inputs
   - Set up logging infrastructure with appropriate levels
   - Clean up old log files for a fresh processing run

2. **Profile Loading**:
   - Load user personality profiles from PostgreSQL or JSON
   - Convert raw data into structured UserProfile objects
   - Initialize profile cache for efficient lookups

3. **Alert Processing Initialization**:
   - Configure and start Spark session
   - Load alerts from database or file source
   - Add derived time-based columns

4. **Distributed Score Calculation**:
   - Broadcast personality profiles to all executors
   - Apply UDF to calculate anomaly scores across the cluster
   - Handle errors within each executor with proper logging

5. **Result Aggregation**:
   - Extract scores and classifications from JSON results
   - Add detailed component scores if requested
   - Sort columns in a consistent order

6. **Output Generation**:
   - Save results in specified format
   - Optimize output based on result size
   - Monitor system resources after processing

7. **Log Management**:
   - Combine batch log files into a single comprehensive log
   - Archive or clean up temporary log files
   - Generate processing statistics and summaries

## Setup Instructions

### Requirements
- Python 3.11+
- PySpark 3.5.1+
- PostgreSQL 15.x (optional)
- Java 11+ (for Spark)

### Installation

```bash
git clone <repository-url>
cd alert-analysis-system
pip install -r requirements.txt
```
