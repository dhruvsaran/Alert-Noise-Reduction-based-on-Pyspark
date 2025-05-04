"""
This module provides utility functions for the alert analysis system.
"""
import logging
from typing import Dict, Any, List

# Get the logger
logger = logging.getLogger("alert_analysis")

def get_source_ips_from_alert(alert_row: Dict[str, Any]) -> List[str]:
    """
    Extract source IPs from an alert row depending on rule name.
    Different rules store IPs in different fields or formats.
    
    Parameters:
    - alert_row: Dictionary containing alert data
    
    Returns:
    - List of source IP addresses
    """
    alert_id = alert_row.get('id', 'unknown')
    context = f"[Alert:{alert_id}]"
    rule_name = alert_row.get("rule_name", "")
    
    if rule_name == "Login Attempts with Same Account from Different Source IPs":
        # For this rule, we look at the source_ips column containing comma-separated IPs
        source_ips_str = alert_row.get("source_ips", "")
        if source_ips_str is None or source_ips_str.strip() == "":
            logger.debug(f"{context} No source IPs found in source_ips field")
            return []
        ips = [ip.strip() for ip in source_ips_str.split(",")]
        logger.debug(f"{context} Extracted {len(ips)} source IPs: {ips}")
        return ips
    else:
        # For other rules, use the standard source_ip column
        source_ip = alert_row.get("source_ip", "")
        if source_ip is None or source_ip.strip() == "":
            logger.debug(f"{context} No source IP found in source_ip field")
            return []
        logger.debug(f"{context} Using single source IP: {source_ip}")
        return [source_ip.strip()]

def debug_single_alert(
    test_alert: Dict[str, Any], 
    personality_profiles: Dict[str, Dict],
    normal_threshold: float = 0.35,
    anomalous_threshold: float = 0.7
) -> Dict[str, Any]:
    """
    Debug a single alert calculation outside the UDF context.
    
    Parameters:
    - test_alert: Alert data dictionary to test
    - personality_profiles: Dictionary of user personality profiles
    - normal_threshold: Threshold for "normal" classification
    - anomalous_threshold: Threshold for "anomalous" classification
    
    Returns:
    - Dictionary containing score, classification and component scores
    """
    # Import scoring functions as needed
    from core.scoring import compute_alert_anomaly_score
    from core.classification import classify_alert
    
    username = test_alert.get("targetusername", "unknown")
    alert_id = test_alert.get("id", "debug")
    
    # Get user's personality profile
    personality = personality_profiles.get(username, {})
    if not personality:
        logger.warning(f"No personality profile found for {username}, using empty profile")
    
    # Try to calculate score directly
    try:
        logger.info(f"Testing score calculation for alert {alert_id} (user: {username})")
        anomaly_score = compute_alert_anomaly_score(test_alert, personality)
        classification = classify_alert(
            anomaly_score, 
            normal_threshold, 
            anomalous_threshold, 
            alert_id
        )
        
        result = {
            "score": anomaly_score,
            "classification": classification,
            "alert_id": alert_id,
            "username": username
        }
        
        logger.info(f"Score calculation successful - {classification} ({anomaly_score:.2f})")
        return result
    except Exception as e:
        logger.error(f"Error in debug calculation: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "error": str(e),
            "alert_id": alert_id,
            "username": username
        }

def setup_udf_logger() -> logging.Logger:
    """
    Create a logger that writes to both a file and stdout for use within UDFs.
    
    Returns:
    - Configured logger instance for UDF usage
    """
    import sys
    
    udf_logger = logging.getLogger("alert_analysis_udf")
    udf_logger.setLevel(logging.DEBUG)
    
    # Clear handlers if any exist
    udf_logger.handlers = []
    
    # File handler that writes to a separate detailed log file
    file_handler = logging.FileHandler("alert_analysis_detailed.log")
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler for immediate feedback
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    
    # Use the same formatter as the main logger
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s"
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    udf_logger.addHandler(file_handler)
    udf_logger.addHandler(console_handler)
    
    return udf_logger

def format_time_window(start_time: str, end_time: str) -> str:
    """
    Format a time window for display or logging purposes.
    
    Parameters:
    - start_time: Start timestamp in string format
    - end_time: End timestamp in string format
    
    Returns:
    - Formatted time window string
    """
    from datetime import datetime
    
    try:
        start = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        end = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        
        # If on the same day
        if start.date() == end.date():
            return f"{start.strftime('%Y-%m-%d %H:%M')} - {end.strftime('%H:%M')}"
        else:
            return f"{start.strftime('%Y-%m-%d %H:%M')} - {end.strftime('%Y-%m-%d %H:%M')}"
    except (ValueError, TypeError) as e:
        logger.warning(f"Error formatting time window: {str(e)}")
        return f"{start_time} - {end_time}"

def monitor_system_resources():
    """
    Monitor and log system resources (CPU, memory) usage.
    
    This function is useful for debugging performance issues.
    """
    try:
        import psutil
        import logging
        
        logger = logging.getLogger("alert_analysis")
        
        # Get CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Get memory usage
        mem = psutil.virtual_memory()
        mem_used_gb = mem.used / (1024 * 1024 * 1024)
        mem_total_gb = mem.total / (1024 * 1024 * 1024)
        mem_percent = mem.percent
        
        # Get disk usage
        disk = psutil.disk_usage('/')
        disk_used_gb = disk.used / (1024 * 1024 * 1024)
        disk_total_gb = disk.total / (1024 * 1024 * 1024)
        disk_percent = disk.percent
        
        logger.info(f"System resources: CPU: {cpu_percent}%, Memory: {mem_used_gb:.1f}GB/{mem_total_gb:.1f}GB ({mem_percent}%), " + 
                  f"Disk: {disk_used_gb:.1f}GB/{disk_total_gb:.1f}GB ({disk_percent}%)")
        
        if mem_percent > 90:
            logger.warning("Memory usage is very high! System might become unstable.")
            
        if cpu_percent > 90:
            logger.warning("CPU usage is very high! Processing may be slow.")
            
        if disk_percent > 90:
            logger.warning("Disk space is running low! Results may not be saved correctly.")
            
    except Exception as e:
        logger.error(f"Error monitoring system resources: {str(e)}")