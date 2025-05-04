"""
This module contains functions for classifying alerts based on their anomaly scores.
"""
import logging

# Get the logger
logger = logging.getLogger("alert_analysis")

# Default thresholds
DEFAULT_NORMAL_THRESHOLD = 0.35
DEFAULT_ANOMALOUS_THRESHOLD = 0.7

def classify_alert(
    score: float, 
    threshold_normal: float = DEFAULT_NORMAL_THRESHOLD, 
    threshold_anomalous: float = DEFAULT_ANOMALOUS_THRESHOLD,
    alert_id: str = "unknown"
) -> str:
    """
    Classify alert based on anomaly score and configurable thresholds.
    
    Parameters:
    - score: Anomaly score (0-1)
    - threshold_normal: Score below this is considered normal
    - threshold_anomalous: Score above this is considered anomalous
    - alert_id: Alert identifier for logging context
    
    Returns:
    - Classification string: "Normal", "Suspicious", or "Anomalous"
    """
    context = f"[Alert:{alert_id}]"
    
    if score < threshold_normal:
        result = "Normal"
    elif score < threshold_anomalous:
        result = "Suspicious"
    else:
        result = "Anomalous"
        
    logger.info(f"{context} Classification based on score {score:.2f}: {result}")
    return result