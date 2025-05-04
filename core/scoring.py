"""
This module contains the core scoring functions for alert anomaly detection.
"""
import logging
import numpy as np
from datetime import datetime
from typing import Dict, List, Union, Any

# Get the logger
logger = logging.getLogger("alert_analysis")

def parse_duration(duration_str: str) -> float:
    """
    Parse duration string to minutes with better error handling.
    
    Parameters:
    - duration_str: String representation of duration (e.g., "5 min", "30 sec")
    
    Returns:
    - Duration in minutes as a float
    """
    if not duration_str or not isinstance(duration_str, str):
        logger.warning(f"Invalid duration string: {duration_str}, using default of 1 minute")
        return 1.0  # Default to 1 minute instead of None
    
    tokens = duration_str.split()
    if len(tokens) < 2:
        logger.warning(f"Invalid duration format: {duration_str}, using default of 1 minute")
        return 1.0
    
    try:
        value = float(tokens[0])
    except ValueError:
        logger.warning(f"Could not convert value in duration: {duration_str}, using default of 1 minute")
        return 1.0

    unit = tokens[1].lower()
    if "min" in unit:
        return value
    elif "sec" in unit:
        return value / 60.0
    else:
        logger.warning(f"Unknown time unit in duration: {duration_str}, using default of 1 minute")
        return 1.0

def analyze_timestamp(alert_timestamp: str, personality: Dict[str, Any], alert_id: str) -> Dict[str, float]:
    """
    Unified function for analyzing timestamp-related patterns.
    Combines unusual time score and office hour ratio checks.
    
    Parameters:
    - alert_timestamp: timestamp of the alert
    - personality: dict containing user's behavioral profile
    - alert_id: identifier for the alert for logging context
    
    Returns:
    - Dictionary with time-related scores
    """
    context = f"[Alert:{alert_id}]"
    try:
        dt = datetime.strptime(alert_timestamp, "%Y-%m-%d %H:%M:%S")
    except ValueError as e:
        logger.warning(f"{context} Invalid timestamp format: {alert_timestamp}. Error: {str(e)}")
        return {"unusual_time_score": 0, "office_hour_ratio_score": 0}
        
    hour = dt.hour
    is_weekend = dt.weekday() >= 5  # 0-4 are Monday-Friday, 5-6 are weekend
    
    # Check if time is unusual based on hourly activity
    hourly_activity_distribution = personality.get("hourly_activity_distribution", {})
    activity = hourly_activity_distribution.get(str(hour), 0)
    activity_values = list(hourly_activity_distribution.values())
    if activity_values:
        threshold = np.percentile(activity_values, 25)
        unusual_time_score = 1 if activity < threshold else 0
    else:
        unusual_time_score = 0
    
    # Determine if current time is within typical office hours (9-17)
    is_office_hours = 9 <= hour < 17
    
    # Get the appropriate ratio from the personality profile based on time
    if is_weekend:
        expected_ratio = personality.get("office_hour_activity_ratio_weekend", 
                                       personality.get("office_hour_activity_ratio", 0.5))
        logger.info(f"{context} Weekend alert at hour {hour}, expected activity ratio: {expected_ratio}")
    else:
        expected_ratio = personality.get("office_hour_activity_ratio_weekday", 
                                       personality.get("office_hour_activity_ratio", 0.8))
        logger.info(f"{context} Weekday alert at hour {hour}, expected activity ratio: {expected_ratio}")
    
    # Calculate office hour ratio score
    if (is_office_hours and expected_ratio < 0.3) or (not is_office_hours and expected_ratio > 0.7):
        office_hour_score = 1.0
    elif (is_office_hours and expected_ratio < 0.5) or (not is_office_hours and expected_ratio > 0.5):
        office_hour_score = 0.5
    else:
        office_hour_score = 0.0
    
    logger.info(
        f"{context} Time analysis results: Hour: {hour}, Activity: {activity}, "
        f"Unusual Time Score: {unusual_time_score}, Office Hour Score: {office_hour_score}"
    )
    
    return {
        "unusual_time_score": unusual_time_score,
        "office_hour_ratio_score": office_hour_score
    }

def check_ip_anomalies(alert_row: Dict[str, Any], personality: Dict[str, Any]) -> Dict[str, float]:
    """
    Unified function for checking IP-related anomalies.
    Handles mixtures of known and unknown IPs properly.
    
    Parameters:
    - alert_row: row from the alerts dataframe
    - personality: dict containing user's behavioral profile
    
    Returns:
    - Dictionary with IP-related scores and metadata about IP status
    """
    alert_id = alert_row.get('id', 'unknown')
    user_id = alert_row.get('targetusername', 'unknown')
    context = f"[Alert:{alert_id}|User:{user_id}]"
    
    from utils.helpers import get_source_ips_from_alert
    
    source_ips = get_source_ips_from_alert(alert_row)
    if not source_ips:
        logger.info(f"{context} No source IPs found for IP anomaly checks")
        return {
            "ip_verification_score": 0,
            "ip_failure_rate_score": 0,
            "unique_failed_ips_score": 0,
            "has_unknown_ips": False,
            "all_ips_unknown": False
        }
    
    # Verify if IPs are known
    known_ips = set(personality.get("known_source_ip_set", []))
    known_source_ips = [ip for ip in source_ips if ip in known_ips]
    unknown_ips = [ip for ip in source_ips if ip not in known_ips]
    unknown_ip_count = len(unknown_ips)
    total_ip_count = len(source_ips)
    unknown_ratio = unknown_ip_count / total_ip_count if total_ip_count else 0
    has_unknown_ips = unknown_ratio > 0
    all_ips_unknown = unknown_ratio == 1.0
    
    # Score based on ratio of unknown IPs
    if all_ips_unknown:  # All IPs are unknown
        ip_verification_score = 1.0
    elif unknown_ratio >= 0.5:  # More than half are unknown
        ip_verification_score = 0.8
    elif unknown_ratio > 0:  # Some IPs are unknown
        ip_verification_score = 0.5
    else:  # All IPs are known
        ip_verification_score = 0.0
    
    logger.info(
        f"{context} IP verification: {unknown_ip_count}/{total_ip_count} unknown IPs "
        f"(ratio: {unknown_ratio:.2f}), score: {ip_verification_score}"
    )
    
    # Check IP failure rates - handle known IPs separately
    source_ip_logon_fail_rate = personality.get("source_ip_logon_fail_rate", {})
    all_rates = list(source_ip_logon_fail_rate.values())
    
    # Mixed approach for failure rate calculation
    if all_rates and known_source_ips:
        high_threshold = np.percentile(all_rates, 75)
        very_high_threshold = np.percentile(all_rates, 90)
        
        # For known IPs, calculate failure rate score
        known_ip_scores = []
        for ip in known_source_ips:
            ip_fail_rate = source_ip_logon_fail_rate.get(ip, 0)
            
            if ip_fail_rate >= very_high_threshold:
                score = 1.0
            elif ip_fail_rate >= high_threshold:
                score = 0.5
            else:
                score = 0.0
            
            known_ip_scores.append(score)
            logger.info(f"{context} Known IP {ip} failure rate: {ip_fail_rate}, score: {score}")
        
        # Calculate aggregate failure rate score for known IPs
        if known_ip_scores:
            # Take the maximum score from known IPs
            known_ip_max_score = max(known_ip_scores) if known_ip_scores else 0
            
            # If we have only known IPs, use their score directly
            if not has_unknown_ips:
                max_failure_score = known_ip_max_score
            else:
                # For mixed case (known + unknown IPs), weigh the known IP scores by their proportion
                # but ensure unknown IPs contribute to a higher score
                known_ip_weight = 1 - unknown_ratio
                max_failure_score = (known_ip_max_score * known_ip_weight) + (1.0 * unknown_ratio)
                logger.info(
                    f"{context} Mixed IP scenario: weighing known IP score ({known_ip_max_score}) "
                    f"at {known_ip_weight:.2f} and unknown IPs at {unknown_ratio:.2f}"
                )
        else:
            # No known IPs with failure rate data, use 1.0 score for all unknown IPs
            max_failure_score = 1.0
            logger.info(f"{context} No known IPs with failure rate data - using score 1.0")
    elif all_ips_unknown:
        # All IPs are unknown, maximum score
        max_failure_score = 1.0
        logger.info(f"{context} All IPs are unknown, assigning maximum failure score")
    else:
        # No data available
        max_failure_score = 0
        logger.info(f"{context} No IP failure rate data available")
    
    # Check unique failed IPs - similar mixed approach
    avg_ips_per_day = personality.get("avg_ips_per_day", 2)  # Default from sample data
    duration_minutes = parse_duration(alert_row.get("duration", "1 min"))
    
    # If we have mostly unknown IPs, this is highly suspicious
    if unknown_ratio >= 0.5:
        unique_failed_ips_score = 1.0
        logger.info(
            f"{context} High ratio of unknown IPs ({unknown_ratio:.2f}), "
            f"assigning maximum unique failed IPs score: {unique_failed_ips_score}"
        )
    else:
        # Calculate for both known and unknown IPs
        unique_ips_count = len(set(source_ips))
        unique_ips_rate = unique_ips_count / duration_minutes
        
        # Base score calculation
        if unique_ips_rate > 3 * avg_ips_per_day:
            base_score = 1.0
        elif unique_ips_rate > 2 * avg_ips_per_day:
            base_score = 0.7
        elif unique_ips_rate > avg_ips_per_day:
            base_score = 0.3
        else:
            base_score = 0.0
        
        # Add penalty for unknown IPs
        if has_unknown_ips:
            # Add up to 0.3 additional score based on unknown ratio
            unknown_penalty = min(0.3, unknown_ratio * 0.6)
            unique_failed_ips_score = min(1.0, base_score + unknown_penalty)
            logger.info(
                f"{context} Adding penalty of {unknown_penalty:.2f} for unknown IPs "
                f"to base unique IPs score {base_score:.2f}"
            )
        else:
            unique_failed_ips_score = base_score
        
        logger.info(
            f"{context} Unique failed IPs: {unique_ips_count} IPs over {duration_minutes:.2f} min "
            f"(rate: {unique_ips_rate:.2f}/min, user avg IPs per day: {avg_ips_per_day:.2f}), "
            f"final score: {unique_failed_ips_score}"
        )
    
    return {
        "ip_verification_score": ip_verification_score,
        "ip_failure_rate_score": max_failure_score,
        "unique_failed_ips_score": unique_failed_ips_score,
        "has_unknown_ips": has_unknown_ips,
        "all_ips_unknown": all_ips_unknown
    }

def compute_logon_failure_score(
    alert_occurrence: Union[str, int, float], 
    duration_str: str, 
    avg_failure: float,  # Not used now, but kept for compatibility
    max_failure: float,
    alert_id: str,
    buffer_ratio: float = 0.1  # 10% buffer to allow slight variation
) -> float:
    """
    Compute score based on logon failure rate compared only to user's max behavior.
    Only values significantly above max_failure (with buffer) are considered anomalous.
    
    Parameters:
    - alert_occurrence: Number of occurrences in the alert
    - duration_str: Duration string from the alert
    - avg_failure: Average failure rate from the user's profile (ignored)
    - max_failure: Maximum failure rate from the user's profile
    - alert_id: Alert identifier for logging context
    - buffer_ratio: Allowed buffer ratio over max before flagging as anomaly (default 10%)
    
    Returns:
    - 1.0 if anomalous, 0.0 otherwise
    """
    context = f"[Alert:{alert_id}]"

    try:
        occurrence = float(alert_occurrence)
    except (ValueError, TypeError):
        logger.warning(f"{context} Invalid occurrence value: {alert_occurrence}, using default of 0")
        occurrence = 0

    duration_minutes = parse_duration(duration_str)
    if duration_minutes <= 0:
        logger.debug(f"{context} Duration is zero or negative, using default of 1 minute")
        duration_minutes = 1.0

    rate = occurrence / duration_minutes
    threshold = max_failure * (1 + buffer_ratio)

    logger.info(f"{context} Logon failure rate: {rate:.2f}/min (Max: {max_failure:.2f}, Threshold w/ buffer: {threshold:.2f})")

    if rate > threshold:
        logger.info(f"{context} Logon failure rate exceeds threshold buffer, score: 1.0 (Anomaly)")
        return 1.0
    else:
        logger.info(f"{context} Logon failure rate within acceptable range, score: 0.0 (Normal)")
        return 0.0

def check_dest_port(dest_port: Union[str, int], common_dest_ports: List[int], alert_id: str) -> float:
    """
    Check if destination port is unusual.
    
    Parameters:
    - dest_port: The destination port to check
    - common_dest_ports: List of ports commonly used by the user
    - alert_id: Alert identifier for logging context
    
    Returns:
    - Score (1.0 if unusual, 0.0 if common)
    """
    context = f"[Alert:{alert_id}]"
    
    if dest_port is None or (isinstance(dest_port, str) and dest_port.strip() == ""):
        logger.info(f"{context} No destination port specified")
        return 0
        
    try:
        port_num = int(dest_port)
        is_unusual = port_num not in common_dest_ports
        logger.info(f"{context} Dest port {port_num} is {'unusual' if is_unusual else 'common'}")
        return 1 if is_unusual else 0
    except (ValueError, TypeError):
        logger.warning(f"{context} Invalid destination port value: {dest_port}")
        return 0

def check_admin_action(alert_row: Dict[str, Any], personality: Dict[str, Any]) -> Dict[str, float]:
    """
    Unified function for checking administrative actions like
    account/group modifications and log clearing.
    
    Only computes scores when occurrences exceed thresholds in the personality profile.
    
    Parameters:
    - alert_row: row from the alerts dataframe
    - personality: dict containing user's behavioral profile
    
    Returns:
    - Dictionary with admin action scores
    """
    alert_id = alert_row.get('id', 'unknown')
    user_id = alert_row.get('targetusername', 'unknown')
    context = f"[Alert:{alert_id}|User:{user_id}]"
    
    rule_name = alert_row.get("rule_name", "")
    occurrence = alert_row.get("occurrence", 1)  # Default to 1 if not provided
    scores = {
        "account_modification_score": 0.0,
        "group_modification_score": 0.0,
        "log_clearing_score": 0.0
    }
    
    # Check account modification
    if "Windows Account Created" in rule_name or "Windows Account Deleted" in rule_name:
        max_account_mod = personality.get("max_account_modifications_per_minute", 0.0)
        avg_account_mod = personality.get("avg_account_modifications_per_minute", 0.0)
        logger.info(f"{context} Account modification check - occurrence: {occurrence}, max: {max_account_mod}, avg: {avg_account_mod}")
        
        # Only compute score if occurrence exceeds max threshold
        if max_account_mod > 0 and occurrence > max_account_mod:
            # For occurrences above max, score increases with ratio (capped at 1.0)
            ratio = occurrence / max_account_mod
            scores["account_modification_score"] = min(1.0, 0.5 + (ratio - 1.0) / 2)
        elif max_account_mod == 0 and occurrence > 0:
            # If user never modifies accounts, any occurrence is highly suspicious
            scores["account_modification_score"] = 1.0
    
    # Check group modification
    if "User Added to Admin Group" in rule_name or "User Added/Removed from Admin Group" in rule_name:
        max_group_mod = personality.get("max_User_Added/Removed_from_Admin_Group", 0.0)
        avg_group_mod = personality.get("avg_User_Added/Removed_from_Admin_Group", 0.0)
        logger.info(f"{context} Group modification check - occurrence: {occurrence}, max: {max_group_mod}, avg: {avg_group_mod}")
        
        # Only compute score if occurrence exceeds max threshold
        if max_group_mod > 0 and occurrence > max_group_mod:
            ratio = occurrence / max_group_mod
            scores["group_modification_score"] = min(1.0, 0.5 + (ratio - 1.0) / 2)
        elif max_group_mod == 0 and occurrence > 0:
            scores["group_modification_score"] = 1.0  
    # === Audit Log Clearing Check ===
    if "Audit Log Cleared" in rule_name:
        max_log_clears = personality.get("max_log_clears_per_min", 0.0)
        logger.info(f"{context} Log clearing check - occurrence: {occurrence}, max: {max_log_clears}")
        
        if max_log_clears == 0 and occurrence > 0:
            scores["log_clearing_score"] = 1.0
        elif max_log_clears > 0 and occurrence > max_log_clears:
            ratio = occurrence / max_log_clears
            scores["log_clearing_score"] = min(1.0, 0.5 + (ratio - 1.0) / 2)

    return scores

def get_dynamic_weights(rule_name: str, has_unknown_ips: bool = False, all_ips_unknown: bool = False) -> Dict[str, float]:
    """
    Return appropriate weights based on the rule category and IP status.
    
    Parameters:
    - rule_name: the name of the rule that triggered the alert
    - has_unknown_ips: flag indicating if any unknown IPs were detected
    - all_ips_unknown: flag indicating if all IPs are unknown
    
    Returns:
    - Dictionary of weights for different factors
    """
    # Define rule categories
    brute_force_rules = ["Brute Force Attempt"]
    multiple_ip_rules = ["Login Attempts with Same Account from Different Source IPs"]
    account_mod_rules = ["Windows Account Created", "Windows Account Deleted"]
    group_mod_rules = ["User Added to Admin Group", "User Removed from Admin Group"]
    log_clearing_rules = ["Audit Log Cleared"]
    
    # Match rule to category
    if any(rule in rule_name for rule in brute_force_rules):
        if all_ips_unknown:
            # All IPs unknown - maximum weight on verification
            return {
                "unusual_time": 0.10,
                "office_hour_ratio": 0.20,
                "logon_failure": 0.20,
                "ip_verification": 0.30,  # Increased from 0.15
                "ip_failure_rate": 0.0,   # Reduced to 0
                "unique_failed_ips": 0.15,
                "dest_port": 0.05,
                "account_modification": 0.0,
                "group_modification": 0.0,
                "log_clearing": 0.0
            }
        elif has_unknown_ips:
            # Mix of known and unknown IPs - balanced approach
            return {
                "unusual_time": 0.10,
                "office_hour_ratio": 0.15,
                "logon_failure": 0.20,
                "ip_verification": 0.25,  # Moderately increased
                "ip_failure_rate": 0.10,  # Reduced but still present
                "unique_failed_ips": 0.15,
                "dest_port": 0.05,
                "account_modification": 0.0,
                "group_modification": 0.0,
                "log_clearing": 0.0
            }
        else:
            # Original weights when all IPs are known
            return {
                "unusual_time": 0.10,
                "office_hour_ratio": 0.15,
                "logon_failure": 0.20,
                "ip_verification": 0.15,
                "ip_failure_rate": 0.15,
                "unique_failed_ips": 0.15,
                "dest_port": 0.10,
                "account_modification": 0.0,
                "group_modification": 0.0,
                "log_clearing": 0.0
            }
    
    elif any(rule in rule_name for rule in multiple_ip_rules):
        if all_ips_unknown:
            # All IPs unknown - maximum focus on verification and unique IPs
            return {
                "unusual_time": 0.10,
                "office_hour_ratio": 0.10,
                "logon_failure": 0.10,
                "ip_verification": 0.35,  # Increased significantly
                "ip_failure_rate": 0.0,   # Reduced to 0
                "unique_failed_ips": 0.25, # Increased
                "dest_port": 0.10,
                "account_modification": 0.0,
                "group_modification": 0.0,
                "log_clearing": 0.0
            }
        elif has_unknown_ips:
            # Mix of known and unknown IPs - specialized for multiple IP scenario
            return {
                "unusual_time": 0.10,
                "office_hour_ratio": 0.10,
                "logon_failure": 0.10,
                "ip_verification": 0.25,  # Moderately increased
                "ip_failure_rate": 0.15,  # Reduced but still considered
                "unique_failed_ips": 0.20, # Increased as this is more relevant
                "dest_port": 0.10,
                "account_modification": 0.0,
                "group_modification": 0.0,
                "log_clearing": 0.0
            }
        else:
            # Original weights when all IPs are known
            return {
                "unusual_time": 0.10,
                "office_hour_ratio": 0.10,
                "logon_failure": 0.15,
                "ip_verification": 0.20,
                "ip_failure_rate": 0.15,
                "unique_failed_ips": 0.20,
                "dest_port": 0.10,
                "account_modification": 0.0,
                "group_modification": 0.0,
                "log_clearing": 0.0
            }
    
    elif any(rule in rule_name for rule in account_mod_rules):
        return {
            "unusual_time": 0.15,
            "office_hour_ratio": 0.15,
            "logon_failure": 0.0,
            "ip_verification": 0.25,
            "ip_failure_rate": 0.0,
            "unique_failed_ips": 0.0,
            "dest_port": 0.0,
            "account_modification": 0.45,
            "group_modification": 0.0,
            "log_clearing": 0.0
        }
    
    elif any(rule in rule_name for rule in group_mod_rules):
        return {
            "unusual_time": 0.15,
            "office_hour_ratio": 0.15,
            "logon_failure": 0.0,
            "ip_verification": 0.20,
            "ip_failure_rate": 0.0,
            "unique_failed_ips": 0.0,
            "dest_port": 0.05,
            "account_modification": 0.0,
            "group_modification": 0.45,
            "log_clearing": 0.0
        }
    
    elif any(rule in rule_name for rule in log_clearing_rules):
        return {
            "unusual_time": 0.15,
            "office_hour_ratio": 0.20,
            "logon_failure": 0.0,
            "ip_verification": 0.15,
            "ip_failure_rate": 0.0,
            "unique_failed_ips": 0.0,
            "dest_port": 0.05,
            "account_modification": 0.0,
            "group_modification": 0.0,
            "log_clearing": 0.45
        }
    
    # Default weights for general cases - adjust based on unknown IPs
    if has_unknown_ips:
        return {
            "unusual_time": 0.15,
            "office_hour_ratio": 0.15,
            "logon_failure": 0.15,
            "ip_verification": 0.25,  # Increased from 0.10
            "ip_failure_rate": 0.0,   # Reduced to 0
            "unique_failed_ips": 0.10,
            "dest_port": 0.05,
            "account_modification": 0.05,
            "group_modification": 0.05,
            "log_clearing": 0.05
        }
    else:
        return {
            "unusual_time": 0.15,
            "office_hour_ratio": 0.15,
            "logon_failure": 0.15,
            "ip_verification": 0.10,
            "ip_failure_rate": 0.10,
            "unique_failed_ips": 0.10,
            "dest_port": 0.05,
            "account_modification": 0.10,
            "group_modification": 0.05,
            "log_clearing": 0.05
        }
        
def compute_alert_anomaly_score(alert_row: Dict[str, Any], personality: Dict[str, Any]) -> float:
    """
    Calculate anomaly score with optimized calculations and reduced redundancy.
    Enhanced to handle mixed IP scenarios.
    
    Parameters:
    - alert_row: row from the alerts dataframe
    - personality: dict containing user's behavioral profile
    
    Returns:
    - Overall anomaly score between 0 and 1
    """
    alert_id = alert_row.get('id', 'unknown')
    user_id = alert_row.get('targetusername', 'unknown')
    context = f"[Alert:{alert_id}|User:{user_id}]"
    
    rule_name = alert_row.get("rule_name", "")
    logger.info(f"{context} Processing alert - Rule: {rule_name}")
    
    # Unified timestamp analysis
    time_scores = analyze_timestamp(alert_row["timestamp"], personality, alert_id)
    
    # Unified IP anomaly checks - now returns enhanced IP metadata
    ip_anomaly_results = check_ip_anomalies(alert_row, personality)
    has_unknown_ips = ip_anomaly_results.pop("has_unknown_ips")
    all_ips_unknown = ip_anomaly_results.pop("all_ips_unknown")
    ip_scores = ip_anomaly_results  # The remaining dict has only the scores
    
    # Log IP status
    if all_ips_unknown:
        logger.info(f"{context} All IPs are unknown - adjusting weights for maximum security")
    elif has_unknown_ips:
        logger.info(f"{context} Mix of known and unknown IPs detected - using specialized weighting")
    
    # Get dynamic weights based on rule name AND IP status
    weights = get_dynamic_weights(rule_name, has_unknown_ips, all_ips_unknown)
    logger.debug(f"{context} Using weights for rule '{rule_name}' (unknown IPs: {has_unknown_ips}, all unknown: {all_ips_unknown}): {weights}")
    
    # Logon failure analysis
    logon_failure_score = compute_logon_failure_score(
        alert_row.get("occurrence", 0),
        alert_row.get("duration", "1 min"),
        personality.get("avg_logon_failures_per_minute", 0),
        personality.get("max_logon_failures_per_minute", 1),
        alert_id
    )
    
    # Destination port check
    dest_port_score = check_dest_port(
        alert_row.get("dest_port", ""),
        personality.get("common_dest_ports", []),
        alert_id
    )
    
    # Admin action checks
    admin_scores = check_admin_action(alert_row, personality)
    
    # Combine all scores with weights
    score_components = {
        "unusual_time": time_scores["unusual_time_score"],
        "office_hour_ratio": time_scores["office_hour_ratio_score"],
        "logon_failure": logon_failure_score,
        "ip_verification": ip_scores["ip_verification_score"],
        "ip_failure_rate": ip_scores["ip_failure_rate_score"],
        "unique_failed_ips": ip_scores["unique_failed_ips_score"],
        "dest_port": dest_port_score,
        "account_modification": admin_scores["account_modification_score"],
        "group_modification": admin_scores["group_modification_score"],
        "log_clearing": admin_scores["log_clearing_score"]
    }
    
    # Apply weights to calculate overall score
    overall_score = sum(weights.get(component, 0) * score for component, score in score_components.items())
    
    # Log detailed scores
    logger.info(
        f"{context} Component scores - Time: {score_components['unusual_time']:.2f}, "
        f"OfficeHour: {score_components['office_hour_ratio']:.2f}, "
        f"Logon: {score_components['logon_failure']:.2f}, "
        f"IPVerification: {score_components['ip_verification']:.2f}, "
        f"IPFailRate: {score_components['ip_failure_rate']:.2f}, "
        f"UniqueFailedIPs: {score_components['unique_failed_ips']:.2f}, "
        f"DestPort: {score_components['dest_port']:.2f}, "
        f"AccountMod: {score_components['account_modification']:.2f}, "
        f"GroupMod: {score_components['group_modification']:.2f}, "
        f"LogClearing: {score_components['log_clearing']:.2f}"
    )
    logger.info(f"{context} Overall Anomaly Score: {overall_score:.4f}")
    
    return overall_score