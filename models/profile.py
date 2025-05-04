"""
This module defines the UserProfile data model representing a user's behavior profile.
"""
from typing import Dict, List, Any, Optional, Set


class UserProfile:
    """
    Model class representing a user's behavior profile.
    
    This class provides a structured representation of user behavior patterns
    for use in anomaly detection.
    """
    
    def __init__(
        self,
        username: str,
        hourly_activity_distribution: Optional[Dict[str, float]] = None,
        office_hour_activity_ratio: Optional[float] = None,
        office_hour_activity_ratio_weekday: Optional[float] = None,
        office_hour_activity_ratio_weekend: Optional[float] = None,
        known_source_ip_set: Optional[List[str]] = None,
        source_ip_logon_fail_rate: Optional[Dict[str, float]] = None,
        avg_logon_failures_per_minute: float = 0.0,
        max_logon_failures_per_minute: float = 1.0,
        common_dest_ports: Optional[List[int]] = None,
        avg_account_modifications_per_minute: float = 0.0,
        max_account_modifications_per_minute: float = 0.0,
        avg_group_modifications_per_minute: float = 0.0,
        max_group_modifications_per_minute: float = 0.0,
        max_log_clears_per_min: float = 0.0,
        avg_ips_per_day: float = 2.0,
        **additional_fields
    ):
        """
        Initialize a UserProfile instance.
        
        Parameters:
        - username: Username of the user
        - hourly_activity_distribution: Dict mapping hour (0-23) to activity level
        - office_hour_activity_ratio: Ratio of activity during office hours (9-17)
        - office_hour_activity_ratio_weekday: Office hour ratio for weekdays
        - office_hour_activity_ratio_weekend: Office hour ratio for weekends
        - known_source_ip_set: List of known source IPs for this user
        - source_ip_logon_fail_rate: Dict mapping IPs to their logon failure rates
        - avg_logon_failures_per_minute: Average rate of logon failures
        - max_logon_failures_per_minute: Maximum rate of logon failures
        - common_dest_ports: List of commonly used destination ports
        - avg_account_modifications_per_minute: Average account modifications
        - max_account_modifications_per_minute: Maximum account modifications
        - avg_group_modifications_per_minute: Average group modifications
        - max_group_modifications_per_minute: Maximum group modifications 
        - max_log_clears_per_min: Maximum log clearing operations per minute
        - avg_ips_per_day: Average number of unique IPs used per day
        - additional_fields: Any additional profile attributes
        """
        self.username = username
        
        # Time-based behavior patterns
        self.hourly_activity_distribution = hourly_activity_distribution or {}
        self.office_hour_activity_ratio = office_hour_activity_ratio or 0.8
        self.office_hour_activity_ratio_weekday = office_hour_activity_ratio_weekday or self.office_hour_activity_ratio
        self.office_hour_activity_ratio_weekend = office_hour_activity_ratio_weekend or 0.5
        
        # IP-related patterns
        self.known_source_ip_set = known_source_ip_set or []
        self.source_ip_logon_fail_rate = source_ip_logon_fail_rate or {}
        self.avg_ips_per_day = avg_ips_per_day
        
        # Authentication patterns
        self.avg_logon_failures_per_minute = avg_logon_failures_per_minute
        self.max_logon_failures_per_minute = max_logon_failures_per_minute
        
        # Network patterns
        self.common_dest_ports = common_dest_ports or [80, 443, 8080, 22, 3389]
        
        # Administrative action patterns
        self.avg_account_modifications_per_minute = avg_account_modifications_per_minute
        self.max_account_modifications_per_minute = max_account_modifications_per_minute
        self.avg_group_modifications_per_minute = avg_group_modifications_per_minute 
        self.max_group_modifications_per_minute = max_group_modifications_per_minute
        self.max_log_clears_per_min = max_log_clears_per_min
        
        # Store user role and other additional fields
        self.additional_fields = additional_fields
        self.role = additional_fields.get('role', 'user')
        
    def add_known_ip(self, ip: str) -> None:
        """
        Add an IP address to the set of known IPs.
        
        Parameters:
        - ip: IP address to add
        """
        if ip and ip not in self.known_source_ip_set:
            self.known_source_ip_set.append(ip)
    
    def update_hourly_activity(self, hour: int, activity_level: float) -> None:
        """
        Update the activity level for a specific hour.
        
        Parameters:
        - hour: Hour of day (0-23)
        - activity_level: Activity level to set
        """
        if 0 <= hour <= 23:
            self.hourly_activity_distribution[str(hour)] = activity_level
    
    def is_ip_known(self, ip: str) -> bool:
        """
        Check if an IP address is known for this user.
        
        Parameters:
        - ip: IP address to check
        
        Returns:
        - True if IP is known, False otherwise
        """
        return ip in self.known_source_ip_set
    
    def get_ip_failure_rate(self, ip: str) -> float:
        """
        Get the logon failure rate for a specific IP.
        
        Parameters:
        - ip: IP address to check
        
        Returns:
        - Failure rate or 0 if IP not found
        """
        return self.source_ip_logon_fail_rate.get(ip, 0.0)
    
    def is_port_common(self, port: int) -> bool:
        """
        Check if a destination port is commonly used by this user.
        
        Parameters:
        - port: Port number to check
        
        Returns:
        - True if port is common, False otherwise
        """
        return port in self.common_dest_ports
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the profile to a dictionary representation.
        
        Returns:
        - Dictionary representation of the profile
        """
        result = {
            "username": self.username,
            "hourly_activity_distribution": self.hourly_activity_distribution,
            "office_hour_activity_ratio": self.office_hour_activity_ratio,
            "office_hour_activity_ratio_weekday": self.office_hour_activity_ratio_weekday,
            "office_hour_activity_ratio_weekend": self.office_hour_activity_ratio_weekend,
            "known_source_ip_set": self.known_source_ip_set,
            "source_ip_logon_fail_rate": self.source_ip_logon_fail_rate,
            "avg_logon_failures_per_minute": self.avg_logon_failures_per_minute,
            "max_logon_failures_per_minute": self.max_logon_failures_per_minute,
            "common_dest_ports": self.common_dest_ports,
            "avg_account_modifications_per_minute": self.avg_account_modifications_per_minute,
            "max_account_modifications_per_minute": self.max_account_modifications_per_minute,
            # Use original field names instead of normalized ones
            "avg_User_Added/Removed_from_Admin_Group": self.avg_group_modifications_per_minute,
            "max_User_Added/Removed_from_Admin_Group": self.max_group_modifications_per_minute,
            "max_log_clears_per_min": self.max_log_clears_per_min,
            "avg_ips_per_day": self.avg_ips_per_day,
            "role": self.role
        }
        
        # Add any additional fields
        result.update(self.additional_fields)
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserProfile':
        """
        Create a UserProfile instance from a dictionary.
        
        Parameters:
        - data: Dictionary containing profile data
        
        Returns:
        - UserProfile instance
        """
        # Required field, ensure it's present
        if 'username' not in data:
            raise ValueError("Username is required for user profile")
        
        # Extract the username first
        username = data['username']
        
        # Create a data copy without the username to avoid the duplicate parameter
        profile_data = data.copy()
        if 'username' in profile_data:
            del profile_data['username']
        
        # Create profile instance with username as the first parameter
        return cls(username=username, **profile_data)
    
    def __str__(self) -> str:
        """String representation of the profile."""
        return f"UserProfile({self.username}, role={self.role}, {len(self.known_source_ip_set)} known IPs)"
    
    def __repr__(self) -> str:
        """Developer representation of the profile."""
        return f"UserProfile(username={self.username}, role={self.role})"

def load_profiles_from_json(json_path: str) -> Dict[str, UserProfile]:
    """
    Load user profiles from a JSON file.
    
    Parameters:
    - json_path: Path to the JSON file
    
    Returns:
    - Dictionary mapping usernames to UserProfile instances
    """
    import json
    import logging
    
    logger = logging.getLogger("alert_analysis")
    
    try:
        with open(json_path, 'r') as f:
            profiles_data = json.load(f)
        
        # Convert dictionary data to UserProfile objects
        profiles = {}
        for username, profile_data in profiles_data.items():
            # Add username to the data if not present
            if 'username' not in profile_data:
                profile_data['username'] = username
                
            try:
                profile = UserProfile.from_dict(profile_data)
                profiles[username] = profile
            except Exception as e:
                logger.warning(f"Error loading profile for user {username}: {str(e)}")
        
        logger.info(f"Successfully loaded {len(profiles)} user profiles")
        return profiles
    
    except Exception as e:
        logger.error(f"Error loading profiles from {json_path}: {str(e)}")
        return {}