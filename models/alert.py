"""
This module defines the Alert data model representing a security alert.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any, Union


class Alert:
    """
    Model class representing a security alert.
    
    This class provides a structured representation of security alert data
    with validation and helper methods.
    """
    
    def __init__(
        self,
        id: Union[str, int],
        timestamp: str,
        targetusername: str,
        rule_name: str,
        severity: str,
        source_ip: Optional[str] = None,
        duration: Optional[str] = None,
        occurrence: Optional[int] = None,
        dest_ip: Optional[str] = None,
        dest_port: Optional[int] = None,
        alert_type: Optional[str] = None,
        source_ips: Optional[str] = None,
        hour_of_day: Optional[int] = None,
        is_weekend: Optional[bool] = None,
        **additional_fields
    ):
        """
        Initialize an Alert instance.
        
        Parameters:
        - id: Unique identifier for the alert
        - timestamp: Timestamp when alert occurred
        - targetusername: Username of the affected user
        - rule_name: Name of the rule that triggered the alert
        - severity: Severity level (e.g., "Low", "Medium", "High")
        - source_ip: Source IP address
        - duration: Duration string (e.g., "5 min", "30 sec")
        - occurrence: Number of times the event occurred
        - dest_ip: Destination IP address
        - dest_port: Destination port number
        - alert_type: Type of alert (e.g., "real", "test")
        - source_ips: Comma-separated list of source IPs (for multi-IP alerts)
        - hour_of_day: Hour of day (0-23)
        - is_weekend: Whether the alert occurred on a weekend
        - additional_fields: Any additional fields in the alert
        """
        self.id = str(id)
        self.timestamp = timestamp
        self.targetusername = targetusername
        self.rule_name = rule_name
        self.severity = severity
        self.source_ip = source_ip
        self.duration = duration or "1 min"
        self.occurrence = int(occurrence) if occurrence is not None else 1
        self.dest_ip = dest_ip
        self.dest_port = int(dest_port) if dest_port is not None else None
        self.alert_type = alert_type
        self.source_ips = source_ips
        
        # Derived fields that can be either provided or calculated
        if hour_of_day is not None:
            self.hour_of_day = int(hour_of_day)
        else:
            self.hour_of_day = self._extract_hour_from_timestamp()
            
        if is_weekend is not None:
            self.is_weekend = bool(is_weekend)
        else:
            self.is_weekend = self._is_weekend_from_timestamp()
        
        # Store any additional fields
        self.additional_fields = additional_fields
        
        # Fields for analysis results (to be filled later)
        self.anomaly_score = None
        self.classification = None
        self.component_scores = {}
    
    def _extract_hour_from_timestamp(self) -> int:
        """Extract hour of day from timestamp."""
        try:
            dt = datetime.strptime(self.timestamp, "%Y-%m-%d %H:%M:%S")
            return dt.hour
        except (ValueError, TypeError):
            return 0
    
    def _is_weekend_from_timestamp(self) -> bool:
        """Determine if timestamp is on a weekend."""
        try:
            dt = datetime.strptime(self.timestamp, "%Y-%m-%d %H:%M:%S")
            # 0-4 are Monday-Friday, 5-6 are weekend
            return dt.weekday() >= 5
        except (ValueError, TypeError):
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the alert to a dictionary representation.
        
        Returns:
        - Dictionary representation of the alert
        """
        result = {
            "id": self.id,
            "timestamp": self.timestamp,
            "targetusername": self.targetusername,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "hour_of_day": self.hour_of_day,
            "is_weekend": self.is_weekend,
            "occurrence": self.occurrence
        }
        
        # Add optional fields if they exist
        if self.source_ip:
            result["source_ip"] = self.source_ip
        if self.duration:
            result["duration"] = self.duration
        if self.dest_ip:
            result["dest_ip"] = self.dest_ip
        if self.dest_port is not None:
            result["dest_port"] = self.dest_port
        if self.alert_type:
            result["alert_type"] = self.alert_type
        if self.source_ips:
            result["source_ips"] = self.source_ips
            
        # Add analysis results if available
        if self.anomaly_score is not None:
            result["anomaly_score"] = self.anomaly_score
        if self.classification:
            result["classification"] = self.classification
            
        # Add component scores if available
        if self.component_scores:
            result["component_scores"] = self.component_scores
            
        # Add any additional fields
        result.update(self.additional_fields)
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Alert':
        """
        Create an Alert instance from a dictionary.
        
        Parameters:
        - data: Dictionary containing alert data
        
        Returns:
        - Alert instance
        """
        # Extract known fields
        known_fields = [
            'id', 'timestamp', 'targetusername', 'rule_name', 'severity',
            'source_ip', 'duration', 'occurrence', 'dest_ip', 'dest_port',
            'alert_type', 'source_ips', 'hour_of_day', 'is_weekend'
        ]
        
        # Split into known and additional fields
        alert_args = {k: data[k] for k in known_fields if k in data}
        additional_fields = {k: v for k, v in data.items() if k not in known_fields}
        
        # Create alert instance
        alert = cls(**alert_args, **additional_fields)
        
        # Add analysis results if available
        if 'anomaly_score' in data:
            alert.anomaly_score = data['anomaly_score']
        if 'classification' in data:
            alert.classification = data['classification']
        if 'component_scores' in data:
            alert.component_scores = data['component_scores']
            
        return alert
    
    def get_source_ips(self) -> List[str]:
        """
        Get a list of source IPs from the alert.
        Handles both single IP and multi-IP scenarios.
        
        Returns:
        - List of source IP addresses
        """
        if self.rule_name == "Login Attempts with Same Account from Different Source IPs" and self.source_ips:
            return [ip.strip() for ip in self.source_ips.split(",")]
        elif self.source_ip:
            return [self.source_ip]
        else:
            return []
    
    def __str__(self) -> str:
        """String representation of the alert."""
        if hasattr(self, 'anomaly_score') and self.anomaly_score is not None:
            return f"Alert {self.id} - Rule: {self.rule_name} - User: {self.targetusername} - Score: {self.anomaly_score:.2f} ({self.classification})"
        else:
            return f"Alert {self.id} - Rule: {self.rule_name} - User: {self.targetusername}"
    
    def __repr__(self) -> str:
        """Developer representation of the alert."""
        return f"Alert(id={self.id}, rule={self.rule_name}, user={self.targetusername})"