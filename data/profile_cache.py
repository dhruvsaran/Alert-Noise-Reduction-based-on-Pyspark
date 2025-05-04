"""
This module provides caching functionality for user behavior profiles.
"""
import json
import logging
import os
from datetime import datetime
from typing import Dict, Any, Optional

# Get the logger
logger = logging.getLogger("alert_analysis")

class ProfileCache:
    """
    Manages caching and retrieval of user behavior profiles.
    Provides memory caching with disk persistence for efficiency.
    """
    
    def __init__(self, cache_file_path: str = "profile_cache.json"):
        """
        Initialize the profile cache.
        
        Parameters:
        - cache_file_path: Path to the cache file for persistence
        """
        self.cache_file_path = cache_file_path
        self.profiles = {}
        self.last_loaded = None
        self.cache_ttl = 3600  # Cache time-to-live in seconds (1 hour)
        
    def load_profiles_from_file(self, file_path: str) -> Dict[str, Dict[str, Any]]:
        """
        Load profiles from a JSON file.
        
        Parameters:
        - file_path: Path to the JSON file containing profiles
        
        Returns:
        - Dictionary of user profiles
        """
        logger.info(f"Loading profiles from file: {file_path}")
        try:
            with open(file_path, 'r') as f:
                profiles = json.load(f)
            
            # Update in-memory cache
            self.profiles = profiles
            self.last_loaded = datetime.now()
            
            # Save to disk cache
            self._save_to_disk_cache()
            
            logger.info(f"Successfully loaded {len(profiles)} profiles")
            return profiles
        except Exception as e:
            logger.error(f"Error loading profiles from file {file_path}: {str(e)}")
            # Try to recover from disk cache
            return self._load_from_disk_cache()
    
    def get_profile(self, username: str) -> Dict[str, Any]:
        """
        Get a user's profile from cache. If not present or expired, loads from original source.
        
        Parameters:
        - username: Username to look up
        
        Returns:
        - User profile dictionary or empty dict if not found
        """
        # Check if cache is expired
        if self._is_cache_expired():
            logger.info("Profile cache expired, reloading profiles")
            self._reload_profiles()
        
        # Return profile from cache if available
        return self.profiles.get(username, {})
    
    def update_profile(self, username: str, profile_data: Dict[str, Any]) -> None:
        """
        Update a user's profile in the cache.
        
        Parameters:
        - username: Username to update
        - profile_data: New profile data
        """
        self.profiles[username] = profile_data
        self._save_to_disk_cache()
        logger.info(f"Updated profile for user: {username}")
    
    def refresh(self, source_path: Optional[str] = None) -> None:
        """
        Force a refresh of the profile cache.
        
        Parameters:
        - source_path: Optional source path to reload from
        """
        if source_path:
            self.load_profiles_from_file(source_path)
        else:
            self._reload_profiles()
    
    def _is_cache_expired(self) -> bool:
        """Check if the cache has expired based on TTL."""
        if self.last_loaded is None:
            return True
        
        elapsed = (datetime.now() - self.last_loaded).total_seconds()
        return elapsed > self.cache_ttl
    
    def _reload_profiles(self) -> None:
        """Reload profiles from original source or disk cache."""
        try:
            # Try to reload from disk cache
            self._load_from_disk_cache()
            self.last_loaded = datetime.now()
        except Exception as e:
            logger.error(f"Failed to reload profiles: {str(e)}")
    
    def _save_to_disk_cache(self) -> None:
        """Save the current profiles to disk cache."""
        try:
            # Convert UserProfile objects to dictionaries before saving to JSON
            profiles_dict = {}
            for username, profile in self.profiles.items():
                if isinstance(profile, dict):
                    profiles_dict[username] = profile
                else:
                    # UserProfile object - convert to dictionary
                    profiles_dict[username] = profile.to_dict()
                    
            # Save the dictionary to disk
            with open(self.cache_file_path, 'w') as f:
                json.dump(profiles_dict, f)
            logger.debug(f"Saved {len(profiles_dict)} profiles to disk cache")
        except Exception as e:
            logger.error(f"Failed to save profiles to disk cache: {str(e)}")
    
    def _load_from_disk_cache(self) -> Dict[str, Dict[str, Any]]:
        """Load profiles from disk cache."""
        try:
            if os.path.exists(self.cache_file_path):
                with open(self.cache_file_path, 'r') as f:
                    self.profiles = json.load(f)
                logger.info(f"Loaded {len(self.profiles)} profiles from disk cache")
                return self.profiles
            else:
                logger.warning("Disk cache file does not exist")
                return {}
        except Exception as e:
            logger.error(f"Failed to load profiles from disk cache: {str(e)}")
            return {}

    def clear(self) -> None:
        """Clear the profile cache."""
        self.profiles = {}
        self.last_loaded = None
        try:
            if os.path.exists(self.cache_file_path):
                os.remove(self.cache_file_path)
            logger.info("Profile cache cleared")
        except Exception as e:
            logger.error(f"Error clearing cache file: {str(e)}")


# Create a global instance for easy import
profile_cache = ProfileCache()

def get_personality_profile(username: str) -> Dict[str, Any]:
    """
    Convenience function to get a user's personality profile from the cache.
    
    Parameters:
    - username: Username to look up
    
    Returns:
    - User profile dictionary or empty dict if not found
    """
    return profile_cache.get_profile(username)

def load_all_profiles(file_path: str) -> Dict[str, Dict[str, Any]]:
    """
    Load all profiles from a file and update the cache.
    
    Parameters:
    - file_path: Path to the profiles file
    
    Returns:
    - Dictionary of all profiles
    """
    return profile_cache.load_profiles_from_file(file_path)