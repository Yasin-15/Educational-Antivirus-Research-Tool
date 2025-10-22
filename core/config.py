"""
Configuration management for the Educational Antivirus Research Tool.
"""
import json
import yaml
import os
from pathlib import Path
from typing import Dict, Any, Optional
from .models import Config
from .exceptions import ConfigurationError


class ConfigManager:
    """Manages configuration loading, saving, and validation."""
    
    DEFAULT_CONFIG_PATHS = [
        "config.json",
        "config.yaml",
        "config.yml"
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager.
        
        Args:
            config_path: Optional path to configuration file
        """
        self.config_path = config_path
        self._config: Optional[Config] = None
    
    def load_config(self, config_path: Optional[str] = None) -> Config:
        """Load configuration from file or create default.
        
        Args:
            config_path: Optional path to configuration file
            
        Returns:
            Config object
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        if config_path:
            self.config_path = config_path
        
        # Try to load from specified path or default paths
        config_data = None
        if self.config_path:
            config_data = self._load_config_file(self.config_path)
        else:
            # Try default paths
            for default_path in self.DEFAULT_CONFIG_PATHS:
                if os.path.exists(default_path):
                    config_data = self._load_config_file(default_path)
                    self.config_path = default_path
                    break
        
        if config_data:
            try:
                self._config = Config.from_dict(config_data)
                self._validate_config(self._config)
            except Exception as e:
                raise ConfigurationError(f"Invalid configuration: {e}")
        else:
            # Create default configuration
            self._config = Config()
        
        return self._config
    
    def save_config(self, config: Config, config_path: Optional[str] = None) -> None:
        """Save configuration to file.
        
        Args:
            config: Configuration to save
            config_path: Optional path to save configuration
            
        Raises:
            ConfigurationError: If saving fails
        """
        if config_path:
            self.config_path = config_path
        
        if not self.config_path:
            self.config_path = "config.json"
        
        try:
            self._validate_config(config)
            config_data = config.to_dict()
            
            if self.config_path.endswith(('.yaml', '.yml')):
                self._save_yaml_config(config_data, self.config_path)
            else:
                self._save_json_config(config_data, self.config_path)
                
            self._config = config
        except Exception as e:
            raise ConfigurationError(f"Failed to save configuration: {e}")
    
    def get_config(self) -> Config:
        """Get current configuration.
        
        Returns:
            Current configuration or default if none loaded
        """
        if self._config is None:
            return self.load_config()
        return self._config
    
    def update_config(self, **kwargs) -> Config:
        """Update configuration with new values.
        
        Args:
            **kwargs: Configuration values to update
            
        Returns:
            Updated configuration
            
        Raises:
            ConfigurationError: If update fails
        """
        if self._config is None:
            self._config = self.load_config()
        
        # Update configuration
        config_dict = self._config.to_dict()
        config_dict.update(kwargs)
        
        try:
            updated_config = Config.from_dict(config_dict)
            self._validate_config(updated_config)
            self._config = updated_config
            return self._config
        except Exception as e:
            raise ConfigurationError(f"Failed to update configuration: {e}")
    
    def create_default_config(self, config_path: str = "config.json") -> Config:
        """Create and save default configuration file.
        
        Args:
            config_path: Path to save default configuration
            
        Returns:
            Default configuration
        """
        default_config = Config()
        self.save_config(default_config, config_path)
        return default_config
    
    def _load_config_file(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from file.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Configuration data as dictionary
            
        Raises:
            ConfigurationError: If loading fails
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                if config_path.endswith(('.yaml', '.yml')):
                    return yaml.safe_load(f)
                else:
                    return json.load(f)
        except FileNotFoundError:
            raise ConfigurationError(f"Configuration file not found: {config_path}")
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            raise ConfigurationError(f"Invalid configuration format: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {e}")
    
    def _save_json_config(self, config_data: Dict[str, Any], config_path: str) -> None:
        """Save configuration as JSON.
        
        Args:
            config_data: Configuration data
            config_path: Path to save configuration
        """
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
    
    def _save_yaml_config(self, config_data: Dict[str, Any], config_path: str) -> None:
        """Save configuration as YAML.
        
        Args:
            config_data: Configuration data
            config_path: Path to save configuration
        """
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config_data, f, default_flow_style=False, indent=2)
    
    def _validate_config(self, config: Config) -> None:
        """Validate configuration values.
        
        Args:
            config: Configuration to validate
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Validate sensitivity levels
        if not 1 <= config.signature_sensitivity <= 10:
            raise ConfigurationError("signature_sensitivity must be between 1 and 10")
        
        if not 1 <= config.behavioral_threshold <= 10:
            raise ConfigurationError("behavioral_threshold must be between 1 and 10")
        
        # Validate file size
        if config.max_file_size_mb <= 0:
            raise ConfigurationError("max_file_size_mb must be positive")
        
        # Validate entropy threshold
        if not 0 <= config.entropy_threshold <= 8:
            raise ConfigurationError("entropy_threshold must be between 0 and 8")
        
        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if config.log_level not in valid_log_levels:
            raise ConfigurationError(f"log_level must be one of: {valid_log_levels}")
        
        # Validate paths exist or can be created
        for path_attr in ['quarantine_path', 'samples_path', 'reports_path']:
            path = getattr(config, path_attr)
            try:
                Path(path).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                raise ConfigurationError(f"Cannot create directory {path}: {e}")


def load_default_config() -> Config:
    """Load default configuration.
    
    Returns:
        Default configuration
    """
    manager = ConfigManager()
    return manager.load_config()


def create_initial_config(config_path: str = "config.json") -> Config:
    """Create initial configuration file with defaults.
    
    Args:
        config_path: Path to save configuration
        
    Returns:
        Created configuration
    """
    manager = ConfigManager()
    return manager.create_default_config(config_path)