"""
Configuration management for the Educational Antivirus Research Tool.
"""
import json
import yaml
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import asdict

from .models import Config
from .exceptions import ConfigurationError


class ConfigManager:
    """Manages configuration loading, saving, and validation with comprehensive default handling."""
    
    DEFAULT_CONFIG_PATHS = [
        "config.json",
        "config.yaml", 
        "config.yml",
        "antivirus_config.json",
        "antivirus_config.yaml"
    ]
    
    def __init__(self, config_path: Optional[str] = None, auto_save: bool = True):
        """Initialize configuration manager.
        
        Args:
            config_path: Optional path to configuration file. If None, will search for default files.
            auto_save: Whether to automatically save configuration changes
        """
        self.config_path = config_path
        self.auto_save = auto_save
        self._config: Optional[Config] = None
        self._default_config = Config()  # Keep reference to defaults
    
    def load_config(self, config_path: Optional[str] = None, use_defaults_on_error: bool = True) -> Config:
        """Load configuration from file or create default configuration.
        
        Args:
            config_path: Optional path to configuration file
            use_defaults_on_error: If True, use default values for invalid settings instead of raising error
            
        Returns:
            Config: Loaded or default configuration
            
        Raises:
            ConfigurationError: If configuration file exists but is invalid and use_defaults_on_error is False
        """
        if config_path:
            self.config_path = config_path
        
        config_data = None
        
        # Try to load from specified path or search for default files
        if self.config_path and os.path.exists(self.config_path):
            try:
                config_data = self._load_config_file(self.config_path)
            except ConfigurationError as e:
                if use_defaults_on_error:
                    print(f"Warning: Failed to load config file {self.config_path}: {e.message}")
                    print("Using default configuration values.")
                    config_data = None
                else:
                    raise
        else:
            # Search for default configuration files
            for default_path in self.DEFAULT_CONFIG_PATHS:
                if os.path.exists(default_path):
                    try:
                        config_data = self._load_config_file(default_path)
                        self.config_path = default_path
                        break
                    except ConfigurationError as e:
                        if use_defaults_on_error:
                            print(f"Warning: Failed to load config file {default_path}: {e.message}")
                            continue
                        else:
                            raise
        
        # Create config from data or use defaults
        if config_data:
            self._config = self._create_config_from_dict(config_data, use_defaults_on_error)
        else:
            self._config = Config()  # Use default values
            # If no config file found, create one with defaults
            if self.auto_save and not self.config_path:
                self.config_path = "config.json"
                self.save_config()
        
        # Validate configuration
        validation_errors = self._config.validate()
        if validation_errors:
            if use_defaults_on_error:
                print("Warning: Configuration validation failed:")
                for error in validation_errors:
                    print(f"- {error}")
                print("Using default values for invalid settings.")
                self._config = self._apply_defaults_for_invalid_values(self._config, validation_errors)
            else:
                error_msg = "Configuration validation failed:\n" + "\n".join(f"- {error}" for error in validation_errors)
                raise ConfigurationError(error_msg)
        
        return self._config
    
    def save_config(self, config: Optional[Config] = None, config_path: Optional[str] = None) -> bool:
        """Save configuration to file.
        
        Args:
            config: Configuration to save. If None, uses current config.
            config_path: Path to save configuration. If None, uses current path or default.
            
        Returns:
            bool: True if saved successfully
            
        Raises:
            ConfigurationError: If no configuration to save or save fails
        """
        if config:
            self._config = config
        
        if not self._config:
            raise ConfigurationError("No configuration to save")
        
        # Validate before saving
        validation_errors = self._config.validate()
        if validation_errors:
            error_msg = "Cannot save invalid configuration:\n" + "\n".join(f"- {error}" for error in validation_errors)
            raise ConfigurationError(error_msg)
        
        # Determine save path
        save_path = config_path or self.config_path or "config.json"
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(save_path) if os.path.dirname(save_path) else ".", exist_ok=True)
            
            # Convert config to dictionary
            config_dict = asdict(self._config)
            
            # Save based on file extension
            if save_path.endswith(('.yaml', '.yml')):
                with open(save_path, 'w', encoding='utf-8') as f:
                    yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            else:
                with open(save_path, 'w', encoding='utf-8') as f:
                    json.dump(config_dict, f, indent=2, ensure_ascii=False)
            
            self.config_path = save_path
            return True
            
        except Exception as e:
            raise ConfigurationError(f"Failed to save configuration to {save_path}: {str(e)}")
    
    def get_config(self) -> Config:
        """Get current configuration.
        
        Returns:
            Config: Current configuration
            
        Raises:
            ConfigurationError: If no configuration loaded
        """
        if not self._config:
            raise ConfigurationError("No configuration loaded. Call load_config() first.")
        return self._config
    
    def update_config(self, save_immediately: bool = None, **kwargs) -> Config:
        """Update configuration with new values.
        
        Args:
            save_immediately: Whether to save config immediately. If None, uses auto_save setting.
            **kwargs: Configuration values to update
            
        Returns:
            Config: Updated configuration
            
        Raises:
            ConfigurationError: If configuration is invalid after update
        """
        if not self._config:
            self._config = Config()
        
        # Store original values for rollback if needed
        original_values = {}
        
        # Update configuration values
        for key, value in kwargs.items():
            if hasattr(self._config, key):
                original_values[key] = getattr(self._config, key)
                setattr(self._config, key, value)
            else:
                raise ConfigurationError(f"Unknown configuration option: {key}")
        
        # Validate updated configuration
        validation_errors = self._config.validate()
        if validation_errors:
            # Rollback changes
            for key, original_value in original_values.items():
                setattr(self._config, key, original_value)
            
            error_msg = "Configuration update failed validation:\n" + "\n".join(f"- {error}" for error in validation_errors)
            raise ConfigurationError(error_msg)
        
        # Save if requested or auto_save is enabled
        should_save = save_immediately if save_immediately is not None else self.auto_save
        if should_save and self.config_path:
            try:
                self.save_config()
            except ConfigurationError as e:
                print(f"Warning: Failed to auto-save configuration: {e.message}")
        
        return self._config
    
    def reset_to_defaults(self) -> Config:
        """Reset configuration to default values.
        
        Returns:
            Config: Default configuration
        """
        self._config = Config()
        return self._config
    
    def _load_config_file(self, file_path: str) -> Dict[str, Any]:
        """Load configuration data from file.
        
        Args:
            file_path: Path to configuration file
            
        Returns:
            Dict[str, Any]: Configuration data
            
        Raises:
            ConfigurationError: If file cannot be loaded or parsed
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.endswith(('.yaml', '.yml')):
                    return yaml.safe_load(f) or {}
                else:
                    return json.load(f)
        except FileNotFoundError:
            raise ConfigurationError(f"Configuration file not found: {file_path}")
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in configuration file {file_path}: {str(e)}")
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in configuration file {file_path}: {str(e)}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration file {file_path}: {str(e)}")
    
    def _create_config_from_dict(self, config_data: Dict[str, Any], use_defaults_on_error: bool = True) -> Config:
        """Create Config object from dictionary data.
        
        Args:
            config_data: Dictionary containing configuration values
            use_defaults_on_error: If True, use default values for invalid settings
            
        Returns:
            Config: Configuration object
        """
        # Start with default config
        config = Config()
        
        # Update with loaded values
        for key, value in config_data.items():
            if hasattr(config, key):
                try:
                    # Validate the type matches the default
                    default_value = getattr(self._default_config, key)
                    if type(value) != type(default_value) and not (isinstance(value, (int, float)) and isinstance(default_value, (int, float))):
                        if use_defaults_on_error:
                            print(f"Warning: Invalid type for {key}, expected {type(default_value).__name__}, got {type(value).__name__}. Using default value.")
                            continue
                        else:
                            raise ConfigurationError(f"Invalid type for {key}, expected {type(default_value).__name__}, got {type(value).__name__}")
                    
                    setattr(config, key, value)
                except Exception as e:
                    if use_defaults_on_error:
                        print(f"Warning: Error setting {key}: {str(e)}. Using default value.")
                    else:
                        raise ConfigurationError(f"Error setting {key}: {str(e)}")
            else:
                if use_defaults_on_error:
                    print(f"Warning: Unknown configuration option '{key}' ignored.")
                else:
                    raise ConfigurationError(f"Unknown configuration option: {key}")
        
        return config
    
    def _apply_defaults_for_invalid_values(self, config: Config, validation_errors: List[str]) -> Config:
        """Apply default values for configuration settings that failed validation.
        
        Args:
            config: Configuration object with invalid values
            validation_errors: List of validation error messages
            
        Returns:
            Config: Configuration with defaults applied for invalid values
        """
        # Create a new config with defaults
        fixed_config = Config()
        
        # Copy valid values from the original config
        for field_name in config.__dataclass_fields__:
            original_value = getattr(config, field_name)
            default_value = getattr(self._default_config, field_name)
            
            # Check if this field has validation errors
            field_has_error = any(field_name in error for error in validation_errors)
            
            if field_has_error:
                setattr(fixed_config, field_name, default_value)
                print(f"  Using default value for {field_name}: {default_value}")
            else:
                setattr(fixed_config, field_name, original_value)
        
        return fixed_config
    
    def get_default_config(self) -> Config:
        """Get a copy of the default configuration.
        
        Returns:
            Config: Default configuration values
        """
        return Config()
    
    def reset_setting_to_default(self, setting_name: str) -> Config:
        """Reset a specific setting to its default value.
        
        Args:
            setting_name: Name of the setting to reset
            
        Returns:
            Config: Updated configuration
            
        Raises:
            ConfigurationError: If setting name is invalid
        """
        if not self._config:
            self._config = Config()
        
        if not hasattr(self._config, setting_name):
            raise ConfigurationError(f"Unknown configuration setting: {setting_name}")
        
        default_value = getattr(self._default_config, setting_name)
        setattr(self._config, setting_name, default_value)
        
        # Save if auto_save is enabled
        if self.auto_save and self.config_path:
            try:
                self.save_config()
            except ConfigurationError as e:
                print(f"Warning: Failed to auto-save configuration: {e.message}")
        
        return self._config
    
    def get_setting_info(self, setting_name: str) -> Dict[str, Any]:
        """Get information about a configuration setting.
        
        Args:
            setting_name: Name of the setting
            
        Returns:
            Dict containing current value, default value, and type information
            
        Raises:
            ConfigurationError: If setting name is invalid
        """
        if not hasattr(Config, setting_name):
            raise ConfigurationError(f"Unknown configuration setting: {setting_name}")
        
        current_config = self._config or Config()
        current_value = getattr(current_config, setting_name)
        default_value = getattr(self._default_config, setting_name)
        
        return {
            'name': setting_name,
            'current_value': current_value,
            'default_value': default_value,
            'type': type(default_value).__name__,
            'is_default': current_value == default_value
        }
    
    def list_all_settings(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all configuration settings.
        
        Returns:
            Dict mapping setting names to their information
        """
        current_config = self._config or Config()
        settings_info = {}
        
        for field_name in current_config.__dataclass_fields__:
            settings_info[field_name] = self.get_setting_info(field_name)
        
        return settings_info
    
    def export_config_template(self, file_path: str, include_comments: bool = True) -> bool:
        """Export a configuration template file with default values.
        
        Args:
            file_path: Path to save the template file
            include_comments: Whether to include explanatory comments
            
        Returns:
            bool: True if template was saved successfully
            
        Raises:
            ConfigurationError: If template cannot be saved
        """
        try:
            default_config = Config()
            config_dict = asdict(default_config)
            
            if file_path.endswith(('.yaml', '.yml')) and include_comments:
                # Create YAML with comments
                yaml_content = "# Educational Antivirus Research Tool Configuration\n"
                yaml_content += "# This file contains default configuration settings\n\n"
                yaml_content += "# Detection Settings\n"
                yaml_content += f"signature_sensitivity: {config_dict['signature_sensitivity']}  # Sensitivity level (1-10)\n"
                yaml_content += f"behavioral_threshold: {config_dict['behavioral_threshold']}   # Risk score threshold (1-10)\n"
                yaml_content += f"max_file_size_mb: {config_dict['max_file_size_mb']}      # Maximum file size to scan in MB\n\n"
                
                yaml_content += "# File Paths\n"
                yaml_content += f"signature_db_path: \"{config_dict['signature_db_path']}\"\n"
                yaml_content += f"quarantine_path: \"{config_dict['quarantine_path']}\"\n"
                yaml_content += f"samples_path: \"{config_dict['samples_path']}\"\n"
                yaml_content += f"reports_path: \"{config_dict['reports_path']}\"\n\n"
                
                yaml_content += "# Behavioral Analysis\n"
                yaml_content += f"entropy_threshold: {config_dict['entropy_threshold']}    # Entropy threshold for suspicious files\n"
                yaml_content += "suspicious_extensions:\n"
                for ext in config_dict['suspicious_extensions']:
                    yaml_content += f"  - \"{ext}\"\n"
                yaml_content += "\n"
                
                yaml_content += "# Logging\n"
                yaml_content += f"log_level: \"{config_dict['log_level']}\"     # DEBUG, INFO, WARNING, ERROR, CRITICAL\n"
                yaml_content += f"log_file: \"{config_dict['log_file']}\"\n\n"
                
                yaml_content += "# Scanning Options\n"
                yaml_content += f"recursive_scan: {str(config_dict['recursive_scan']).lower()}\n"
                yaml_content += f"follow_symlinks: {str(config_dict['follow_symlinks']).lower()}\n"
                yaml_content += "skip_extensions:\n"
                for ext in config_dict['skip_extensions']:
                    yaml_content += f"  - \"{ext}\"\n"
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(yaml_content)
            else:
                # Save as JSON or YAML without comments
                if file_path.endswith(('.yaml', '.yml')):
                    with open(file_path, 'w', encoding='utf-8') as f:
                        yaml.dump(config_dict, f, default_flow_style=False, indent=2)
                else:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(config_dict, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            raise ConfigurationError(f"Failed to export configuration template to {file_path}: {str(e)}")