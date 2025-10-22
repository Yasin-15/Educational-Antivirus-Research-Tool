"""
Logging configuration for the Educational Antivirus Research Tool.
"""
import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional
from .models import Config


class LoggingManager:
    """Manages logging configuration and setup."""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize logging manager.
        
        Args:
            config: Configuration object with logging settings
        """
        self.config = config or Config()
        self._logger: Optional[logging.Logger] = None
    
    def setup_logging(self, config: Optional[Config] = None) -> logging.Logger:
        """Set up logging configuration.
        
        Args:
            config: Optional configuration to use
            
        Returns:
            Configured logger
        """
        if config:
            self.config = config
        
        # Create logger
        logger = logging.getLogger('antivirus')
        logger.setLevel(getattr(logging, self.config.log_level))
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, self.config.log_level))
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler
        if self.config.log_file:
            # Ensure log directory exists
            log_path = Path(self.config.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create rotating file handler (10MB max, 5 backups)
            file_handler = logging.handlers.RotatingFileHandler(
                self.config.log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setLevel(getattr(logging, self.config.log_level))
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        self._logger = logger
        return logger
    
    def get_logger(self) -> logging.Logger:
        """Get configured logger.
        
        Returns:
            Configured logger
        """
        if self._logger is None:
            return self.setup_logging()
        return self._logger
    
    def update_config(self, config: Config) -> None:
        """Update logging configuration.
        
        Args:
            config: New configuration
        """
        self.config = config
        self.setup_logging(config)


def setup_default_logging(log_level: str = "INFO", log_file: str = "antivirus.log") -> logging.Logger:
    """Set up default logging configuration.
    
    Args:
        log_level: Logging level
        log_file: Log file path
        
    Returns:
        Configured logger
    """
    config = Config()
    config.log_level = log_level
    config.log_file = log_file
    
    manager = LoggingManager(config)
    return manager.setup_logging()