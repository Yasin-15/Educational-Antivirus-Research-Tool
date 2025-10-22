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
    """Manages logging configuration for the antivirus tool."""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self._logger = None
    
    def setup_logging(self) -> logging.Logger:
        """Set up logging configuration based on config settings."""
        if self._logger:
            return self._logger
        
        # Create logger
        logger = logging.getLogger('educational_antivirus')
        logger.setLevel(getattr(logging, self.config.log_level.upper(), logging.INFO))
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # Create formatter
        formatter = logging.Formatter(self.config.log_format)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler
        if self.config.log_file:
            log_dir = Path(self.config.log_file).parent
            log_dir.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                self.config.log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            file_handler.setLevel(getattr(logging, self.config.log_level.upper(), logging.INFO))
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        self._logger = logger
        return logger
    
    def get_logger(self, name: str = None) -> logging.Logger:
        """Get a logger instance."""
        if not self._logger:
            self.setup_logging()
        
        if name:
            return logging.getLogger(f'educational_antivirus.{name}')
        return self._logger
    
    def log_scan_start(self, scan_id: str, paths: list):
        """Log the start of a scan operation."""
        logger = self.get_logger('scanner')
        logger.info(f"Starting scan {scan_id} for paths: {paths}")
    
    def log_detection(self, detection):
        """Log a threat detection."""
        logger = self.get_logger('detection')
        logger.warning(f"Threat detected: {detection.threat_name} in {detection.file_path}")
    
    def log_quarantine(self, file_path: str, quarantine_path: str):
        """Log a quarantine operation."""
        logger = self.get_logger('quarantine')
        logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
    
    def log_error(self, operation: str, error: Exception):
        """Log an error during operations."""
        logger = self.get_logger('error')
        logger.error(f"Error in {operation}: {str(error)}", exc_info=True)


# Global logging manager instance
_logging_manager = None


def get_logger(name: str = None) -> logging.Logger:
    """Get a logger instance (global function for backward compatibility)."""
    global _logging_manager
    if not _logging_manager:
        _logging_manager = LoggingManager()
    return _logging_manager.get_logger(name)