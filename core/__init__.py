"""
Core module for the Educational Antivirus Research Tool.
Contains the main engine and base interfaces.
"""

from .models import (
    Detection, ScanResult, FileInfo, SampleInfo, ScanOptions,
    QuarantineEntry, BehavioralResult, AnalysisDetails, Config,
    DetectionType, ScanStatus
)
from .config import ConfigManager, load_default_config, create_initial_config
from .logging_config import LoggingManager, setup_default_logging
from .initialization import InitializationManager, initialize_system, check_initialization
from .sample_database import SampleDatabaseManager, initialize_sample_database
from .exceptions import (
    AntivirusError, ScanError, QuarantineError, 
    SignatureError, ConfigurationError
)

# Try to import file_utils if it exists
try:
    from .file_utils import (
        calculate_md5, calculate_sha256, calculate_entropy,
        detect_file_type, get_file_permissions, extract_file_metadata,
        is_suspicious_file_type, get_file_size_category, analyze_file_characteristics
    )
    _file_utils_available = True
except ImportError:
    _file_utils_available = False

__all__ = [
    # Models
    'Detection', 'ScanResult', 'FileInfo', 'SampleInfo', 'ScanOptions',
    'QuarantineEntry', 'BehavioralResult', 'AnalysisDetails', 'Config',
    'DetectionType', 'ScanStatus',
    
    # Configuration
    'ConfigManager', 'load_default_config', 'create_initial_config',
    
    # Logging
    'LoggingManager', 'setup_default_logging',
    
    # Initialization
    'InitializationManager', 'initialize_system', 'check_initialization',
    
    # Sample Database
    'SampleDatabaseManager', 'initialize_sample_database',
    
    # Exceptions
    'AntivirusError', 'ScanError', 'QuarantineError', 
    'SignatureError', 'ConfigurationError'
]

# Add file utilities if available
if _file_utils_available:
    __all__.extend([
        'calculate_md5', 'calculate_sha256', 'calculate_entropy',
        'detect_file_type', 'get_file_permissions', 'extract_file_metadata',
        'is_suspicious_file_type', 'get_file_size_category', 'analyze_file_characteristics'
    ])