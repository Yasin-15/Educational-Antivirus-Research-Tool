"""
Core module for the Educational Antivirus Research Tool.
Contains the main engine and base interfaces.
"""

from .models import (
    Detection, ScanResult, FileInfo, SampleInfo, ScanOptions,
    QuarantineEntry, BehavioralResult, AnalysisDetails, Config,
    DetectionType, ScanStatus
)
from .file_utils import (
    calculate_md5, calculate_sha256, calculate_entropy,
    detect_file_type, get_file_permissions, extract_file_metadata,
    is_suspicious_file_type, get_file_size_category, analyze_file_characteristics
)
from .exceptions import (
    AntivirusError, ScanError, QuarantineError, 
    SignatureError, ConfigurationError
)

__all__ = [
    # Models
    'Detection', 'ScanResult', 'FileInfo', 'SampleInfo', 'ScanOptions',
    'QuarantineEntry', 'BehavioralResult', 'AnalysisDetails', 'Config',
    'DetectionType', 'ScanStatus',
    
    # File utilities
    'calculate_md5', 'calculate_sha256', 'calculate_entropy',
    'detect_file_type', 'get_file_permissions', 'extract_file_metadata',
    'is_suspicious_file_type', 'get_file_size_category', 'analyze_file_characteristics',
    
    # Exceptions
    'AntivirusError', 'ScanError', 'QuarantineError', 
    'SignatureError', 'ConfigurationError'
]