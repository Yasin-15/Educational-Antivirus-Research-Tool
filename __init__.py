"""
Educational Antivirus Research Tool

A Python-based educational tool for learning about antivirus detection mechanisms
through hands-on experience with signature-based detection, behavioral analysis,
quarantine management, and threat reporting using completely harmless test files.
"""

__version__ = "1.0.0"
__author__ = "Educational Antivirus Project"
__description__ = "Educational tool for learning antivirus detection mechanisms"

from .core.models import (
    Detection, ScanResult, ScanOptions, FileInfo, 
    SampleInfo, QuarantineEntry, BehavioralResult, AnalysisDetails
)
from .core.config import Config
from .core.exceptions import (
    AntivirusError, ScanError, QuarantineError, SignatureError,
    BehavioralAnalysisError, ConfigurationError, SampleManagementError,
    ReportGenerationError, FileAccessError, DatabaseError
)
from .core.logging_config import LoggingManager

__all__ = [
    'Detection', 'ScanResult', 'ScanOptions', 'FileInfo',
    'SampleInfo', 'QuarantineEntry', 'BehavioralResult', 'AnalysisDetails',
    'Config', 'LoggingManager',
    'AntivirusError', 'ScanError', 'QuarantineError', 'SignatureError',
    'BehavioralAnalysisError', 'ConfigurationError', 'SampleManagementError',
    'ReportGenerationError', 'FileAccessError', 'DatabaseError'
]