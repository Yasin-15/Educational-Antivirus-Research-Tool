"""
Sample management module for the Educational Antivirus Research Tool.

This module provides functionality for creating, managing, and organizing
harmless test malware samples for educational purposes.
"""

from .sample_manager import SampleManager, SampleManagerError
from .sample_generator import SampleGenerator, SampleGeneratorError

__all__ = [
    'SampleManager',
    'SampleManagerError', 
    'SampleGenerator',
    'SampleGeneratorError'
]