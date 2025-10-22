"""
Exception hierarchy for the Educational Antivirus Research Tool.
"""


class AntivirusError(Exception):
    """Base exception for antivirus operations."""
    
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class ScanError(AntivirusError):
    """Raised when file scanning fails."""
    pass


class QuarantineError(AntivirusError):
    """Raised when quarantine operations fail."""
    pass


class SignatureError(AntivirusError):
    """Raised when signature operations fail."""
    pass


class BehavioralAnalysisError(AntivirusError):
    """Raised when behavioral analysis fails."""
    pass


class ConfigurationError(AntivirusError):
    """Raised when configuration is invalid."""
    pass


class SampleManagementError(AntivirusError):
    """Raised when sample management operations fail."""
    pass


class ReportGenerationError(AntivirusError):
    """Raised when report generation fails."""
    pass


class FileAccessError(AntivirusError):
    """Raised when file access operations fail."""
    pass


class DatabaseError(AntivirusError):
    """Raised when database operations fail."""
    pass