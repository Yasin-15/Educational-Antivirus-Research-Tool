"""
Reporting and educational content module for the Educational Antivirus Research Tool.

This module provides comprehensive reporting capabilities with educational content
to help users understand threats and learn about cybersecurity concepts.
"""

from .report_generator import (
    ReportGenerator,
    ReportStatistics,
    ReportTemplate,
    JSONReportTemplate,
    CSVReportTemplate,
    TextReportTemplate
)

from .educational_content import (
    EducationalDatabase,
    EducationalContentDisplay,
    ThreatInfo,
    DetectionExplanation,
    ThreatCategory,
    DetectionMethod
)

from .educational_report_system import EducationalReportSystem

__all__ = [
    # Report generation
    'ReportGenerator',
    'ReportStatistics',
    'ReportTemplate',
    'JSONReportTemplate',
    'CSVReportTemplate',
    'TextReportTemplate',
    
    # Educational content
    'EducationalDatabase',
    'EducationalContentDisplay',
    'ThreatInfo',
    'DetectionExplanation',
    'ThreatCategory',
    'DetectionMethod',
    
    # Integrated system
    'EducationalReportSystem'
]