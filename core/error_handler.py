"""
Comprehensive error handling and user guidance system for the Educational Antivirus Tool.

This module provides centralized error handling, user-friendly error messages,
and guidance for common issues and scenarios.
"""
import os
import sys
import traceback
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

from .exceptions import AntivirusError, DatabaseError, SampleManagementError
from .logging_config import setup_default_logging

logger = setup_default_logging()

# Import user guidance system if available
try:
    from .user_guidance import create_user_guidance_system
    USER_GUIDANCE_AVAILABLE = True
except ImportError:
    USER_GUIDANCE_AVAILABLE = False


class ErrorCategory:
    """Error category constants."""
    INITIALIZATION = "initialization"
    CONFIGURATION = "configuration"
    DATABASE = "database"
    SAMPLE_MANAGEMENT = "sample_management"
    SCANNING = "scanning"
    QUARANTINE = "quarantine"
    REPORTING = "reporting"
    SYSTEM = "system"
    USER_INPUT = "user_input"


class ErrorSeverity:
    """Error severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class UserGuidanceManager:
    """Manages user guidance and error resolution suggestions."""
    
    def __init__(self):
        """Initialize the user guidance manager."""
        self.error_solutions = self._initialize_error_solutions()
        self.common_scenarios = self._initialize_common_scenarios()
        
    def get_error_guidance(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Get comprehensive guidance for an error.
        
        Args:
            error: The exception that occurred
            context: Optional context information
            
        Returns:
            Dictionary with error guidance information
        """
        error_type = type(error).__name__
        error_message = str(error)
        
        guidance = {
            'error_type': error_type,
            'error_message': error_message,
            'category': self._categorize_error(error),
            'severity': self._assess_severity(error),
            'user_friendly_message': self._get_user_friendly_message(error),
            'possible_causes': self._get_possible_causes(error),
            'solutions': self._get_solutions(error),
            'prevention_tips': self._get_prevention_tips(error),
            'related_help': self._get_related_help(error),
            'context': context or {}
        }
        
        return guidance
    
    def format_error_message(self, guidance: Dict[str, Any], verbose: bool = False) -> str:
        """Format error guidance into a user-friendly message.
        
        Args:
            guidance: Error guidance dictionary
            verbose: Whether to include detailed information
            
        Returns:
            Formatted error message
        """
        lines = []
        
        # Error header
        severity_icon = self._get_severity_icon(guidance['severity'])
        lines.append(f"{severity_icon} {guidance['user_friendly_message']}")
        lines.append("")
        
        # Possible causes
        if guidance['possible_causes']:
            lines.append("Possible causes:")
            for cause in guidance['possible_causes']:
                lines.append(f"  • {cause}")
            lines.append("")
        
        # Solutions
        if guidance['solutions']:
            lines.append("Recommended solutions:")
            for i, solution in enumerate(guidance['solutions'], 1):
                lines.append(f"  {i}. {solution}")
            lines.append("")
        
        # Prevention tips
        if guidance['prevention_tips'] and verbose:
            lines.append("Prevention tips:")
            for tip in guidance['prevention_tips']:
                lines.append(f"  • {tip}")
            lines.append("")
        
        # Related help
        if guidance['related_help']:
            lines.append("For more help:")
            for help_item in guidance['related_help']:
                lines.append(f"  • {help_item}")
            lines.append("")
        
        # Technical details (verbose mode)
        if verbose:
            lines.append("Technical details:")
            lines.append(f"  Error type: {guidance['error_type']}")
            lines.append(f"  Category: {guidance['category']}")
            lines.append(f"  Severity: {guidance['severity']}")
            if guidance['context']:
                lines.append(f"  Context: {guidance['context']}")
        
        return "\n".join(lines)
    
    def get_common_scenario_guidance(self, scenario: str) -> Optional[Dict[str, Any]]:
        """Get guidance for common user scenarios.
        
        Args:
            scenario: Scenario identifier
            
        Returns:
            Guidance dictionary or None if scenario not found
        """
        return self.common_scenarios.get(scenario)
    
    def _categorize_error(self, error: Exception) -> str:
        """Categorize an error based on its type and context."""
        error_type = type(error).__name__
        error_message = str(error).lower()
        
        # Database-related errors
        if isinstance(error, DatabaseError) or 'database' in error_message:
            return ErrorCategory.DATABASE
        
        # Sample management errors
        if isinstance(error, SampleManagementError) or 'sample' in error_message:
            return ErrorCategory.SAMPLE_MANAGEMENT
        
        # Configuration errors
        if 'config' in error_message or 'configuration' in error_message:
            return ErrorCategory.CONFIGURATION
        
        # File system errors
        if any(keyword in error_message for keyword in ['file', 'directory', 'path', 'permission']):
            return ErrorCategory.SYSTEM
        
        # Import/module errors
        if 'import' in error_message or 'module' in error_message:
            return ErrorCategory.INITIALIZATION
        
        # Default to system category
        return ErrorCategory.SYSTEM
    
    def _assess_severity(self, error: Exception) -> str:
        """Assess the severity of an error."""
        error_type = type(error).__name__
        error_message = str(error).lower()
        
        # Critical errors that prevent tool from functioning
        critical_indicators = ['database', 'initialization', 'config', 'import']
        if any(indicator in error_message for indicator in critical_indicators):
            return ErrorSeverity.CRITICAL
        
        # Errors that affect functionality but tool can continue
        error_indicators = ['scan', 'quarantine', 'sample']
        if any(indicator in error_message for indicator in error_indicators):
            return ErrorSeverity.ERROR
        
        # Warnings for non-critical issues
        warning_indicators = ['permission', 'access', 'timeout']
        if any(indicator in error_message for indicator in warning_indicators):
            return ErrorSeverity.WARNING
        
        # Default to error level
        return ErrorSeverity.ERROR
    
    def _get_user_friendly_message(self, error: Exception) -> str:
        """Get a user-friendly error message."""
        error_type = type(error).__name__
        error_message = str(error).lower()
        
        # Database errors
        if 'database' in error_message:
            return "There's an issue with the sample or threat database"
        
        # Configuration errors
        if 'config' in error_message:
            return "There's a problem with the configuration settings"
        
        # File system errors
        if 'permission' in error_message:
            return "The tool doesn't have permission to access a required file or directory"
        
        if 'file not found' in error_message or 'no such file' in error_message:
            return "A required file or directory could not be found"
        
        # Import errors
        if 'import' in error_message or 'module' in error_message:
            return "A required Python module is missing or cannot be loaded"
        
        # Sample management errors
        if 'sample' in error_message:
            return "There's an issue with sample management operations"
        
        # Generic error message
        return f"An unexpected error occurred: {str(error)}"
    
    def _get_possible_causes(self, error: Exception) -> List[str]:
        """Get possible causes for an error."""
        error_message = str(error).lower()
        causes = []
        
        if 'database' in error_message:
            causes.extend([
                "Database files are missing or corrupted",
                "Insufficient disk space for database operations",
                "Database files are locked by another process",
                "Incorrect database file permissions"
            ])
        
        if 'config' in error_message:
            causes.extend([
                "Configuration file has invalid syntax",
                "Required configuration values are missing",
                "Configuration file permissions are incorrect",
                "Configuration file path is invalid"
            ])
        
        if 'permission' in error_message:
            causes.extend([
                "Insufficient user permissions",
                "Files or directories are read-only",
                "Antivirus software is blocking access",
                "Files are in use by another application"
            ])
        
        if 'import' in error_message or 'module' in error_message:
            causes.extend([
                "Required Python packages are not installed",
                "Python environment is not properly configured",
                "Package versions are incompatible",
                "Python path is not set correctly"
            ])
        
        if 'sample' in error_message:
            causes.extend([
                "Sample files are missing or corrupted",
                "Sample metadata is inconsistent",
                "Insufficient permissions to create samples",
                "Sample directory structure is invalid"
            ])
        
        return causes
    
    def _get_solutions(self, error: Exception) -> List[str]:
        """Get solutions for an error."""
        error_message = str(error).lower()
        solutions = []
        
        if 'database' in error_message:
            solutions.extend([
                "Run 'python main.py init-samples --repair' to repair databases",
                "Run 'python main.py init-samples --force-reset' to recreate databases",
                "Check available disk space and free up space if needed",
                "Ensure no other instances of the tool are running"
            ])
        
        if 'config' in error_message:
            solutions.extend([
                "Validate config.json syntax using a JSON validator",
                "Reset configuration to defaults by deleting config.json",
                "Check file permissions on config.json",
                "Run 'python main.py config show' to verify configuration"
            ])
        
        if 'permission' in error_message:
            solutions.extend([
                "Run the tool with administrator/root privileges",
                "Check and modify file/directory permissions",
                "Temporarily disable antivirus real-time protection",
                "Close other applications that might be using the files"
            ])
        
        if 'import' in error_message or 'module' in error_message:
            solutions.extend([
                "Install required packages: pip install -r requirements.txt",
                "Verify Python version compatibility (3.7+)",
                "Check Python environment and virtual environment setup",
                "Reinstall the tool dependencies"
            ])
        
        if 'sample' in error_message:
            solutions.extend([
                "Reinitialize sample databases: python main.py init-samples",
                "Check sample directory permissions",
                "Validate sample metadata consistency",
                "Clean up orphaned sample files"
            ])
        
        # Always include general solutions
        solutions.extend([
            "Check the log file (antivirus.log) for detailed error information",
            "Run the command with --verbose flag for more details",
            "Restart the tool and try the operation again"
        ])
        
        return solutions
    
    def _get_prevention_tips(self, error: Exception) -> List[str]:
        """Get prevention tips for an error."""
        error_message = str(error).lower()
        tips = []
        
        if 'database' in error_message:
            tips.extend([
                "Regularly backup database files",
                "Monitor disk space usage",
                "Avoid forcefully terminating the application",
                "Run periodic database validation checks"
            ])
        
        if 'config' in error_message:
            tips.extend([
                "Backup configuration files before making changes",
                "Use configuration validation tools",
                "Document configuration changes",
                "Test configuration changes in a safe environment"
            ])
        
        if 'permission' in error_message:
            tips.extend([
                "Run the tool with appropriate user permissions",
                "Set up proper file and directory permissions",
                "Configure antivirus exclusions for tool directories",
                "Avoid running multiple instances simultaneously"
            ])
        
        # General prevention tips
        tips.extend([
            "Keep the tool and dependencies updated",
            "Monitor log files for early warning signs",
            "Follow the recommended installation and setup procedures",
            "Use the educational workflows to learn proper usage"
        ])
        
        return tips
    
    def _get_related_help(self, error: Exception) -> List[str]:
        """Get related help resources for an error."""
        error_message = str(error).lower()
        help_items = []
        
        if 'database' in error_message:
            help_items.extend([
                "Run 'python main.py help-system' and select 'Sample Management'",
                "Check the troubleshooting section in README.md",
                "Review database initialization documentation"
            ])
        
        if 'config' in error_message:
            help_items.extend([
                "Run 'python main.py help-system' and select 'Configuration'",
                "Review configuration examples in examples/usage_examples.py",
                "Check default configuration values"
            ])
        
        # Always include general help
        help_items.extend([
            "Run 'python main.py help-system' for interactive help",
            "Check examples/usage_examples.py for usage examples",
            "Review the troubleshooting section in README.md",
            "Run educational workflows to learn proper usage"
        ])
        
        return help_items
    
    def _get_severity_icon(self, severity: str) -> str:
        """Get icon for error severity."""
        icons = {
            ErrorSeverity.INFO: "ℹ️",
            ErrorSeverity.WARNING: "⚠️",
            ErrorSeverity.ERROR: "❌",
            ErrorSeverity.CRITICAL: "🚨"
        }
        return icons.get(severity, "❓")
    
    def _initialize_error_solutions(self) -> Dict[str, Dict[str, Any]]:
        """Initialize error solutions database."""
        return {
            'database_initialization_failed': {
                'message': 'Database initialization failed',
                'solutions': [
                    'Check disk space availability',
                    'Verify write permissions in the data directory',
                    'Run with --force-reset to recreate databases',
                    'Check for conflicting processes'
                ]
            },
            'configuration_load_failed': {
                'message': 'Configuration could not be loaded',
                'solutions': [
                    'Validate JSON syntax in config.json',
                    'Check file permissions on config.json',
                    'Reset to default configuration',
                    'Verify configuration file path'
                ]
            },
            'sample_creation_failed': {
                'message': 'Sample creation failed',
                'solutions': [
                    'Check write permissions in samples directory',
                    'Verify available disk space',
                    'Ensure sample name is unique',
                    'Check sample type parameters'
                ]
            }
        }
    
    def _initialize_common_scenarios(self) -> Dict[str, Dict[str, Any]]:
        """Initialize common scenario guidance."""
        return {
            'first_time_setup': {
                'title': 'First Time Setup',
                'description': 'Setting up the Educational Antivirus Tool for the first time',
                'steps': [
                    'Install Python 3.7 or higher',
                    'Install dependencies: pip install -r requirements.txt',
                    'Initialize databases: python main.py init-samples',
                    'Verify setup: python main.py config show',
                    'Run beginner workflow: python main.py examples beginner'
                ],
                'common_issues': [
                    'Permission errors: Run with appropriate privileges',
                    'Missing dependencies: Install requirements.txt',
                    'Database errors: Check disk space and permissions'
                ]
            },
            'scanning_not_working': {
                'title': 'Scanning Issues',
                'description': 'Troubleshooting scanning operations',
                'steps': [
                    'Verify target path exists and is accessible',
                    'Check file permissions on target directory',
                    'Ensure databases are initialized',
                    'Review configuration settings',
                    'Check log files for detailed errors'
                ],
                'common_issues': [
                    'Path not found: Verify directory path',
                    'Permission denied: Check access rights',
                    'No results: Verify detection settings'
                ]
            },
            'performance_issues': {
                'title': 'Performance Optimization',
                'description': 'Improving tool performance',
                'steps': [
                    'Adjust max_file_size_mb setting',
                    'Use appropriate detection sensitivity',
                    'Exclude unnecessary directories',
                    'Monitor system resources',
                    'Consider batch processing for large datasets'
                ],
                'common_issues': [
                    'Slow scanning: Reduce file size limits',
                    'High memory usage: Process files in batches',
                    'Disk space issues: Clean up temporary files'
                ]
            },
            'quarantine_issues': {
                'title': 'Quarantine Operations',
                'description': 'Troubleshooting quarantine functionality',
                'steps': [
                    'Verify quarantine directory exists and is writable',
                    'Check file permissions on quarantine directory',
                    'Ensure adequate disk space for quarantine operations',
                    'Test quarantine and restore operations',
                    'Review quarantine logs for errors'
                ],
                'common_issues': [
                    'Cannot quarantine files: Check directory permissions',
                    'Restore fails: Verify original file locations',
                    'Quarantine directory full: Clean up old quarantined files'
                ]
            },
            'detection_tuning': {
                'title': 'Detection Sensitivity Tuning',
                'description': 'Optimizing detection accuracy',
                'steps': [
                    'Start with default sensitivity settings',
                    'Test with known malware samples',
                    'Adjust signature_sensitivity for false positives',
                    'Tune behavioral_threshold for behavioral analysis',
                    'Update entropy_threshold for packed files',
                    'Review and update suspicious file extensions'
                ],
                'common_issues': [
                    'Too many false positives: Increase sensitivity thresholds',
                    'Missing detections: Lower sensitivity thresholds',
                    'Slow performance: Reduce detection complexity'
                ]
            },
            'educational_workflows': {
                'title': 'Using Educational Workflows',
                'description': 'Getting started with learning workflows',
                'steps': [
                    'Initialize sample databases first',
                    'Start with beginner workflow',
                    'Progress through intermediate scenarios',
                    'Experiment with advanced features',
                    'Use interactive help system for guidance'
                ],
                'common_issues': [
                    'Workflows not working: Ensure databases are initialized',
                    'Missing samples: Run init-samples command',
                    'Permission errors: Run with appropriate privileges'
                ]
            }
        }


class ErrorHandler:
    """Centralized error handling system."""
    
    def __init__(self, verbose: bool = False):
        """Initialize the error handler.
        
        Args:
            verbose: Whether to show detailed error information
        """
        self.verbose = verbose
        self.guidance_manager = UserGuidanceManager()
        
        # Initialize contextual help system if available
        if USER_GUIDANCE_AVAILABLE:
            self.contextual_help = create_user_guidance_system()
        else:
            self.contextual_help = None
        
    def handle_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> None:
        """Handle an error with comprehensive guidance.
        
        Args:
            error: The exception that occurred
            context: Optional context information
        """
        # Log the error
        logger.error(f"Error occurred: {error}", exc_info=True)
        
        # Get guidance
        guidance = self.guidance_manager.get_error_guidance(error, context)
        
        # Format and display error message
        error_message = self.guidance_manager.format_error_message(guidance, self.verbose)
        print(error_message)
        
        # Log guidance for debugging
        logger.debug(f"Error guidance: {guidance}")
        
        # Provide contextual help if available
        if self.contextual_help and context:
            contextual_help = self.contextual_help.get_contextual_help({
                'operation': context.get('operation', ''),
                'error_type': type(error).__name__,
                'error_message': str(error)
            })
            
            if contextual_help.get('suggestions'):
                print("\n💡 Additional suggestions:")
                for suggestion in contextual_help['suggestions']:
                    print(f"  • {suggestion}")
            
            if contextual_help.get('quick_fixes'):
                print("\n🔧 Quick fixes to try:")
                for fix in contextual_help['quick_fixes']:
                    print(f"  • {fix}")
            
            if contextual_help.get('learning_resources'):
                print("\n📚 Learning resources:")
                for resource in contextual_help['learning_resources']:
                    print(f"  • {resource}")
    
    def handle_warning(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Handle a warning with user guidance.
        
        Args:
            message: Warning message
            context: Optional context information
        """
        logger.warning(message)
        print(f"⚠️  Warning: {message}")
        
        if context:
            print("Additional information:")
            for key, value in context.items():
                print(f"  {key}: {value}")
    
    def suggest_next_steps(self, scenario: str) -> None:
        """Suggest next steps for a common scenario.
        
        Args:
            scenario: Scenario identifier
        """
        guidance = self.guidance_manager.get_common_scenario_guidance(scenario)
        
        if guidance:
            print(f"📋 {guidance['title']}")
            print(f"   {guidance['description']}")
            print()
            
            if 'steps' in guidance:
                print("Recommended steps:")
                for i, step in enumerate(guidance['steps'], 1):
                    print(f"  {i}. {step}")
                print()
            
            if 'common_issues' in guidance:
                print("Common issues and solutions:")
                for issue in guidance['common_issues']:
                    print(f"  • {issue}")
        else:
            print(f"No guidance available for scenario: {scenario}")


def create_error_handler(verbose: bool = False) -> ErrorHandler:
    """Create and configure an error handler.
    
    Args:
        verbose: Whether to show detailed error information
        
    Returns:
        Configured ErrorHandler instance
    """
    return ErrorHandler(verbose)


def handle_cli_error(error: Exception, verbose: bool = False) -> int:
    """Handle CLI errors and return appropriate exit code.
    
    Args:
        error: The exception that occurred
        verbose: Whether to show detailed error information
        
    Returns:
        Exit code (non-zero for errors)
    """
    handler = create_error_handler(verbose)
    handler.handle_error(error)
    
    # Return appropriate exit code based on error type
    if isinstance(error, (DatabaseError, SampleManagementError)):
        return 2  # Data/configuration error
    elif isinstance(error, PermissionError):
        return 3  # Permission error
    elif isinstance(error, FileNotFoundError):
        return 4  # File not found error
    else:
        return 1  # General error