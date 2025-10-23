"""
Enhanced error message system with comprehensive solutions and user guidance.

This module provides detailed, actionable error messages with step-by-step
solutions and contextual help for the Educational Antivirus Tool.
"""
import os
import sys
import platform
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

from .logging_config import setup_default_logging

logger = setup_default_logging()


class EnhancedErrorMessage:
    """Enhanced error message with comprehensive guidance."""
    
    def __init__(self, error: Exception, context: Optional[Dict[str, Any]] = None):
        """Initialize enhanced error message.
        
        Args:
            error: The exception that occurred
            context: Optional context information
        """
        self.error = error
        self.context = context or {}
        self.error_type = type(error).__name__
        self.error_message = str(error)
        
    def generate_comprehensive_message(self) -> str:
        """Generate a comprehensive error message with solutions."""
        lines = []
        
        # Header with error type and severity
        severity = self._assess_severity()
        severity_icon = self._get_severity_icon(severity)
        
        lines.append(f"{severity_icon} {self.error_type}: {self.error_message}")
        lines.append("=" * 60)
        lines.append("")
        
        # Context information
        if self.context:
            lines.append("📍 Context:")
            for key, value in self.context.items():
                lines.append(f"   {key}: {value}")
            lines.append("")
        
        # Detailed explanation
        explanation = self._get_detailed_explanation()
        if explanation:
            lines.append("📝 What happened:")
            lines.append(f"   {explanation}")
            lines.append("")
        
        # Possible causes
        causes = self._get_possible_causes()
        if causes:
            lines.append("🔍 Possible causes:")
            for i, cause in enumerate(causes, 1):
                lines.append(f"   {i}. {cause}")
            lines.append("")
        
        # Step-by-step solutions
        solutions = self._get_step_by_step_solutions()
        if solutions:
            lines.append("🛠️ Step-by-step solutions:")
            for i, solution in enumerate(solutions, 1):
                lines.append(f"   {i}. {solution['title']}")
                lines.append(f"      Command: {solution.get('command', 'N/A')}")
                if solution.get('description'):
                    lines.append(f"      Description: {solution['description']}")
                if solution.get('expected_result'):
                    lines.append(f"      Expected result: {solution['expected_result']}")
                lines.append("")
        
        # Platform-specific guidance
        platform_guidance = self._get_platform_specific_guidance()
        if platform_guidance:
            lines.append(f"🖥️ {platform.system()}-specific guidance:")
            for guidance in platform_guidance:
                lines.append(f"   • {guidance}")
            lines.append("")
        
        # Prevention tips
        prevention_tips = self._get_prevention_tips()
        if prevention_tips:
            lines.append("🛡️ Prevention tips:")
            for tip in prevention_tips:
                lines.append(f"   • {tip}")
            lines.append("")
        
        # Related resources
        resources = self._get_related_resources()
        if resources:
            lines.append("📚 Related resources:")
            for resource in resources:
                lines.append(f"   • {resource}")
            lines.append("")
        
        # Emergency procedures for critical errors
        if severity == 'critical':
            emergency_procedures = self._get_emergency_procedures()
            if emergency_procedures:
                lines.append("🚨 Emergency procedures:")
                for procedure in emergency_procedures:
                    lines.append(f"   • {procedure}")
                lines.append("")
        
        return "\n".join(lines)
    
    def _assess_severity(self) -> str:
        """Assess error severity level."""
        error_message_lower = self.error_message.lower()
        
        # Critical errors that prevent tool from functioning
        critical_indicators = [
            'database.*corrupt', 'initialization.*failed', 'config.*missing',
            'python.*version', 'import.*error', 'module.*not.*found'
        ]
        
        # Error indicators that affect functionality
        error_indicators = [
            'permission.*denied', 'file.*not.*found', 'access.*denied',
            'disk.*space', 'memory.*error'
        ]
        
        # Warning indicators for non-critical issues
        warning_indicators = [
            'timeout', 'slow.*performance', 'deprecated'
        ]
        
        import re
        
        for pattern in critical_indicators:
            if re.search(pattern, error_message_lower):
                return 'critical'
        
        for pattern in error_indicators:
            if re.search(pattern, error_message_lower):
                return 'error'
        
        for pattern in warning_indicators:
            if re.search(pattern, error_message_lower):
                return 'warning'
        
        return 'error'  # Default to error level
    
    def _get_severity_icon(self, severity: str) -> str:
        """Get icon for error severity."""
        icons = {
            'info': 'ℹ️',
            'warning': '⚠️',
            'error': '❌',
            'critical': '🚨'
        }
        return icons.get(severity, '❓')
    
    def _get_detailed_explanation(self) -> str:
        """Get detailed explanation of what happened."""
        error_explanations = {
            'ModuleNotFoundError': 'A required Python module could not be imported. This usually means the module is not installed or not accessible in the current Python environment.',
            'PermissionError': 'The operation was denied due to insufficient permissions. This can happen when trying to access files or directories without proper access rights.',
            'FileNotFoundError': 'A required file or directory could not be found at the specified location. This may indicate a missing file, incorrect path, or deleted resource.',
            'DatabaseError': 'An error occurred while accessing or manipulating the database. This could be due to corruption, locking issues, or insufficient permissions.',
            'ConfigurationError': 'The configuration could not be loaded or contains invalid values. This may be due to syntax errors or missing required settings.',
            'ImportError': 'A Python module could not be imported due to missing dependencies or environment issues.',
            'OSError': 'An operating system level error occurred, often related to file system operations or resource limitations.'
        }
        
        return error_explanations.get(self.error_type, 
            f'An unexpected {self.error_type} occurred during operation.')
    
    def _get_possible_causes(self) -> List[str]:
        """Get list of possible causes for the error."""
        causes_map = {
            'ModuleNotFoundError': [
                'Required Python packages are not installed',
                'Virtual environment is not activated',
                'Python path is not configured correctly',
                'Package versions are incompatible'
            ],
            'PermissionError': [
                'Running without administrator/root privileges',
                'Files or directories have restrictive permissions',
                'Antivirus software is blocking file access',
                'Files are currently in use by another application',
                'Network drive permissions are insufficient'
            ],
            'FileNotFoundError': [
                'File or directory was moved or deleted',
                'Incorrect file path specified',
                'Working directory is not what was expected',
                'File system case sensitivity issues',
                'Network connectivity problems for remote files'
            ],
            'DatabaseError': [
                'Database files are corrupted or missing',
                'Another process has locked the database',
                'Insufficient disk space for database operations',
                'Database schema version mismatch',
                'File system permissions prevent database access'
            ],
            'ConfigurationError': [
                'Configuration file has invalid JSON/YAML syntax',
                'Required configuration values are missing',
                'Configuration file permissions are incorrect',
                'Configuration values are outside valid ranges'
            ]
        }
        
        return causes_map.get(self.error_type, [
            'Unexpected system condition',
            'Resource limitations',
            'Environmental configuration issues'
        ])
    
    def _get_step_by_step_solutions(self) -> List[Dict[str, str]]:
        """Get step-by-step solutions for the error."""
        solutions_map = {
            'ModuleNotFoundError': [
                {
                    'title': 'Install required dependencies',
                    'command': 'pip install -r requirements.txt',
                    'description': 'Install all required Python packages',
                    'expected_result': 'All packages installed successfully'
                },
                {
                    'title': 'Verify Python environment',
                    'command': 'python --version && pip --version',
                    'description': 'Check Python and pip versions',
                    'expected_result': 'Python 3.7+ and pip version displayed'
                },
                {
                    'title': 'Check virtual environment',
                    'command': 'python -c "import sys; print(sys.prefix)"',
                    'description': 'Verify if virtual environment is active',
                    'expected_result': 'Virtual environment path displayed'
                }
            ],
            'PermissionError': [
                {
                    'title': 'Run with elevated privileges',
                    'command': 'Run as Administrator (Windows) or use sudo (Linux/Mac)',
                    'description': 'Execute the command with administrative rights',
                    'expected_result': 'Command executes without permission errors'
                },
                {
                    'title': 'Check file permissions',
                    'command': 'icacls <file> (Windows) or ls -la <file> (Linux/Mac)',
                    'description': 'Verify current file permissions',
                    'expected_result': 'File permissions displayed'
                },
                {
                    'title': 'Configure antivirus exclusions',
                    'command': 'Add tool directory to antivirus exclusions',
                    'description': 'Prevent antivirus from blocking file access',
                    'expected_result': 'Tool directory excluded from real-time scanning'
                }
            ],
            'FileNotFoundError': [
                {
                    'title': 'Verify file existence',
                    'command': 'dir <path> (Windows) or ls -la <path> (Linux/Mac)',
                    'description': 'Check if the file or directory exists',
                    'expected_result': 'File or directory listing displayed'
                },
                {
                    'title': 'Check current working directory',
                    'command': 'cd (Windows) or pwd (Linux/Mac)',
                    'description': 'Verify current directory location',
                    'expected_result': 'Current directory path displayed'
                },
                {
                    'title': 'Initialize missing resources',
                    'command': 'python main.py init-samples',
                    'description': 'Create missing database and sample files',
                    'expected_result': 'Resources initialized successfully'
                }
            ],
            'DatabaseError': [
                {
                    'title': 'Repair database',
                    'command': 'python main.py init-samples --repair',
                    'description': 'Attempt to repair corrupted databases',
                    'expected_result': 'Database repair completed successfully'
                },
                {
                    'title': 'Reset database',
                    'command': 'python main.py init-samples --force-reset',
                    'description': 'Recreate databases from scratch',
                    'expected_result': 'New databases created successfully'
                },
                {
                    'title': 'Check disk space',
                    'command': 'dir C:\\ (Windows) or df -h (Linux/Mac)',
                    'description': 'Verify available disk space',
                    'expected_result': 'At least 100MB free space available'
                }
            ]
        }
        
        return solutions_map.get(self.error_type, [
            {
                'title': 'Run system diagnostics',
                'command': 'python main.py troubleshoot --check-all',
                'description': 'Perform comprehensive system health check',
                'expected_result': 'System status report generated'
            },
            {
                'title': 'Check log files',
                'command': 'type antivirus.log | findstr ERROR (Windows) or grep ERROR antivirus.log (Linux/Mac)',
                'description': 'Review detailed error information in logs',
                'expected_result': 'Error details and stack traces displayed'
            }
        ])
    
    def _get_platform_specific_guidance(self) -> List[str]:
        """Get platform-specific guidance."""
        system = platform.system()
        
        if system == "Windows":
            return [
                'Use "Run as Administrator" for elevated privileges',
                'Check Windows Defender exclusions and real-time protection',
                'Use "icacls" command to manage file permissions',
                'Consider using PowerShell for advanced operations',
                'Check Windows Event Viewer for system-level errors'
            ]
        elif system == "Darwin":  # macOS
            return [
                'Use "sudo" for elevated privileges when necessary',
                'Check System Preferences > Security & Privacy settings',
                'Use "chmod" and "chown" to manage file permissions',
                'Consider Gatekeeper restrictions for downloaded files',
                'Check Console app for system logs'
            ]
        elif system == "Linux":
            return [
                'Use "sudo" for elevated privileges when necessary',
                'Check SELinux or AppArmor policies if applicable',
                'Use "chmod", "chown", and "chgrp" for permission management',
                'Verify user group memberships with "groups" command',
                'Check system logs with "journalctl" or "/var/log/"'
            ]
        else:
            return [
                'Consult your operating system documentation',
                'Check system-specific permission and security settings',
                'Verify file system compatibility and limitations'
            ]
    
    def _get_prevention_tips(self) -> List[str]:
        """Get prevention tips to avoid similar errors."""
        prevention_map = {
            'ModuleNotFoundError': [
                'Use virtual environments to isolate dependencies',
                'Keep requirements.txt updated with exact versions',
                'Test installations in clean environments',
                'Document Python version requirements clearly'
            ],
            'PermissionError': [
                'Run the tool with appropriate user permissions from the start',
                'Set up proper file and directory permissions during installation',
                'Configure antivirus exclusions before first use',
                'Avoid running multiple instances simultaneously'
            ],
            'FileNotFoundError': [
                'Always run initialization commands after installation',
                'Backup important configuration and data files',
                'Use absolute paths when possible',
                'Verify file locations before operations'
            ],
            'DatabaseError': [
                'Regularly backup database files',
                'Monitor disk space usage',
                'Avoid forcefully terminating the application',
                'Run periodic database validation checks'
            ]
        }
        
        return prevention_map.get(self.error_type, [
            'Keep the tool and dependencies updated',
            'Monitor log files for early warning signs',
            'Follow recommended installation and setup procedures',
            'Test changes in a safe environment first'
        ])
    
    def _get_related_resources(self) -> List[str]:
        """Get related help resources."""
        return [
            'Interactive troubleshooting: python main.py troubleshoot',
            'Comprehensive diagnostics: python main.py troubleshoot --check-all',
            'Educational workflows: python main.py examples beginner',
            'Interactive help system: python main.py help-system',
            'Troubleshooting guide: docs/troubleshooting.md',
            'Usage examples: examples/usage_examples.py',
            'Configuration reference: python main.py config show'
        ]
    
    def _get_emergency_procedures(self) -> List[str]:
        """Get emergency procedures for critical errors."""
        return [
            'Stop all running instances of the tool immediately',
            'Backup any important data or configuration files',
            'Run comprehensive system diagnostics',
            'Consider complete reinstallation if corruption is suspected',
            'Document the error conditions for future reference',
            'Test in a clean environment to isolate the issue'
        ]


def create_enhanced_error_message(error: Exception, context: Optional[Dict[str, Any]] = None) -> str:
    """Create an enhanced error message with comprehensive guidance.
    
    Args:
        error: The exception that occurred
        context: Optional context information
        
    Returns:
        Comprehensive error message string
    """
    enhanced_message = EnhancedErrorMessage(error, context)
    return enhanced_message.generate_comprehensive_message()


def format_error_for_cli(error: Exception, context: Optional[Dict[str, Any]] = None, verbose: bool = False) -> str:
    """Format error message for CLI display.
    
    Args:
        error: The exception that occurred
        context: Optional context information
        verbose: Whether to include verbose information
        
    Returns:
        Formatted error message for CLI
    """
    if verbose:
        return create_enhanced_error_message(error, context)
    else:
        # Simplified version for non-verbose mode
        lines = []
        
        error_type = type(error).__name__
        error_message = str(error)
        
        lines.append(f"❌ {error_type}: {error_message}")
        
        # Quick solutions
        enhanced_msg = EnhancedErrorMessage(error, context)
        solutions = enhanced_msg._get_step_by_step_solutions()
        
        if solutions:
            lines.append("")
            lines.append("Quick solutions:")
            for i, solution in enumerate(solutions[:2], 1):  # Show only first 2
                lines.append(f"  {i}. {solution['title']}")
                lines.append(f"     {solution['command']}")
        
        lines.append("")
        lines.append("For detailed help: python main.py troubleshoot")
        lines.append("For verbose output: add --verbose flag")
        
        return "\n".join(lines)