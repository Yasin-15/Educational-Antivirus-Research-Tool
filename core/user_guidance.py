"""
Enhanced user guidance system for the Educational Antivirus Tool.

This module provides comprehensive user guidance, contextual help,
and step-by-step solutions for common scenarios and issues.
"""
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

from .logging_config import setup_default_logging

logger = setup_default_logging()


class ScenarioGuide:
    """Provides guidance for specific user scenarios."""
    
    def __init__(self):
        """Initialize the scenario guide."""
        self.scenarios = self._initialize_scenarios()
    
    def get_scenario_guidance(self, scenario_id: str) -> Optional[Dict[str, Any]]:
        """Get guidance for a specific scenario."""
        return self.scenarios.get(scenario_id)
    
    def list_available_scenarios(self) -> List[str]:
        """Get list of available scenario IDs."""
        return list(self.scenarios.keys())
    
    def search_scenarios(self, query: str) -> List[Tuple[str, Dict[str, Any]]]:
        """Search scenarios by keywords."""
        query_lower = query.lower()
        matches = []
        
        for scenario_id, scenario in self.scenarios.items():
            searchable_text = (
                scenario.get('title', '').lower() + ' ' +
                scenario.get('description', '').lower() + ' ' +
                ' '.join(scenario.get('keywords', [])).lower()
            )
            
            if query_lower in searchable_text:
                matches.append((scenario_id, scenario))
        
        return matches
    
    def _initialize_scenarios(self) -> Dict[str, Dict[str, Any]]:
        """Initialize scenario guidance database."""
        return {
            'first_time_setup': {
                'title': 'First Time Setup and Installation',
                'description': 'Complete guide for setting up the Educational Antivirus Tool',
                'keywords': ['setup', 'install', 'first', 'new', 'begin'],
                'difficulty': 'beginner',
                'estimated_time': '10-15 minutes',
                'prerequisites': ['Python 3.7+', 'Command line access'],
                'steps': [
                    {
                        'step': 1,
                        'title': 'Verify Python Installation',
                        'description': 'Check that Python 3.7 or higher is installed',
                        'command': 'python --version',
                        'expected_output': 'Python 3.7.x or higher',
                        'troubleshooting': [
                            'If Python is not found, install from https://python.org',
                            'On some systems, use "python3" instead of "python"',
                            'Ensure Python is added to your system PATH'
                        ]
                    },
                    {
                        'step': 2,
                        'title': 'Install Dependencies',
                        'description': 'Install required Python packages',
                        'command': 'pip install -r requirements.txt',
                        'expected_output': 'Successfully installed packages',
                        'troubleshooting': [
                            'Use "pip3" if "pip" is not found',
                            'Consider using a virtual environment',
                            'Run with --user flag if permission issues occur'
                        ]
                    },
                    {
                        'step': 3,
                        'title': 'Initialize Sample Databases',
                        'description': 'Set up educational sample and threat databases',
                        'command': 'python main.py init-samples',
                        'expected_output': 'Sample database initialization completed successfully',
                        'troubleshooting': [
                            'Run with administrator privileges if permission errors occur',
                            'Ensure at least 100MB of free disk space',
                            'Use --force-reset flag if databases are corrupted'
                        ]
                    }
                ],
                'success_indicators': [
                    'All commands execute without errors',
                    'Sample databases contain educational samples',
                    'Configuration is loaded successfully'
                ],
                'next_steps': [
                    'Run educational workflows: python main.py examples beginner',
                    'Try interactive help: python main.py help-system',
                    'Review usage examples in examples/usage_examples.py'
                ]
            },
            
            'scanning_files': {
                'title': 'Scanning Files and Directories',
                'description': 'Learn how to scan files and directories for threats',
                'keywords': ['scan', 'detect', 'analyze', 'check'],
                'difficulty': 'beginner',
                'estimated_time': '5-10 minutes',
                'prerequisites': ['Tool installed and initialized'],
                'configuration_tips': [
                    'Adjust signature_sensitivity (1-10) for detection sensitivity',
                    'Set max_file_size_mb to limit files scanned by size',
                    'Configure suspicious_extensions for file type filtering'
                ],
                'performance_tips': [
                    'Start with smaller directories for testing',
                    'Exclude media files and system directories',
                    'Monitor system resources during large scans'
                ]
            },
            
            'troubleshooting_errors': {
                'title': 'Troubleshooting Common Errors',
                'description': 'Diagnose and resolve common issues',
                'keywords': ['error', 'problem', 'issue', 'fix', 'debug'],
                'difficulty': 'intermediate',
                'estimated_time': '10-30 minutes',
                'prerequisites': ['Basic command line knowledge'],
                'common_error_patterns': {
                    'import_errors': {
                        'symptoms': ['ModuleNotFoundError', 'ImportError'],
                        'causes': ['Missing dependencies', 'Python path issues'],
                        'solutions': [
                            'pip install -r requirements.txt',
                            'Check Python environment setup'
                        ]
                    },
                    'permission_errors': {
                        'symptoms': ['PermissionError', 'Access denied'],
                        'causes': ['Insufficient privileges', 'File locks'],
                        'solutions': [
                            'Run with administrator privileges',
                            'Check file and directory permissions'
                        ]
                    }
                }
            }
        }


class ContextualHelpSystem:
    """Provides contextual help based on user actions and errors."""
    
    def __init__(self):
        """Initialize the contextual help system."""
        self.scenario_guide = ScenarioGuide()
        self.help_history = []
    
    def get_contextual_help(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get contextual help based on current context."""
        help_info = {
            'suggestions': [],
            'related_scenarios': [],
            'quick_fixes': [],
            'learning_resources': []
        }
        
        operation = context.get('operation', '')
        error_type = context.get('error_type', '')
        user_level = context.get('user_level', 'beginner')
        
        # Operation-specific suggestions
        if 'scan' in operation.lower():
            help_info['suggestions'].extend([
                'Ensure target files/directories exist and are accessible',
                'Check configuration settings for optimal performance'
            ])
            help_info['related_scenarios'].append('scanning_files')
            
        # Error-specific quick fixes
        if error_type:
            if 'permission' in error_type.lower():
                help_info['quick_fixes'].extend([
                    'Run with administrator/elevated privileges',
                    'Check file and directory permissions'
                ])
            elif 'database' in error_type.lower():
                help_info['quick_fixes'].extend([
                    'python main.py init-samples --repair',
                    'python main.py troubleshoot --fix-common'
                ])
        
        # User level-specific learning resources
        if user_level == 'beginner':
            help_info['learning_resources'].extend([
                'Start with: python main.py examples beginner',
                'Use interactive help: python main.py help-system'
            ])
        
        self.help_history.append({
            'timestamp': datetime.now(),
            'context': context,
            'help_provided': help_info
        })
        
        return help_info
    
    def suggest_next_actions(self, context: Dict[str, Any]) -> List[str]:
        """Suggest next actions based on current context."""
        suggestions = []
        
        operation = context.get('operation', '')
        success = context.get('success', False)
        
        if success:
            if 'init' in operation:
                suggestions.extend([
                    'Try running educational workflows: python main.py examples beginner',
                    'Explore configuration options: python main.py config show'
                ])
        else:
            suggestions.extend([
                'Check the troubleshooting guide: docs/troubleshooting.md',
                'Run interactive troubleshooting: python main.py troubleshoot'
            ])
        
        return suggestions[:5]


def create_user_guidance_system() -> ContextualHelpSystem:
    """Create and configure a user guidance system."""
    return ContextualHelpSystem()