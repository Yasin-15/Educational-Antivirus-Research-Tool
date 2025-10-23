#!/usr/bin/env python3
"""
Command-line interface for the Educational Antivirus Research Tool.
"""
import argparse
import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
import json
from datetime import datetime

from core.config import ConfigManager
from core.models import Config
from core.exceptions import AntivirusError
from core.sample_initialization import SampleInitializationManager, initialize_educational_databases
from core.logging_config import setup_default_logging
from core.error_handler import ErrorHandler, create_error_handler, handle_cli_error
from core.enhanced_error_messages import format_error_for_cli

logger = setup_default_logging()


class CLIError(AntivirusError):
    """Raised when CLI operations fail."""
    pass


class AntivirusCLI:
    """Main CLI interface for the Educational Antivirus Research Tool."""
    
    def __init__(self):
        """Initialize the CLI interface."""
        self.config_manager = ConfigManager()
        self.config: Optional[Config] = None
        self.verbose = False
        self.error_handler: Optional[ErrorHandler] = None
        
    def initialize(self, config_path: Optional[str] = None) -> bool:
        """Initialize the CLI with configuration.
        
        Args:
            config_path: Optional path to configuration file
            
        Returns:
            True if initialization successful
        """
        try:
            # Load configuration
            self.config = self.config_manager.load_config(config_path)
            logger.info("CLI initialized successfully")
            return True
            
        except Exception as e:
            print(f"Error: Failed to initialize CLI: {e}")
            logger.error(f"CLI initialization failed: {e}")
            return False
    
    def run(self, args: List[str]) -> int:
        """Run the CLI with provided arguments.
        
        Args:
            args: Command line arguments
            
        Returns:
            Exit code (0 for success, non-zero for error)
        """
        try:
            parser = self._create_argument_parser()
            parsed_args = parser.parse_args(args)
            
            # Set global options
            self.verbose = parsed_args.verbose
            
            # Initialize error handler
            self.error_handler = create_error_handler(self.verbose)
            
            # Initialize CLI
            config_path = getattr(parsed_args, 'config', None)
            if not self.initialize(config_path):
                return 1
            
            # Execute command
            if hasattr(parsed_args, 'func'):
                return parsed_args.func(parsed_args)
            else:
                parser.print_help()
                return 0
                
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            return 130
        except Exception as e:
            if self.error_handler:
                return handle_cli_error(e, self.verbose)
            else:
                # Use enhanced error messaging
                error_message = format_error_for_cli(e, {'operation': 'cli_execution'}, self.verbose)
                print(error_message)
                return 1
    
    def _create_argument_parser(self) -> argparse.ArgumentParser:
        """Create the main argument parser with all commands and options."""
        parser = argparse.ArgumentParser(
            prog='antivirus-cli',
            description='Educational Antivirus Research Tool - Command Line Interface',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s init-samples                         # Initialize sample databases
  %(prog)s init-samples --force-reset          # Recreate all databases
  %(prog)s config show                         # Show current configuration
  %(prog)s examples beginner                   # Run beginner educational workflow
  %(prog)s examples scenarios                  # Demonstrate scanning scenarios
  %(prog)s help-system                         # Interactive help system
            """
        )
        
        # Global options
        parser.add_argument(
            '--config', '-c',
            help='Path to configuration file'
        )
        parser.add_argument(
            '--verbose', '-v',
            action='store_true',
            help='Enable verbose output'
        )
        parser.add_argument(
            '--version',
            action='version',
            version='Educational Antivirus Research Tool v1.0.0'
        )
        
        # Create subparsers for commands
        subparsers = parser.add_subparsers(
            dest='command',
            help='Available commands',
            metavar='COMMAND'
        )
        
        # Sample database initialization command
        self._add_init_samples_command(subparsers)
        
        # Configuration commands
        self._add_config_commands(subparsers)
        
        # Educational examples and workflows
        self._add_examples_commands(subparsers)
        
        # Interactive help system
        self._add_help_system_command(subparsers)
        
        # Troubleshooting command
        self._add_troubleshooting_command(subparsers)
        
        return parser
    
    def _add_init_samples_command(self, subparsers) -> None:
        """Add sample database initialization command."""
        init_parser = subparsers.add_parser(
            'init-samples',
            help='Initialize sample databases',
            description='Initialize educational sample and threat databases'
        )
        
        init_parser.add_argument(
            '--force-reset',
            action='store_true',
            help='Force recreation of all databases'
        )
        init_parser.add_argument(
            '--validate-only',
            action='store_true',
            help='Only validate existing databases without creating new ones'
        )
        init_parser.add_argument(
            '--repair',
            action='store_true',
            help='Repair corrupted or missing databases'
        )
        
        init_parser.set_defaults(func=self._handle_init_samples_command)
    
    def _add_config_commands(self, subparsers) -> None:
        """Add configuration management commands."""
        config_parser = subparsers.add_parser(
            'config',
            help='Manage configuration settings',
            description='View and modify configuration settings'
        )
        
        config_subparsers = config_parser.add_subparsers(
            dest='config_action',
            help='Configuration actions'
        )
        
        # Show config
        show_parser = config_subparsers.add_parser(
            'show',
            help='Show current configuration'
        )
        show_parser.add_argument(
            'setting',
            nargs='?',
            help='Specific setting to show (optional)'
        )
        show_parser.set_defaults(func=self._handle_config_show)
        
        config_parser.set_defaults(func=self._handle_config_command)
    
    def _add_examples_commands(self, subparsers) -> None:
        """Add educational examples and workflow commands."""
        examples_parser = subparsers.add_parser(
            'examples',
            help='Run educational workflows and demonstrations',
            description='Educational workflows and scanning scenario demonstrations'
        )
        
        examples_parser.add_argument(
            'workflow',
            choices=['beginner', 'intermediate', 'advanced', 'scenarios'],
            help='Educational workflow to run'
        )
        
        examples_parser.set_defaults(func=self._handle_examples_command)
    
    def _add_help_system_command(self, subparsers) -> None:
        """Add interactive help system command."""
        help_parser = subparsers.add_parser(
            'help-system',
            help='Interactive help system with comprehensive guidance',
            description='Launch interactive help system with detailed guidance and examples'
        )
        
        help_parser.set_defaults(func=self._handle_help_system_command)
    
    def _add_troubleshooting_command(self, subparsers) -> None:
        """Add troubleshooting and diagnostics command."""
        troubleshoot_parser = subparsers.add_parser(
            'troubleshoot',
            help='Run system diagnostics and troubleshooting',
            description='Diagnose common issues and provide troubleshooting guidance'
        )
        
        troubleshoot_parser.add_argument(
            '--check-all',
            action='store_true',
            help='Run comprehensive system checks'
        )
        
        troubleshoot_parser.add_argument(
            '--fix-common',
            action='store_true',
            help='Attempt to fix common issues automatically'
        )
        
        troubleshoot_parser.set_defaults(func=self._handle_troubleshooting_command)
    
    def _handle_init_samples_command(self, args) -> int:
        """Handle sample database initialization command."""
        try:
            print("Educational Antivirus Sample Database Initialization")
            print("=" * 55)
            
            # Create initialization manager
            try:
                manager = SampleInitializationManager(self.config)
            except Exception as e:
                self.error_handler.handle_error(e, {
                    'operation': 'initialization_manager_creation',
                    'config_path': getattr(self.config, 'config_path', 'default')
                })
                return 2
            
            if args.validate_only:
                print("Validating existing databases...")
                try:
                    validation_results = manager.validate_all_databases()
                    
                    if all(validation_results.values()):
                        print("✓ All databases are valid and accessible")
                        return 0
                    else:
                        print("⚠ Some validation checks failed:")
                        for check, result in validation_results.items():
                            status = "✓" if result else "✗"
                            print(f"  {status} {check}")
                        
                        # Provide guidance for validation failures
                        self.error_handler.suggest_next_steps('database_validation_failed')
                        return 1
                        
                except Exception as e:
                    self.error_handler.handle_error(e, {
                        'operation': 'database_validation',
                        'validation_type': 'all_databases'
                    })
                    return 2
            
            elif args.repair:
                print("Repairing databases...")
                try:
                    repair_results = manager.repair_databases()
                    
                    if all(repair_results.values()):
                        print("✓ All databases repaired successfully")
                        return 0
                    else:
                        print("⚠ Some repairs failed:")
                        for repair, result in repair_results.items():
                            status = "✓" if result else "✗"
                            print(f"  {status} {repair}")
                        
                        # Provide guidance for repair failures
                        print("\nIf repairs continue to fail, try:")
                        print("  1. Run with --force-reset to recreate databases")
                        print("  2. Check file permissions and disk space")
                        print("  3. Ensure no other instances are running")
                        return 1
                        
                except Exception as e:
                    self.error_handler.handle_error(e, {
                        'operation': 'database_repair',
                        'repair_type': 'all_databases'
                    })
                    return 2
            
            else:
                # Full initialization
                try:
                    results = manager.initialize_all_databases(args.force_reset)
                    
                    if results.get('validation_passed', False):
                        print("\n✓ Sample database initialization completed successfully!")
                        
                        # Show status
                        status = manager.get_initialization_status()
                        print(f"\nStatus Summary:")
                        print(f"  Sample count: {status.get('sample_count', 0)}")
                        print(f"  Threat information entries: {status.get('threat_count', 0)}")
                        print(f"  Databases initialized: {'Yes' if status.get('databases_initialized', False) else 'No'}")
                        
                        # Suggest next steps for successful initialization
                        print("\nNext steps:")
                        print("  • Run 'python main.py examples beginner' to start learning")
                        print("  • Use 'python main.py help-system' for interactive help")
                        print("  • Check 'examples/usage_examples.py' for usage examples")
                        
                        return 0
                    else:
                        print("\n⚠ Initialization completed with some issues")
                        if 'error' in results:
                            error_msg = results['error']
                            print(f"Error: {error_msg}")
                            
                            # Provide specific guidance based on error
                            if 'permission' in error_msg.lower():
                                print("\nThis appears to be a permission issue. Try:")
                                print("  • Running with administrator/elevated privileges")
                                print("  • Checking write permissions on the data directory")
                                print("  • Ensuring antivirus software isn't blocking access")
                            elif 'space' in error_msg.lower():
                                print("\nThis appears to be a disk space issue. Try:")
                                print("  • Freeing up disk space")
                                print("  • Moving to a directory with more space")
                                print("  • Checking available disk space with 'df -h' (Linux/Mac) or 'dir' (Windows)")
                        
                        return 1
                        
                except Exception as e:
                    self.error_handler.handle_error(e, {
                        'operation': 'full_initialization',
                        'force_reset': args.force_reset
                    })
                    return 2
        
        except Exception as e:
            self.error_handler.handle_error(e, {
                'operation': 'init_samples_command',
                'args': vars(args)
            })
            return 1
    
    def _handle_config_command(self, args) -> int:
        """Handle configuration command."""
        if not hasattr(args, 'config_action') or args.config_action is None:
            print("Error: No configuration action specified")
            print("Use 'config show' to view current configuration")
            return 1
        
        return 0
    
    def _handle_config_show(self, args) -> int:
        """Handle configuration show command."""
        try:
            if args.setting:
                # Show specific setting
                value = getattr(self.config, args.setting, None)
                if value is not None:
                    print(f"{args.setting}: {value}")
                else:
                    print(f"Setting '{args.setting}' not found")
                    return 1
            else:
                # Show all configuration
                print("Current Configuration:")
                print("=" * 30)
                config_dict = self.config.to_dict()
                for key, value in config_dict.items():
                    print(f"{key}: {value}")
            
            return 0
            
        except Exception as e:
            print(f"Error showing configuration: {e}")
            return 1
    
    def _handle_examples_command(self, args) -> int:
        """Handle educational examples command."""
        try:
            # Import here to avoid circular imports
            from examples.educational_workflows import EducationalWorkflowManager
            
            print("Loading Educational Antivirus Workflow System...")
            manager = EducationalWorkflowManager(self.config)
            
            if args.workflow == 'beginner':
                manager.run_beginner_workflow()
            elif args.workflow == 'intermediate':
                manager.run_intermediate_workflow()
            elif args.workflow == 'advanced':
                manager.run_advanced_workflow()
            elif args.workflow == 'scenarios':
                manager.demonstrate_scanning_scenarios()
            
            return 0
            
        except ImportError as e:
            print(f"Error: Educational workflows module not available: {e}")
            return 1
        except Exception as e:
            print(f"Error running educational workflow: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return 1
    
    def _handle_help_system_command(self, args) -> int:
        """Handle interactive help system command."""
        try:
            # Import here to avoid circular imports
            from examples.educational_workflows import EducationalWorkflowManager
            
            manager = EducationalWorkflowManager(self.config)
            manager.show_interactive_help()
            
            return 0
            
        except ImportError as e:
            print(f"Error: Help system module not available: {e}")
            return 1
        except Exception as e:
            print(f"Error launching help system: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return 1
    
    def _handle_troubleshooting_command(self, args) -> int:
        """Handle troubleshooting and diagnostics command."""
        try:
            print("🔧 Educational Antivirus Tool - System Diagnostics")
            print("=" * 55)
            print()
            
            if args.check_all:
                return self._run_comprehensive_diagnostics()
            elif args.fix_common:
                return self._fix_common_issues()
            else:
                return self._run_interactive_troubleshooting()
                
        except Exception as e:
            self.error_handler.handle_error(e, {
                'operation': 'troubleshooting_command',
                'args': vars(args)
            })
            return 1
    
    def _run_comprehensive_diagnostics(self) -> int:
        """Run comprehensive system diagnostics."""
        print("Running comprehensive system diagnostics...")
        print()
        
        diagnostics = []
        overall_status = True
        
        # Check Python environment
        print("1. Checking Python environment...")
        try:
            import sys
            python_version = sys.version_info
            if python_version >= (3, 7):
                print(f"   ✓ Python {python_version.major}.{python_version.minor}.{python_version.micro}")
                diagnostics.append(("Python Version", True, f"Python {python_version.major}.{python_version.minor}.{python_version.micro}"))
            else:
                print(f"   ✗ Python {python_version.major}.{python_version.minor}.{python_version.micro} (requires 3.7+)")
                diagnostics.append(("Python Version", False, f"Python {python_version.major}.{python_version.minor}.{python_version.micro} - upgrade required"))
                overall_status = False
        except Exception as e:
            print(f"   ✗ Python environment check failed: {e}")
            diagnostics.append(("Python Version", False, str(e)))
            overall_status = False
        
        # Check dependencies
        print("2. Checking dependencies...")
        try:
            import pkg_resources
            with open('requirements.txt', 'r') as f:
                requirements = f.read().strip().split('\n')
            
            missing_deps = []
            for req in requirements:
                if req.strip():
                    try:
                        pkg_resources.require(req.strip())
                        print(f"   ✓ {req.strip()}")
                    except pkg_resources.DistributionNotFound:
                        print(f"   ✗ {req.strip()} (missing)")
                        missing_deps.append(req.strip())
                    except pkg_resources.VersionConflict as e:
                        print(f"   ⚠ {req.strip()} (version conflict: {e})")
                        missing_deps.append(req.strip())
            
            if missing_deps:
                diagnostics.append(("Dependencies", False, f"Missing: {', '.join(missing_deps)}"))
                overall_status = False
            else:
                diagnostics.append(("Dependencies", True, "All dependencies satisfied"))
                
        except Exception as e:
            print(f"   ✗ Dependency check failed: {e}")
            diagnostics.append(("Dependencies", False, str(e)))
            overall_status = False
        
        # Check configuration
        print("3. Checking configuration...")
        try:
            config_status = self.config is not None
            if config_status:
                print("   ✓ Configuration loaded successfully")
                diagnostics.append(("Configuration", True, "Configuration valid"))
            else:
                print("   ✗ Configuration not loaded")
                diagnostics.append(("Configuration", False, "Configuration not loaded"))
                overall_status = False
        except Exception as e:
            print(f"   ✗ Configuration check failed: {e}")
            diagnostics.append(("Configuration", False, str(e)))
            overall_status = False
        
        # Check database initialization
        print("4. Checking database initialization...")
        try:
            from core.sample_initialization import SampleInitializationManager
            manager = SampleInitializationManager(self.config)
            status = manager.get_initialization_status()
            
            if status.get('databases_initialized', False):
                sample_count = status.get('sample_count', 0)
                threat_count = status.get('threat_count', 0)
                print(f"   ✓ Databases initialized ({sample_count} samples, {threat_count} threats)")
                diagnostics.append(("Database", True, f"{sample_count} samples, {threat_count} threats"))
            else:
                print("   ✗ Databases not initialized")
                diagnostics.append(("Database", False, "Databases not initialized"))
                overall_status = False
                
        except Exception as e:
            print(f"   ✗ Database check failed: {e}")
            diagnostics.append(("Database", False, str(e)))
            overall_status = False
        
        # Check file system permissions
        print("5. Checking file system permissions...")
        try:
            import os
            from pathlib import Path
            
            directories_to_check = ['samples/', 'quarantine/', 'reports/', 'data/']
            permission_issues = []
            
            for directory in directories_to_check:
                path = Path(directory)
                if path.exists():
                    if os.access(path, os.R_OK | os.W_OK):
                        print(f"   ✓ {directory} (read/write access)")
                    else:
                        print(f"   ✗ {directory} (insufficient permissions)")
                        permission_issues.append(directory)
                else:
                    print(f"   ⚠ {directory} (does not exist)")
            
            if permission_issues:
                diagnostics.append(("Permissions", False, f"Issues with: {', '.join(permission_issues)}"))
                overall_status = False
            else:
                diagnostics.append(("Permissions", True, "All directories accessible"))
                
        except Exception as e:
            print(f"   ✗ Permission check failed: {e}")
            diagnostics.append(("Permissions", False, str(e)))
            overall_status = False
        
        # Check disk space
        print("6. Checking disk space...")
        try:
            import shutil
            total, used, free = shutil.disk_usage('.')
            free_mb = free // (1024 * 1024)
            
            if free_mb > 100:  # At least 100MB free
                print(f"   ✓ Disk space: {free_mb} MB available")
                diagnostics.append(("Disk Space", True, f"{free_mb} MB available"))
            else:
                print(f"   ⚠ Disk space: {free_mb} MB available (low)")
                diagnostics.append(("Disk Space", False, f"Only {free_mb} MB available"))
                overall_status = False
                
        except Exception as e:
            print(f"   ✗ Disk space check failed: {e}")
            diagnostics.append(("Disk Space", False, str(e)))
            overall_status = False
        
        # Summary
        print()
        print("Diagnostic Summary:")
        print("=" * 20)
        
        for check, status, details in diagnostics:
            status_icon = "✓" if status else "✗"
            print(f"{status_icon} {check}: {details}")
        
        print()
        if overall_status:
            print("🎉 All system checks passed! The tool is ready for use.")
            print()
            print("Next steps:")
            print("• Run 'python main.py examples beginner' to start learning")
            print("• Use 'python main.py help-system' for interactive help")
            return 0
        else:
            print("⚠ Some issues were detected. See recommendations below:")
            print()
            
            # Provide specific recommendations
            for check, status, details in diagnostics:
                if not status:
                    if check == "Python Version":
                        print("• Python Version Issue:")
                        print("  - Install Python 3.7 or higher")
                        print("  - Update your Python installation")
                    elif check == "Dependencies":
                        print("• Dependency Issues:")
                        print("  - Run: pip install -r requirements.txt")
                        print("  - Consider using a virtual environment")
                    elif check == "Configuration":
                        print("• Configuration Issues:")
                        print("  - Check config.json syntax")
                        print("  - Run: python main.py config show")
                    elif check == "Database":
                        print("• Database Issues:")
                        print("  - Run: python main.py init-samples")
                        print("  - Try: python main.py init-samples --repair")
                    elif check == "Permissions":
                        print("• Permission Issues:")
                        print("  - Run with administrator privileges")
                        print("  - Check directory permissions")
                    elif check == "Disk Space":
                        print("• Disk Space Issues:")
                        print("  - Free up disk space")
                        print("  - Clean temporary files")
            
            return 1
    
    def _fix_common_issues(self) -> int:
        """Attempt to fix common issues automatically."""
        print("Attempting to fix common issues automatically...")
        print()
        
        fixes_attempted = []
        fixes_successful = []
        
        # Fix 1: Initialize databases if missing
        print("1. Checking and fixing database initialization...")
        try:
            from core.sample_initialization import SampleInitializationManager
            manager = SampleInitializationManager(self.config)
            status = manager.get_initialization_status()
            
            if not status.get('databases_initialized', False):
                print("   Initializing databases...")
                results = manager.initialize_all_databases(force_reset=False)
                if results.get('validation_passed', False):
                    print("   ✓ Databases initialized successfully")
                    fixes_successful.append("Database initialization")
                else:
                    print("   ✗ Database initialization failed")
                fixes_attempted.append("Database initialization")
            else:
                print("   ✓ Databases already initialized")
                
        except Exception as e:
            print(f"   ✗ Database fix failed: {e}")
            fixes_attempted.append("Database initialization")
        
        # Fix 2: Create missing directories
        print("2. Creating missing directories...")
        try:
            from pathlib import Path
            directories = ['samples/', 'quarantine/', 'reports/', 'data/']
            created_dirs = []
            
            for directory in directories:
                path = Path(directory)
                if not path.exists():
                    path.mkdir(parents=True, exist_ok=True)
                    created_dirs.append(directory)
                    print(f"   ✓ Created directory: {directory}")
            
            if created_dirs:
                fixes_successful.append(f"Created directories: {', '.join(created_dirs)}")
            else:
                print("   ✓ All required directories exist")
                
            fixes_attempted.append("Directory creation")
            
        except Exception as e:
            print(f"   ✗ Directory creation failed: {e}")
            fixes_attempted.append("Directory creation")
        
        # Fix 3: Reset configuration if corrupted
        print("3. Checking and fixing configuration...")
        try:
            if self.config is None:
                print("   Configuration not loaded, attempting to reset...")
                config_path = Path('config.json')
                if config_path.exists():
                    # Backup existing config
                    backup_path = Path(f'config.json.backup.{datetime.now().strftime("%Y%m%d_%H%M%S")}')
                    config_path.rename(backup_path)
                    print(f"   Backed up existing config to: {backup_path}")
                
                # Reinitialize configuration
                self.config = self.config_manager.load_config()
                print("   ✓ Configuration reset to defaults")
                fixes_successful.append("Configuration reset")
            else:
                print("   ✓ Configuration is valid")
                
            fixes_attempted.append("Configuration validation")
            
        except Exception as e:
            print(f"   ✗ Configuration fix failed: {e}")
            fixes_attempted.append("Configuration validation")
        
        # Summary
        print()
        print("Fix Summary:")
        print("=" * 15)
        print(f"Fixes attempted: {len(fixes_attempted)}")
        print(f"Fixes successful: {len(fixes_successful)}")
        
        if fixes_successful:
            print("\nSuccessful fixes:")
            for fix in fixes_successful:
                print(f"  ✓ {fix}")
        
        if len(fixes_successful) == len(fixes_attempted):
            print("\n🎉 All issues were resolved successfully!")
            print("The tool should now be ready for use.")
            return 0
        else:
            print(f"\n⚠ {len(fixes_attempted) - len(fixes_successful)} issues could not be resolved automatically.")
            print("You may need to address these manually or run comprehensive diagnostics.")
            return 1
    
    def _run_interactive_troubleshooting(self) -> int:
        """Run interactive troubleshooting with user guidance."""
        print("🔍 Interactive Troubleshooting Assistant")
        print("=" * 40)
        print()
        print("This assistant will help you diagnose and resolve common issues.")
        print("Please select the type of issue you're experiencing:")
        print()
        
        options = {
            '1': ('Installation and Setup Issues', self._troubleshoot_installation),
            '2': ('Database and Sample Management', self._troubleshoot_database),
            '3': ('Configuration Problems', self._troubleshoot_configuration),
            '4': ('Scanning and Detection Issues', self._troubleshoot_scanning),
            '5': ('Quarantine Operations', self._troubleshoot_quarantine),
            '6': ('Performance and Resource Issues', self._troubleshoot_performance),
            '7': ('Permission and Access Problems', self._troubleshoot_permissions),
            '8': ('Run Quick System Check', self._run_quick_system_check),
            '9': ('View Common Error Solutions', self._show_common_error_solutions)
        }
        
        for key, (description, _) in options.items():
            print(f"{key}. {description}")
        
        print("\n0. Exit troubleshooting")
        print()
        
        try:
            choice = input("Enter your choice (0-9): ").strip()
            
            if choice == '0':
                print("Exiting troubleshooting assistant.")
                return 0
            elif choice in options:
                _, handler = options[choice]
                return handler()
            else:
                print("Invalid choice. Please enter a number between 0-9.")
                return self._run_interactive_troubleshooting()
                
        except KeyboardInterrupt:
            print("\nTroubleshooting cancelled by user.")
            return 0
        except Exception as e:
            self.error_handler.handle_error(e, {'operation': 'interactive_troubleshooting'})
            return 1
    
    def _troubleshoot_installation(self) -> int:
        """Troubleshoot installation and setup issues."""
        print("\n🔧 Installation and Setup Troubleshooting")
        print("=" * 45)
        
        # Check Python version
        print("Checking Python version...")
        import sys
        python_version = sys.version_info
        if python_version >= (3, 7):
            print(f"✓ Python {python_version.major}.{python_version.minor}.{python_version.micro} (compatible)")
        else:
            print(f"✗ Python {python_version.major}.{python_version.minor}.{python_version.micro} (requires 3.7+)")
            print("\nSolution:")
            print("• Install Python 3.7 or higher from https://python.org")
            print("• Update your system's Python installation")
            return 1
        
        # Check dependencies
        print("\nChecking dependencies...")
        try:
            with open('requirements.txt', 'r') as f:
                requirements = f.read().strip().split('\n')
            
            missing_deps = []
            for req in requirements:
                if req.strip():
                    try:
                        import pkg_resources
                        pkg_resources.require(req.strip())
                    except (pkg_resources.DistributionNotFound, pkg_resources.VersionConflict):
                        missing_deps.append(req.strip())
            
            if missing_deps:
                print(f"✗ Missing dependencies: {', '.join(missing_deps)}")
                print("\nSolution:")
                print("• Run: pip install -r requirements.txt")
                print("• Consider using a virtual environment")
                return 1
            else:
                print("✓ All dependencies are installed")
                
        except Exception as e:
            print(f"✗ Could not check dependencies: {e}")
            return 1
        
        print("\n✅ Installation appears to be correct!")
        print("\nNext steps:")
        print("• Run: python main.py init-samples")
        print("• Try: python main.py examples beginner")
        
        return 0
    
    def _troubleshoot_database(self) -> int:
        """Troubleshoot database and sample management issues."""
        print("\n💾 Database and Sample Management Troubleshooting")
        print("=" * 55)
        
        try:
            from core.sample_initialization import SampleInitializationManager
            manager = SampleInitializationManager(self.config)
            
            print("Checking database status...")
            status = manager.get_initialization_status()
            
            if status.get('databases_initialized', False):
                sample_count = status.get('sample_count', 0)
                threat_count = status.get('threat_count', 0)
                print(f"✓ Databases initialized ({sample_count} samples, {threat_count} threats)")
                
                # Check for common database issues
                print("\nRunning database validation...")
                validation = manager.validate_all_databases()
                
                issues = []
                for check, result in validation.items():
                    if not result:
                        issues.append(check)
                
                if issues:
                    print(f"⚠ Database validation issues: {', '.join(issues)}")
                    print("\nRecommended solutions:")
                    print("• Run: python main.py init-samples --repair")
                    print("• If repair fails: python main.py init-samples --force-reset")
                    return 1
                else:
                    print("✓ Database validation passed")
                    
            else:
                print("✗ Databases not initialized")
                print("\nSolution:")
                print("• Run: python main.py init-samples")
                return 1
                
        except Exception as e:
            print(f"✗ Database check failed: {e}")
            print("\nCommon causes and solutions:")
            print("• Permission issues: Run with administrator privileges")
            print("• Disk space: Check available disk space")
            print("• File locks: Ensure no other instances are running")
            return 1
        
        print("\n✅ Database system appears to be working correctly!")
        return 0
    
    def _troubleshoot_configuration(self) -> int:
        """Troubleshoot configuration problems."""
        print("\n⚙️ Configuration Troubleshooting")
        print("=" * 35)
        
        print("Checking configuration status...")
        
        if self.config is None:
            print("✗ Configuration not loaded")
            print("\nPossible causes:")
            print("• config.json file is missing or corrupted")
            print("• Invalid JSON syntax")
            print("• Permission issues")
            
            print("\nSolutions:")
            print("• Delete config.json to reset to defaults")
            print("• Validate JSON syntax using online tools")
            print("• Check file permissions")
            
            # Offer to reset configuration
            try:
                reset = input("\nWould you like to reset configuration to defaults? (y/n): ").strip().lower()
                if reset == 'y':
                    config_path = Path('config.json')
                    if config_path.exists():
                        backup_path = Path(f'config.json.backup.{datetime.now().strftime("%Y%m%d_%H%M%S")}')
                        config_path.rename(backup_path)
                        print(f"Backed up existing config to: {backup_path}")
                    
                    self.config = self.config_manager.load_config()
                    print("✓ Configuration reset to defaults")
                    return 0
            except KeyboardInterrupt:
                print("\nConfiguration reset cancelled.")
            
            return 1
        else:
            print("✓ Configuration loaded successfully")
            
            # Show current configuration
            print("\nCurrent configuration:")
            config_dict = self.config.to_dict()
            for key, value in config_dict.items():
                print(f"  {key}: {value}")
        
        print("\n✅ Configuration appears to be working correctly!")
        return 0
    
    def _troubleshoot_scanning(self) -> int:
        """Troubleshoot scanning and detection issues."""
        print("\n🔍 Scanning and Detection Troubleshooting")
        print("=" * 45)
        
        print("Common scanning issues and solutions:")
        print()
        
        print("1. No files detected during scan:")
        print("   • Check if target path exists and is accessible")
        print("   • Verify file permissions on target directory")
        print("   • Ensure recursive_scan is enabled for subdirectories")
        print()
        
        print("2. Scanning is very slow:")
        print("   • Reduce max_file_size_mb setting")
        print("   • Lower signature_sensitivity and behavioral_threshold")
        print("   • Exclude large directories or media files")
        print()
        
        print("3. Too many false positives:")
        print("   • Increase signature_sensitivity threshold")
        print("   • Adjust entropy_threshold for better accuracy")
        print("   • Review and update suspicious_extensions list")
        print()
        
        print("4. Missing detections:")
        print("   • Lower signature_sensitivity for more sensitive detection")
        print("   • Ensure sample databases are up to date")
        print("   • Check if file types are in suspicious_extensions")
        print()
        
        # Offer to check current detection settings
        if self.config:
            print("Current detection settings:")
            print(f"  signature_sensitivity: {self.config.signature_sensitivity}")
            print(f"  behavioral_threshold: {self.config.behavioral_threshold}")
            print(f"  entropy_threshold: {self.config.entropy_threshold}")
            print(f"  max_file_size_mb: {self.config.max_file_size_mb}")
        
        return 0
    
    def _troubleshoot_quarantine(self) -> int:
        """Troubleshoot quarantine operations."""
        print("\n🔒 Quarantine Operations Troubleshooting")
        print("=" * 45)
        
        print("Checking quarantine system...")
        
        # Check quarantine directory
        quarantine_path = Path(self.config.quarantine_path if self.config else 'quarantine/')
        
        if not quarantine_path.exists():
            print(f"✗ Quarantine directory does not exist: {quarantine_path}")
            print("\nSolution:")
            print(f"• Create directory: mkdir {quarantine_path}")
            
            try:
                create = input(f"\nCreate quarantine directory now? (y/n): ").strip().lower()
                if create == 'y':
                    quarantine_path.mkdir(parents=True, exist_ok=True)
                    print(f"✓ Created quarantine directory: {quarantine_path}")
            except KeyboardInterrupt:
                print("\nDirectory creation cancelled.")
            
            return 1
        
        # Check permissions
        if not os.access(quarantine_path, os.R_OK | os.W_OK):
            print(f"✗ Insufficient permissions on quarantine directory: {quarantine_path}")
            print("\nSolutions:")
            print("• Run with administrator/elevated privileges")
            print("• Check and modify directory permissions")
            return 1
        
        print(f"✓ Quarantine directory is accessible: {quarantine_path}")
        
        # Check for quarantined files
        quarantined_files = list(quarantine_path.glob('*'))
        print(f"Current quarantined files: {len(quarantined_files)}")
        
        if quarantined_files:
            print("\nQuarantined files:")
            for file_path in quarantined_files[:5]:  # Show first 5
                print(f"  • {file_path.name}")
            if len(quarantined_files) > 5:
                print(f"  ... and {len(quarantined_files) - 5} more")
        
        print("\n✅ Quarantine system appears to be working correctly!")
        return 0
    
    def _troubleshoot_performance(self) -> int:
        """Troubleshoot performance and resource issues."""
        print("\n⚡ Performance and Resource Troubleshooting")
        print("=" * 50)
        
        print("Performance optimization recommendations:")
        print()
        
        # Check current settings that affect performance
        if self.config:
            print("Current performance-related settings:")
            print(f"  max_file_size_mb: {self.config.max_file_size_mb}")
            print(f"  signature_sensitivity: {self.config.signature_sensitivity}")
            print(f"  behavioral_threshold: {self.config.behavioral_threshold}")
            print(f"  recursive_scan: {self.config.recursive_scan}")
            print()
            
            # Provide recommendations
            if self.config.max_file_size_mb > 50:
                print("⚠ Large file size limit may slow scanning")
                print("  Recommendation: Reduce max_file_size_mb to 10-20 MB")
            
            if self.config.signature_sensitivity < 5:
                print("⚠ Very sensitive detection may impact performance")
                print("  Recommendation: Increase signature_sensitivity to 5-7")
        
        # Check system resources
        print("System resource recommendations:")
        print("• Close unnecessary applications during scanning")
        print("• Ensure adequate free disk space (>100MB)")
        print("• Consider scanning smaller directories at a time")
        print("• Use --verbose flag to monitor progress")
        
        # Check disk space
        try:
            import shutil
            total, used, free = shutil.disk_usage('.')
            free_mb = free // (1024 * 1024)
            print(f"\nCurrent disk space: {free_mb} MB available")
            
            if free_mb < 100:
                print("⚠ Low disk space may cause issues")
                print("  Recommendation: Free up disk space")
        except Exception:
            pass
        
        return 0
    
    def _troubleshoot_permissions(self) -> int:
        """Troubleshoot permission and access problems."""
        print("\n🔐 Permission and Access Troubleshooting")
        print("=" * 45)
        
        print("Checking file and directory permissions...")
        
        # Check key directories
        directories_to_check = [
            ('samples/', 'Sample storage'),
            ('quarantine/', 'Quarantine storage'),
            ('reports/', 'Report output'),
            ('data/', 'Database storage')
        ]
        
        permission_issues = []
        
        for directory, description in directories_to_check:
            path = Path(directory)
            
            if path.exists():
                if os.access(path, os.R_OK | os.W_OK):
                    print(f"✓ {description}: {directory}")
                else:
                    print(f"✗ {description}: {directory} (insufficient permissions)")
                    permission_issues.append(directory)
            else:
                print(f"⚠ {description}: {directory} (does not exist)")
                permission_issues.append(directory)
        
        if permission_issues:
            print(f"\nPermission issues detected: {', '.join(permission_issues)}")
            print("\nCommon solutions:")
            print("• Run the tool with administrator/elevated privileges")
            print("• Check and modify file/directory permissions")
            print("• Ensure antivirus software isn't blocking access")
            print("• Close other applications that might be using the files")
            
            # Platform-specific guidance
            import platform
            if platform.system() == "Windows":
                print("\nWindows-specific solutions:")
                print("• Right-click and 'Run as Administrator'")
                print("• Check Windows Defender exclusions")
                print("• Use 'icacls' command to check permissions")
            else:
                print("\nLinux/Mac-specific solutions:")
                print("• Use 'sudo' if necessary")
                print("• Check permissions with 'ls -la'")
                print("• Use 'chmod' to modify permissions")
            
            return 1
        
        print("\n✅ All permissions appear to be correct!")
        return 0
    
    def _run_quick_system_check(self) -> int:
        """Run a quick system check."""
        print("\n⚡ Quick System Check")
        print("=" * 25)
        
        checks = [
            ("Python version", self._check_python_version),
            ("Configuration", self._check_configuration),
            ("Database status", self._check_database_status),
            ("Directory permissions", self._check_directory_permissions),
            ("Disk space", self._check_disk_space)
        ]
        
        passed = 0
        total = len(checks)
        
        for check_name, check_func in checks:
            print(f"Checking {check_name}...", end=" ")
            try:
                if check_func():
                    print("✓")
                    passed += 1
                else:
                    print("✗")
            except Exception:
                print("✗")
        
        print(f"\nQuick check results: {passed}/{total} checks passed")
        
        if passed == total:
            print("🎉 All quick checks passed! The system appears to be healthy.")
            return 0
        else:
            print("⚠ Some issues detected. Use specific troubleshooting options for details.")
            return 1
    
    def _check_python_version(self) -> bool:
        """Check if Python version is compatible."""
        import sys
        return sys.version_info >= (3, 7)
    
    def _check_configuration(self) -> bool:
        """Check if configuration is loaded."""
        return self.config is not None
    
    def _check_database_status(self) -> bool:
        """Check if databases are initialized."""
        try:
            from core.sample_initialization import SampleInitializationManager
            manager = SampleInitializationManager(self.config)
            status = manager.get_initialization_status()
            return status.get('databases_initialized', False)
        except Exception:
            return False
    
    def _check_directory_permissions(self) -> bool:
        """Check if required directories have proper permissions."""
        directories = ['samples/', 'quarantine/', 'reports/', 'data/']
        
        for directory in directories:
            path = Path(directory)
            if path.exists() and not os.access(path, os.R_OK | os.W_OK):
                return False
        
        return True
    
    def _check_disk_space(self) -> bool:
        """Check if there's adequate disk space."""
        try:
            import shutil
            total, used, free = shutil.disk_usage('.')
            free_mb = free // (1024 * 1024)
            return free_mb > 100  # At least 100MB
        except Exception:
            return False
    
    def _show_common_error_solutions(self) -> int:
        """Show solutions for common errors."""
        print("\n📋 Common Error Solutions")
        print("=" * 30)
        
        common_errors = {
            "ModuleNotFoundError": {
                "description": "Python module/package not found",
                "solutions": [
                    "Install requirements: pip install -r requirements.txt",
                    "Check Python environment and virtual environment",
                    "Verify Python path configuration"
                ]
            },
            "PermissionError": {
                "description": "Insufficient file/directory permissions",
                "solutions": [
                    "Run with administrator/elevated privileges",
                    "Check file and directory permissions",
                    "Configure antivirus exclusions",
                    "Close other applications using the files"
                ]
            },
            "FileNotFoundError": {
                "description": "Required file or directory not found",
                "solutions": [
                    "Verify file paths are correct",
                    "Run initialization: python main.py init-samples",
                    "Check if files were moved or deleted",
                    "Restore from backup if available"
                ]
            },
            "DatabaseError": {
                "description": "Database operation failed",
                "solutions": [
                    "Repair databases: python main.py init-samples --repair",
                    "Reset databases: python main.py init-samples --force-reset",
                    "Check disk space and permissions",
                    "Ensure no other instances are running"
                ]
            },
            "ConfigurationError": {
                "description": "Configuration loading or validation failed",
                "solutions": [
                    "Validate JSON syntax in config.json",
                    "Reset configuration by deleting config.json",
                    "Check file permissions on config.json",
                    "Restore from backup configuration"
                ]
            }
        }
        
        for error_type, info in common_errors.items():
            print(f"\n{error_type}:")
            print(f"  Description: {info['description']}")
            print("  Solutions:")
            for solution in info['solutions']:
                print(f"    • {solution}")
        
        print("\nFor more detailed help:")
        print("• Run: python main.py help-system")
        print("• Check: docs/troubleshooting.md")
        print("• Use specific troubleshooting options in this menu")
        
        return 0


def main(args=None):
    """Main entry point for the CLI."""
    if args is None:
        args = sys.argv[1:]
    
    cli = AntivirusCLI()
    return cli.run(args)


if __name__ == '__main__':
    sys.exit(main())