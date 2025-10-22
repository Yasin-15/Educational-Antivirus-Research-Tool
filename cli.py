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
            print(f"Error: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
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
    
    def _handle_init_samples_command(self, args) -> int:
        """Handle sample database initialization command."""
        try:
            print("Educational Antivirus Sample Database Initialization")
            print("=" * 55)
            
            # Create initialization manager
            manager = SampleInitializationManager(self.config)
            
            if args.validate_only:
                print("Validating existing databases...")
                validation_results = manager.validate_all_databases()
                
                if all(validation_results.values()):
                    print("✓ All databases are valid and accessible")
                    return 0
                else:
                    print("⚠ Some validation checks failed:")
                    for check, result in validation_results.items():
                        status = "✓" if result else "✗"
                        print(f"  {status} {check}")
                    return 1
            
            elif args.repair:
                print("Repairing databases...")
                repair_results = manager.repair_databases()
                
                if all(repair_results.values()):
                    print("✓ All databases repaired successfully")
                    return 0
                else:
                    print("⚠ Some repairs failed:")
                    for repair, result in repair_results.items():
                        status = "✓" if result else "✗"
                        print(f"  {status} {repair}")
                    return 1
            
            else:
                # Full initialization
                results = manager.initialize_all_databases(args.force_reset)
                
                if results.get('validation_passed', False):
                    print("\n✓ Sample database initialization completed successfully!")
                    
                    # Show status
                    status = manager.get_initialization_status()
                    print(f"\nStatus Summary:")
                    print(f"  Sample count: {status.get('sample_count', 0)}")
                    print(f"  Threat information entries: {status.get('threat_count', 0)}")
                    print(f"  Databases initialized: {'Yes' if status.get('databases_initialized', False) else 'No'}")
                    
                    return 0
                else:
                    print("\n⚠ Initialization completed with some issues")
                    if 'error' in results:
                        print(f"Error: {results['error']}")
                    return 1
        
        except Exception as e:
            print(f"✗ Initialization failed: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
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


def main(args: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI."""
    if args is None:
        args = sys.argv[1:]
    
    cli = AntivirusCLI()
    return cli.run(args)


if __name__ == '__main__':
    sys.exit(main())