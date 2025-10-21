#!/usr/bin/env python3
"""
Command-line interface for the Educational Antivirus Research Tool.

This module provides a comprehensive CLI for scanning files, managing configuration,
handling quarantine operations, and managing test samples.
"""
import argparse
import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
import json
from datetime import datetime

from core.config import ConfigManager
from core.models import Config, ScanOptions, DetectionType
from core.exceptions import (
    AntivirusError, ScanError, ConfigurationError, 
    QuarantineError, FileAccessError
)
from core.integrated_scanner import IntegratedScanner, ThreatAction
from core.logging_config import get_logger
from quarantine.quarantine_interface import QuarantineInterface
from reporting.report_generator import ReportGenerator
from reporting.educational_report_system import EducationalReportSystem
from cli_utils import (
    ProgressIndicator, ThreatDisplayFormatter, 
    InteractivePrompt, ScanResultsFormatter
)

logger = get_logger(__name__)


class CLIError(AntivirusError):
    """Raised when CLI operations fail."""
    pass


class AntivirusCLI:
    """Main CLI interface for the Educational Antivirus Research Tool."""
    
    def __init__(self):
        """Initialize the CLI interface."""
        self.config_manager = ConfigManager()
        self.config: Optional[Config] = None
        self.scanner: Optional[IntegratedScanner] = None
        self.quarantine_interface: Optional[QuarantineInterface] = None
        self.report_generator: Optional[ReportGenerator] = None
        self.educational_system: Optional[EducationalReportSystem] = None
        
        # CLI state
        self.interactive_mode = False
        self.verbose = False
        self.progress_indicator: Optional[ProgressIndicator] = None
        
    def initialize(self, config_path: Optional[str] = None) -> bool:
        """Initialize the CLI with configuration and components.
        
        Args:
            config_path: Optional path to configuration file
            
        Returns:
            True if initialization successful
        """
        try:
            # Load configuration
            self.config = self.config_manager.load_config(config_path)
            
            # Initialize components
            self.scanner = IntegratedScanner(self.config)
            self.scanner.initialize()
            
            self.quarantine_interface = QuarantineInterface(self.config.quarantine_path)
            self.report_generator = ReportGenerator(self.config)
            self.educational_system = EducationalReportSystem()
            
            # Set up interactive callbacks if needed
            if self.interactive_mode:
                self.scanner.set_threat_decision_callback(self._interactive_threat_decision)
                self.scanner.set_progress_callback(self._progress_callback)
            
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
            self.interactive_mode = getattr(parsed_args, 'interactive', False)
            
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
        finally:
            self._cleanup()
    
    def _display_scan_header(self, args) -> None:
        """Display enhanced scan header with configuration information."""
        print(f"\n{'='*70}")
        print(f"🔍 EDUCATIONAL ANTIVIRUS SCAN")
        print(f"{'='*70}")
        print(f"📁 Target: {args.path}")
        print(f"🕒 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Display scan configuration
        config_info = []
        if args.interactive:
            config_info.append("📋 Interactive mode enabled")
        if args.recursive:
            config_info.append("📁 Recursive scanning")
        if args.follow_symlinks:
            config_info.append("🔗 Following symlinks")
        if args.skip_extensions:
            config_info.append(f"⏭️  Skipping: {', '.join(args.skip_extensions)}")
        if args.max_size:
            config_info.append(f"📏 Max file size: {args.max_size}MB")
        
        if config_info:
            print("⚙️  Configuration:")
            for info in config_info:
                print(f"   {info}")
        
        print()
    
    def _estimate_file_count(self, path: str, options: ScanOptions) -> int:
        """Estimate the number of files to be scanned."""
        try:
            if os.path.isfile(path):
                return 1
            
            file_count = 0
            path_obj = Path(path)
            
            if options.recursive:
                pattern = "**/*"
            else:
                pattern = "*"
            
            for file_path in path_obj.glob(pattern):
                if file_path.is_file():
                    # Check if we should skip this file
                    if self._should_skip_file_for_estimation(str(file_path), options):
                        continue
                    file_count += 1
            
            return file_count
            
        except Exception as e:
            logger.warning(f"Failed to estimate file count: {e}")
            return 0
    
    def _should_skip_file_for_estimation(self, file_path: str, options: ScanOptions) -> bool:
        """Check if a file should be skipped during estimation."""
        file_path_lower = file_path.lower()
        
        # Check skip extensions from command line
        for ext in options.skip_extensions:
            if file_path_lower.endswith(ext.lower()):
                return True
        
        # Check global skip extensions from config
        if self.config:
            for ext in self.config.skip_extensions:
                if file_path_lower.endswith(ext.lower()):
                    return True
        
        return False
    
    def _progress_callback(self, progress_info: Dict[str, Any]) -> None:
        """Callback for receiving progress updates from scan engine."""
        if self.progress_indicator:
            self.progress_indicator.update(
                current_item=progress_info.get('files_scanned', 0),
                current_file=progress_info.get('current_file', ''),
                detections=progress_info.get('detections_found', 0),
                errors=progress_info.get('errors_encountered', 0)
            )
    
    def _interactive_threat_decision(self, detection: Detection) -> ThreatAction:
        """Interactive callback for threat handling decisions."""
        from cli_utils import ThreatDisplayFormatter, InteractivePrompt
        
        print(f"\n{'='*70}")
        print("🚨 THREAT DETECTED")
        print(f"{'='*70}")
        
        # Display threat details
        print(ThreatDisplayFormatter.format_threat_details(detection))
        
        # Show educational information if available
        if self.educational_system:
            try:
                educational_info = self.educational_system.get_threat_explanation(
                    detection.threat_name, detection.detection_type.value
                )
                if educational_info:
                    print(f"\n📚 Educational Information:")
                    print(f"   {educational_info.get('description', 'No description available')}")
                    
                    if educational_info.get('detection_method'):
                        print(f"   Detection Method: {educational_info['detection_method']}")
                    
                    if educational_info.get('risk_factors'):
                        print(f"   Risk Factors: {', '.join(educational_info['risk_factors'])}")
            except Exception as e:
                logger.debug(f"Failed to get educational info: {e}")
        
        # Present action options
        options = [
            "Quarantine (move to secure isolation)",
            "Ignore (continue without action)",
            "Delete (permanently remove file)",
            "Skip (don't process this threat)"
        ]
        
        print(f"\n🤔 What would you like to do with this threat?")
        choice = InteractivePrompt.select_option("Choose an action:", options, default=0)
        
        action_map = {
            0: ThreatAction.QUARANTINE,
            1: ThreatAction.IGNORE,
            2: ThreatAction.DELETE,
            3: ThreatAction.SKIP
        }
        
        selected_action = action_map[choice]
        
        # Confirm destructive actions
        if selected_action == ThreatAction.DELETE:
            if not InteractivePrompt.confirm(
                f"⚠️  Are you sure you want to permanently delete '{detection.file_path}'?",
                default=False
            ):
                print("🔄 Switching to quarantine instead...")
                selected_action = ThreatAction.QUARANTINE
        
        print(f"✅ Action selected: {selected_action.value.upper()}")
        return selected_action
    
    def _display_enhanced_scan_results(self, scan_result: ScanResult, format_type: str) -> None:
        """Display scan results with enhanced formatting."""
        from cli_utils import ScanResultsFormatter
        
        if format_type == 'json':
            import json
            result_data = ScanResultsFormatter.format_json_output(scan_result)
            print(json.dumps(result_data, indent=2))
        elif format_type == 'csv':
            csv_output = ScanResultsFormatter.format_csv_output(scan_result)
            print(csv_output)
        else:  # text format
            detailed_output = ScanResultsFormatter.format_detailed_results(scan_result)
            print(detailed_output)
            
            # Show real-time threat handling summary if available
            if hasattr(scan_result, 'details') and scan_result.details:
                self._display_threat_handling_summary(scan_result.details)
    
    def _display_threat_handling_summary(self, details: Dict[str, Any]) -> None:
        """Display summary of threat handling actions taken."""
        if 'threat_decisions' not in details:
            return
        
        decisions = details['threat_decisions']
        if not decisions:
            return
        
        print(f"\n{'='*70}")
        print("🛡️  THREAT HANDLING SUMMARY")
        print(f"{'='*70}")
        
        # Count actions
        quarantined = details.get('quarantine_actions', 0)
        ignored = details.get('ignored_threats', 0)
        deleted = details.get('deleted_threats', 0)
        
        print(f"🔒 Quarantined: {quarantined}")
        print(f"👁️  Ignored: {ignored}")
        print(f"🗑️  Deleted: {deleted}")
        
        # Show recent decisions
        if len(decisions) > 0:
            print(f"\n📋 Recent Actions:")
            for decision in decisions[-5:]:  # Show last 5 decisions
                action_emoji = {
                    'quarantine': '🔒',
                    'ignore': '👁️',
                    'delete': '🗑️',
                    'skip': '⏭️'
                }.get(decision['action'], '❓')
                
                auto_text = " (auto)" if decision['auto_applied'] else ""
                print(f"   {action_emoji} {decision['action'].upper()}: {os.path.basename(decision['detection_id'])}{auto_text}")
    
    def _save_enhanced_scan_results(self, scan_result: ScanResult, output_path: str, format_type: str) -> None:
        """Save scan results to file with enhanced formatting."""
        from cli_utils import ScanResultsFormatter
        
        try:
            if format_type == 'json':
                import json
                result_data = ScanResultsFormatter.format_json_output(scan_result)
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(result_data, f, indent=2, ensure_ascii=False)
            
            elif format_type == 'csv':
                csv_output = ScanResultsFormatter.format_csv_output(scan_result)
                with open(output_path, 'w', encoding='utf-8', newline='') as f:
                    f.write(csv_output)
            
            else:  # text format
                detailed_output = ScanResultsFormatter.format_detailed_results(scan_result)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(detailed_output)
                    
                    # Add threat handling summary to text output
                    if hasattr(scan_result, 'details') and scan_result.details:
                        f.write(f"\n{'='*70}\n")
                        f.write("THREAT HANDLING SUMMARY\n")
                        f.write(f"{'='*70}\n")
                        
                        details = scan_result.details
                        f.write(f"Quarantined: {details.get('quarantine_actions', 0)}\n")
                        f.write(f"Ignored: {details.get('ignored_threats', 0)}\n")
                        f.write(f"Deleted: {details.get('deleted_threats', 0)}\n")
                        
                        if 'threat_decisions' in details:
                            f.write(f"\nDetailed Actions:\n")
                            for decision in details['threat_decisions']:
                                f.write(f"  {decision['action'].upper()}: {decision['detection_id']}")
                                if decision['auto_applied']:
                                    f.write(" (automatic)")
                                f.write(f" - {decision['reason']}\n")
            
        except Exception as e:
            logger.error(f"Failed to save scan results: {e}")
            raise
    
    def _show_scan_recommendations(self, scan_result: ScanResult) -> None:
        """Show recommendations based on scan results."""
        print(f"\n{'='*70}")
        print("💡 RECOMMENDATIONS")
        print(f"{'='*70}")
        
        if not scan_result.detections:
            print("✅ No threats detected! Your system appears clean.")
            print("💡 Consider running regular scans to maintain security.")
            return
        
        # Analyze threat patterns
        high_risk_count = len([d for d in scan_result.detections if d.risk_score >= 8])
        signature_count = len([d for d in scan_result.detections if d.detection_type.value == 'signature'])
        behavioral_count = len([d for d in scan_result.detections if d.detection_type.value == 'behavioral'])
        
        recommendations = []
        
        if high_risk_count > 0:
            recommendations.append(f"🔴 {high_risk_count} high-risk threat(s) found - immediate attention recommended")
        
        if signature_count > 0:
            recommendations.append(f"🎯 {signature_count} known signature(s) detected - update your signature database regularly")
        
        if behavioral_count > 0:
            recommendations.append(f"🧠 {behavioral_count} suspicious behavior(s) detected - consider manual analysis")
        
        if scan_result.errors:
            recommendations.append(f"⚠️  {len(scan_result.errors)} file(s) couldn't be scanned - check file permissions")
        
        # General recommendations
        recommendations.extend([
            "🔄 Run scans regularly to catch new threats",
            "📚 Review educational content to learn about detected threats",
            "🔒 Check quarantined files periodically and clean up old entries",
            "⚙️  Adjust detection sensitivity based on your security needs"
        ])
        
        for i, recommendation in enumerate(recommendations, 1):
            print(f"{i:2d}. {recommendation}")
        
        # Show next steps
        if scan_result.detections:
            print(f"\n🔧 Next Steps:")
            print(f"   • Review quarantined files: antivirus-cli quarantine list")
            print(f"   • Generate detailed report: antivirus-cli report generate <scan_results.json>")
            print(f"   • Learn about threats: Check educational content in reports")
    
    def _cleanup(self) -> None:
        """Clean up resources and stop any running operations."""
        if self.progress_indicator:
            self.progress_indicator.stop()
            self.progress_indicator = None
        
        # Remove progress callbacks
        if self.scanner and self.scanner.scan_engine:
            try:
                self.scanner.scan_engine.remove_progress_callback(self._progress_callback)
            except:
                pass  # Callback might not be registered
    
    def _create_argument_parser(self) -> argparse.ArgumentParser:
        """Create the main argument parser with all commands and options."""
        parser = argparse.ArgumentParser(
            prog='antivirus-cli',
            description='Educational Antivirus Research Tool - Command Line Interface',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s scan /path/to/scan                    # Scan a directory
  %(prog)s scan file.exe --interactive          # Scan with user prompts
  %(prog)s config show                          # Show current configuration
  %(prog)s config set signature_sensitivity 8   # Update configuration
  %(prog)s quarantine list                      # List quarantined files
  %(prog)s samples create eicar                 # Create EICAR test sample
  %(prog)s report generate scan_results.json    # Generate scan report
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
        
        # Scan command
        self._add_scan_command(subparsers)
        
        # Configuration commands
        self._add_config_commands(subparsers)
        
        # Quarantine commands
        self._add_quarantine_commands(subparsers)
        
        # Sample management commands
        self._add_sample_commands(subparsers)
        
        # Report commands
        self._add_report_commands(subparsers)
        
        # Help command
        self._add_help_command(subparsers)
        
        return parser
    
    def _add_scan_command(self, subparsers) -> None:
        """Add scan command and options."""
        scan_parser = subparsers.add_parser(
            'scan',
            help='Scan files or directories for threats',
            description='Scan files or directories using signature and behavioral detection'
        )
        
        scan_parser.add_argument(
            'path',
            help='Path to scan (file or directory)'
        )
        scan_parser.add_argument(
            '--recursive', '-r',
            action='store_true',
            help='Scan directories recursively'
        )
        scan_parser.add_argument(
            '--interactive', '-i',
            action='store_true',
            help='Interactive mode - prompt for threat handling decisions'
        )
        scan_parser.add_argument(
            '--output', '-o',
            help='Save scan results to file (JSON format)'
        )
        scan_parser.add_argument(
            '--format',
            choices=['json', 'csv', 'text'],
            default='text',
            help='Output format for results (default: text)'
        )
        scan_parser.add_argument(
            '--max-size',
            type=int,
            help='Maximum file size to scan in MB'
        )
        scan_parser.add_argument(
            '--skip-extensions',
            nargs='*',
            help='File extensions to skip (e.g., .log .tmp)'
        )
        scan_parser.add_argument(
            '--follow-symlinks',
            action='store_true',
            help='Follow symbolic links during scanning'
        )
        scan_parser.add_argument(
            '--no-quarantine',
            action='store_true',
            help='Disable automatic quarantine actions'
        )
        
        scan_parser.set_defaults(func=self._handle_scan_command)
    
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
        
        # Set config
        set_parser = config_subparsers.add_parser(
            'set',
            help='Set configuration value'
        )
        set_parser.add_argument(
            'setting',
            help='Setting name to modify'
        )
        set_parser.add_argument(
            'value',
            help='New value for the setting'
        )
        set_parser.set_defaults(func=self._handle_config_set)
        
        # Reset config
        reset_parser = config_subparsers.add_parser(
            'reset',
            help='Reset configuration to defaults'
        )
        reset_parser.add_argument(
            'setting',
            nargs='?',
            help='Specific setting to reset (optional, resets all if not specified)'
        )
        reset_parser.add_argument(
            '--confirm',
            action='store_true',
            help='Confirm the reset operation'
        )
        reset_parser.set_defaults(func=self._handle_config_reset)
        
        # Export config template
        export_parser = config_subparsers.add_parser(
            'export',
            help='Export configuration template'
        )
        export_parser.add_argument(
            'output_file',
            help='Output file path'
        )
        export_parser.add_argument(
            '--format',
            choices=['json', 'yaml'],
            default='yaml',
            help='Output format (default: yaml)'
        )
        export_parser.set_defaults(func=self._handle_config_export)
        
        config_parser.set_defaults(func=self._handle_config_command)
    
    def _add_quarantine_commands(self, subparsers) -> None:
        """Add quarantine management commands."""
        quarantine_parser = subparsers.add_parser(
            'quarantine',
            help='Manage quarantined files',
            description='List, restore, or delete quarantined files'
        )
        
        quarantine_subparsers = quarantine_parser.add_subparsers(
            dest='quarantine_action',
            help='Quarantine actions'
        )
        
        # List quarantined files
        list_parser = quarantine_subparsers.add_parser(
            'list',
            help='List quarantined files'
        )
        list_parser.add_argument(
            '--status',
            choices=['active', 'restored'],
            help='Filter by status'
        )
        list_parser.add_argument(
            '--type',
            choices=['signature', 'behavioral'],
            help='Filter by detection type'
        )
        list_parser.add_argument(
            '--limit',
            type=int,
            help='Maximum number of entries to show'
        )
        list_parser.set_defaults(func=self._handle_quarantine_list)
        
        # Show quarantine details
        show_parser = quarantine_subparsers.add_parser(
            'show',
            help='Show quarantine details'
        )
        show_parser.add_argument(
            'quarantine_id',
            help='Quarantine ID'
        )
        show_parser.set_defaults(func=self._handle_quarantine_show)
        
        # Restore file
        restore_parser = quarantine_subparsers.add_parser(
            'restore',
            help='Restore quarantined file'
        )
        restore_parser.add_argument(
            'quarantine_id',
            help='Quarantine ID'
        )
        restore_parser.add_argument(
            '--force',
            action='store_true',
            help='Force restoration without confirmation'
        )
        restore_parser.set_defaults(func=self._handle_quarantine_restore)
        
        # Delete quarantined file
        delete_parser = quarantine_subparsers.add_parser(
            'delete',
            help='Delete quarantined file permanently'
        )
        delete_parser.add_argument(
            'quarantine_id',
            help='Quarantine ID'
        )
        delete_parser.add_argument(
            '--force',
            action='store_true',
            help='Skip confirmation'
        )
        delete_parser.set_defaults(func=self._handle_quarantine_delete)
        
        # Quarantine statistics
        stats_parser = quarantine_subparsers.add_parser(
            'stats',
            help='Show quarantine statistics'
        )
        stats_parser.set_defaults(func=self._handle_quarantine_stats)
        
        quarantine_parser.set_defaults(func=self._handle_quarantine_command)
    
    def _add_sample_commands(self, subparsers) -> None:
        """Add sample management commands."""
        samples_parser = subparsers.add_parser(
            'samples',
            help='Manage test samples',
            description='Create and manage harmless test malware samples'
        )
        
        samples_subparsers = samples_parser.add_subparsers(
            dest='samples_action',
            help='Sample actions'
        )
        
        # Create sample
        create_parser = samples_subparsers.add_parser(
            'create',
            help='Create test sample'
        )
        create_parser.add_argument(
            'sample_type',
            choices=['eicar', 'custom_signature', 'behavioral_trigger'],
            help='Type of sample to create'
        )
        create_parser.add_argument(
            '--name',
            help='Custom name for the sample'
        )
        create_parser.add_argument(
            '--signature-name',
            help='Signature name (for custom_signature type)'
        )
        create_parser.add_argument(
            '--trigger-type',
            help='Trigger type (for behavioral_trigger type)'
        )
        create_parser.set_defaults(func=self._handle_samples_create)
        
        # List samples
        list_parser = samples_subparsers.add_parser(
            'list',
            help='List available samples'
        )
        list_parser.add_argument(
            '--type',
            help='Filter by sample type'
        )
        list_parser.set_defaults(func=self._handle_samples_list)
        
        # Show sample details
        show_parser = samples_subparsers.add_parser(
            'show',
            help='Show sample details'
        )
        show_parser.add_argument(
            'sample_id',
            help='Sample ID or name'
        )
        show_parser.set_defaults(func=self._handle_samples_show)
        
        # Delete sample
        delete_parser = samples_subparsers.add_parser(
            'delete',
            help='Delete test sample'
        )
        delete_parser.add_argument(
            'sample_id',
            help='Sample ID or name'
        )
        delete_parser.add_argument(
            '--confirm',
            action='store_true',
            help='Confirm deletion'
        )
        delete_parser.set_defaults(func=self._handle_samples_delete)
        
        samples_parser.set_defaults(func=self._handle_samples_command)
    
    def _add_report_commands(self, subparsers) -> None:
        """Add report generation commands."""
        report_parser = subparsers.add_parser(
            'report',
            help='Generate reports',
            description='Generate scan reports and educational content'
        )
        
        report_subparsers = report_parser.add_subparsers(
            dest='report_action',
            help='Report actions'
        )
        
        # Generate report
        generate_parser = report_subparsers.add_parser(
            'generate',
            help='Generate scan report'
        )
        generate_parser.add_argument(
            'scan_results',
            help='Path to scan results file (JSON)'
        )
        generate_parser.add_argument(
            '--format',
            choices=['json', 'csv', 'text', 'html'],
            default='text',
            help='Report format (default: text)'
        )
        generate_parser.add_argument(
            '--output',
            help='Output file path'
        )
        generate_parser.add_argument(
            '--educational',
            action='store_true',
            help='Include educational content'
        )
        generate_parser.set_defaults(func=self._handle_report_generate)
        
        report_parser.set_defaults(func=self._handle_report_command)
    
    def _add_help_command(self, subparsers) -> None:
        """Add help command."""
        help_parser = subparsers.add_parser(
            'help',
            help='Show help for commands'
        )
        help_parser.add_argument(
            'topic',
            nargs='?',
            help='Help topic or command'
        )
        help_parser.set_defaults(func=self._handle_help_command)    
    
# Command handlers
    def _handle_scan_command(self, args) -> int:
        """Handle scan command with enhanced progress and output."""
        try:
            # Validate path
            if not os.path.exists(args.path):
                print(f"❌ Error: Path does not exist: {args.path}")
                return 1
            
            # Create scan options
            scan_options = ScanOptions(
                recursive=args.recursive,
                follow_symlinks=args.follow_symlinks,
                skip_extensions=args.skip_extensions or []
            )
            
            # Update config with command line options
            if args.max_size:
                self.config.max_file_size_mb = args.max_size
            
            # Display scan start information with enhanced formatting
            self._display_scan_header(args)
            
            # Estimate total files for progress indicator
            total_files = self._estimate_file_count(args.path, scan_options)
            
            # Initialize progress indicator with enhanced features
            if not self.verbose:
                self.progress_indicator = ProgressIndicator(
                    total_items=total_files,
                    show_eta=True,
                    show_rate=True
                )
                self.progress_indicator.start()
                
                # Set up progress callback for real-time updates
                self.scanner.scan_engine.add_progress_callback(self._progress_callback)
            
            print(f"📊 Estimated files to scan: {total_files:,}")
            print("=" * 70)
            
            # Perform scan with enhanced progress tracking and user interaction
            if args.no_quarantine:
                scan_result = self.scanner.scan_engine.scan_path(args.path, scan_options)
            else:
                scan_result = self.scanner.scan_with_interaction(
                    args.path, 
                    scan_options, 
                    interactive=args.interactive
                )
            
            # Stop progress indicator
            if self.progress_indicator:
                self.progress_indicator.stop()
                self.progress_indicator = None
                self.scanner.scan_engine.remove_progress_callback(self._progress_callback)
            
            # Display results with enhanced formatting
            self._display_enhanced_scan_results(scan_result, args.format)
            
            # Save results if requested
            if args.output:
                self._save_enhanced_scan_results(scan_result, args.output, args.format)
                print(f"💾 Results saved to: {args.output}")
            
            # Show recommendations based on results
            self._show_scan_recommendations(scan_result)
            
            return 0
            
        except KeyboardInterrupt:
            if self.progress_indicator:
                self.progress_indicator.stop()
                self.progress_indicator = None
            print("\n\n⚠️  Scan cancelled by user.")
            return 130
        except Exception as e:
            if self.progress_indicator:
                self.progress_indicator.stop()
                self.progress_indicator = None
            print(f"❌ Scan failed: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return 1
    
    def _handle_config_command(self, args) -> int:
        """Handle config command without subcommand."""
        print("Configuration management commands:")
        print("  show    - Show current configuration")
        print("  set     - Set configuration value")
        print("  reset   - Reset configuration to defaults")
        print("  export  - Export configuration template")
        print("\nUse 'antivirus-cli config <command> --help' for more information")
        return 0
    
    def _handle_config_show(self, args) -> int:
        """Handle config show command."""
        try:
            if args.setting:
                # Show specific setting
                setting_info = self.config_manager.get_setting_info(args.setting)
                print(f"Setting: {setting_info['name']}")
                print(f"  Current value: {setting_info['current_value']}")
                print(f"  Default value: {setting_info['default_value']}")
                print(f"  Type: {setting_info['type']}")
                print(f"  Is default: {'Yes' if setting_info['is_default'] else 'No'}")
            else:
                # Show all settings
                settings = self.config_manager.list_all_settings()
                print("Current Configuration:")
                print("=" * 50)
                
                for name, info in settings.items():
                    status = " (default)" if info['is_default'] else " (modified)"
                    print(f"{name}: {info['current_value']}{status}")
            
            return 0
            
        except Exception as e:
            print(f"Error showing configuration: {e}")
            return 1
    
    def _handle_config_set(self, args) -> int:
        """Handle config set command."""
        try:
            # Parse value based on setting type
            setting_info = self.config_manager.get_setting_info(args.setting)
            value_type = setting_info['type']
            
            if value_type == 'bool':
                value = args.value.lower() in ('true', '1', 'yes', 'on')
            elif value_type == 'int':
                value = int(args.value)
            elif value_type == 'float':
                value = float(args.value)
            elif value_type == 'list':
                value = args.value.split(',') if args.value else []
            else:
                value = args.value
            
            # Update configuration
            self.config_manager.update_config(**{args.setting: value})
            print(f"Configuration updated: {args.setting} = {value}")
            
            return 0
            
        except Exception as e:
            print(f"Error setting configuration: {e}")
            return 1
    
    def _handle_config_reset(self, args) -> int:
        """Handle config reset command."""
        try:
            if not args.confirm:
                if args.setting:
                    print(f"This will reset '{args.setting}' to its default value.")
                else:
                    print("This will reset ALL configuration settings to their default values.")
                print("Use --confirm to proceed with the reset.")
                return 1
            
            if args.setting:
                # Reset specific setting
                self.config_manager.reset_setting_to_default(args.setting)
                print(f"Setting '{args.setting}' reset to default value")
            else:
                # Reset all settings
                self.config_manager.reset_to_defaults()
                self.config_manager.save_config()
                print("All configuration settings reset to default values")
            
            return 0
            
        except Exception as e:
            print(f"Error resetting configuration: {e}")
            return 1
    
    def _handle_config_export(self, args) -> int:
        """Handle config export command."""
        try:
            # Determine format from file extension if not specified
            if args.format == 'yaml' or args.output_file.endswith(('.yaml', '.yml')):
                format_type = 'yaml'
            else:
                format_type = 'json'
            
            # Export template
            self.config_manager.export_config_template(args.output_file, include_comments=True)
            print(f"Configuration template exported to: {args.output_file}")
            
            return 0
            
        except Exception as e:
            print(f"Error exporting configuration: {e}")
            return 1
    
    def _handle_quarantine_command(self, args) -> int:
        """Handle quarantine command without subcommand."""
        print("Quarantine management commands:")
        print("  list     - List quarantined files")
        print("  show     - Show quarantine details")
        print("  restore  - Restore quarantined file")
        print("  delete   - Delete quarantined file permanently")
        print("  stats    - Show quarantine statistics")
        print("\nUse 'antivirus-cli quarantine <command> --help' for more information")
        return 0
    
    def _handle_quarantine_list(self, args) -> int:
        """Handle quarantine list command."""
        try:
            entries = self.quarantine_interface.list_quarantined_files(
                status_filter=args.status,
                detection_type_filter=args.type,
                limit=args.limit
            )
            
            if not entries:
                print("No quarantined files found.")
                return 0
            
            print(f"Found {len(entries)} quarantined file(s):")
            print()
            
            for entry in entries:
                print(f"ID: {entry['quarantine_id']}")
                print(f"  File: {entry['filename']}")
                print(f"  Original Path: {entry['original_path']}")
                print(f"  Quarantined: {entry['quarantine_date']}")
                print(f"  Status: {entry['status']}")
                print(f"  Threat: {entry['threat_name']}")
                print(f"  Detection Type: {entry['detection_type']}")
                print(f"  Risk Score: {entry['risk_score']}")
                print(f"  Days Quarantined: {entry['days_quarantined']}")
                if entry['signature_id']:
                    print(f"  Signature ID: {entry['signature_id']}")
                print()
            
            return 0
            
        except Exception as e:
            print(f"Error listing quarantined files: {e}")
            return 1
    
    def _handle_quarantine_show(self, args) -> int:
        """Handle quarantine show command."""
        try:
            details = self.quarantine_interface.get_quarantine_details(args.quarantine_id)
            
            if not details:
                print("Quarantine entry not found.")
                return 1
            
            print("Quarantine Details:")
            print(f"  ID: {details['quarantine_id']}")
            print(f"  File: {details['filename']}")
            print(f"  Original Path: {details['original_path']}")
            print(f"  Quarantine Path: {details['quarantine_path']}")
            print(f"  Quarantined: {details['quarantine_date']}")
            print(f"  Status: {details['status']}")
            print(f"  Days Quarantined: {details['days_quarantined']}")
            print()
            
            print("File Information:")
            print(f"  File Size: {details['file_size']} bytes ({details['file_size_mb']} MB)")
            print(f"  File Status: {'✓ File exists' if details['file_exists'] else '✗ File missing'}")
            print()
            
            print("Detection Information:")
            detection = details['detection_info']
            print(f"  Threat Name: {detection['threat_name']}")
            print(f"  Detection Type: {detection['detection_type']}")
            print(f"  Risk Score: {detection['risk_score']}")
            print(f"  Detection Time: {detection['detection_timestamp']}")
            
            if detection['signature_id']:
                print(f"  Signature ID: {detection['signature_id']}")
            
            if detection['details']:
                print("  Additional Details:")
                for key, value in detection['details'].items():
                    print(f"    {key}: {value}")
            
            return 0
            
        except Exception as e:
            print(f"Error showing quarantine details: {e}")
            return 1
    
    def _handle_quarantine_restore(self, args) -> int:
        """Handle quarantine restore command."""
        try:
            # Create confirmation callback if not forcing
            confirm_callback = None if args.force else self._create_confirmation_callback()
            
            success, message = self.quarantine_interface.restore_quarantined_file(
                args.quarantine_id,
                force_overwrite=args.force,
                confirm_callback=confirm_callback
            )
            
            if success:
                print(f"✓ {message}")
                return 0
            else:
                print(f"✗ {message}")
                return 1
                
        except Exception as e:
            print(f"Error restoring file: {e}")
            return 1
    
    def _handle_quarantine_delete(self, args) -> int:
        """Handle quarantine delete command."""
        try:
            # Create confirmation callback if not forcing
            confirm_callback = None if args.force else self._create_confirmation_callback()
            
            success, message = self.quarantine_interface.delete_quarantined_file(
                args.quarantine_id,
                confirm_callback=confirm_callback
            )
            
            if success:
                print(f"✓ {message}")
                return 0
            else:
                print(f"✗ {message}")
                return 1
                
        except Exception as e:
            print(f"Error deleting quarantined file: {e}")
            return 1
    
    def _handle_quarantine_stats(self, args) -> int:
        """Handle quarantine stats command."""
        try:
            stats = self.quarantine_interface.get_quarantine_statistics()
            
            print("Quarantine Statistics:")
            print(f"  Total quarantined files: {stats.get('total_quarantined', 0)}")
            print(f"  Active quarantined files: {stats.get('active_quarantined', 0)}")
            print(f"  Restored files: {stats.get('restored_files', 0)}")
            print(f"  Signature detections: {stats.get('signature_detections', 0)}")
            print(f"  Behavioral detections: {stats.get('behavioral_detections', 0)}")
            print(f"  Quarantine path: {stats.get('quarantine_path', 'N/A')}")
            print(f"  Last updated: {stats.get('last_updated', 'N/A')}")
            
            # Show enhanced statistics if available
            if 'risk_analysis' in stats:
                print()
                print("Risk Analysis:")
                risk = stats['risk_analysis']
                print(f"  Average risk score: {risk['average_risk_score']}")
                print(f"  High risk files (≥8): {risk['high_risk_count']} ({risk['high_risk_percentage']}%)")
            
            if 'age_analysis' in stats:
                print()
                print("Age Analysis:")
                age = stats['age_analysis']
                print(f"  Average age: {age['average_days']} days")
                print(f"  Oldest file: {age['oldest_days']} days")
                print(f"  Newest file: {age['newest_days']} days")
            
            if 'threat_analysis' in stats:
                print()
                print("Threat Analysis:")
                threat = stats['threat_analysis']
                print(f"  Unique threats: {threat['unique_threats']}")
                print(f"  Total detections: {threat['total_detections']}")
            
            if 'error' in stats:
                print(f"  Error: {stats['error']}")
            
            return 0
            
        except Exception as e:
            print(f"Error getting quarantine statistics: {e}")
            return 1
    
    def _handle_samples_command(self, args) -> int:
        """Handle samples command without subcommand."""
        print("Sample management commands:")
        print("  create  - Create test sample")
        print("  list    - List available samples")
        print("  show    - Show sample details")
        print("  delete  - Delete test sample")
        print("\nUse 'antivirus-cli samples <command> --help' for more information")
        return 0
    
    def _handle_samples_create(self, args) -> int:
        """Handle samples create command."""
        try:
            # Import sample manager here to avoid circular imports
            from samples.sample_manager import SampleManager
            
            sample_manager = SampleManager(self.config.samples_path)
            
            # Prepare kwargs based on sample type
            kwargs = {}
            if args.sample_type == 'custom_signature' and args.signature_name:
                kwargs['signature_name'] = args.signature_name
            elif args.sample_type == 'behavioral_trigger' and args.trigger_type:
                kwargs['trigger_type'] = args.trigger_type
            
            # Create sample
            sample_info = sample_manager.create_test_sample(
                args.sample_type,
                name=args.name,
                **kwargs
            )
            
            print(f"✓ Test sample created successfully:")
            print(f"  Sample ID: {sample_info.sample_id}")
            print(f"  Name: {sample_info.name}")
            print(f"  Type: {sample_info.sample_type}")
            print(f"  File Path: {sample_info.file_path}")
            print(f"  Description: {sample_info.description}")
            
            return 0
            
        except Exception as e:
            print(f"Error creating sample: {e}")
            return 1
    
    def _handle_samples_list(self, args) -> int:
        """Handle samples list command."""
        try:
            from samples.sample_manager import SampleManager
            
            sample_manager = SampleManager(self.config.samples_path)
            samples = sample_manager.list_available_samples()
            
            if args.type:
                samples = [s for s in samples if s.sample_type == args.type]
            
            if not samples:
                print("No samples found.")
                return 0
            
            print(f"Found {len(samples)} sample(s):")
            print()
            
            for sample in samples:
                print(f"ID: {sample.sample_id}")
                print(f"  Name: {sample.name}")
                print(f"  Type: {sample.sample_type}")
                print(f"  Created: {sample.creation_date}")
                print(f"  File: {sample.file_path}")
                print(f"  Description: {sample.description}")
                if sample.signatures:
                    print(f"  Signatures: {', '.join(sample.signatures)}")
                print()
            
            return 0
            
        except Exception as e:
            print(f"Error listing samples: {e}")
            return 1
    
    def _handle_samples_show(self, args) -> int:
        """Handle samples show command."""
        try:
            from samples.sample_manager import SampleManager
            
            sample_manager = SampleManager(self.config.samples_path)
            
            # Try to get sample by ID first, then by name
            sample = sample_manager.get_sample_metadata(args.sample_id)
            if not sample:
                sample = sample_manager.get_sample_by_name(args.sample_id)
            
            if not sample:
                print("Sample not found.")
                return 1
            
            print("Sample Details:")
            print(f"  ID: {sample.sample_id}")
            print(f"  Name: {sample.name}")
            print(f"  Type: {sample.sample_type}")
            print(f"  Created: {sample.creation_date}")
            print(f"  File Path: {sample.file_path}")
            print(f"  Description: {sample.description}")
            
            if sample.signatures:
                print(f"  Signatures: {', '.join(sample.signatures)}")
            
            # Check if file exists
            if os.path.exists(sample.file_path):
                file_size = os.path.getsize(sample.file_path)
                print(f"  File Size: {file_size} bytes")
                print(f"  File Status: ✓ File exists")
            else:
                print(f"  File Status: ✗ File missing")
            
            return 0
            
        except Exception as e:
            print(f"Error showing sample details: {e}")
            return 1
    
    def _handle_samples_delete(self, args) -> int:
        """Handle samples delete command."""
        try:
            if not args.confirm:
                print("This will permanently delete the test sample.")
                print("Use --confirm to proceed with deletion.")
                return 1
            
            from samples.sample_manager import SampleManager
            
            sample_manager = SampleManager(self.config.samples_path)
            
            # Try to get sample by ID first, then by name
            sample = sample_manager.get_sample_metadata(args.sample_id)
            if not sample:
                sample = sample_manager.get_sample_by_name(args.sample_id)
            
            if not sample:
                print("Sample not found.")
                return 1
            
            # Delete sample
            success = sample_manager.delete_sample(sample.sample_id, confirm=True)
            
            if success:
                print(f"✓ Sample '{sample.name}' deleted successfully")
                return 0
            else:
                print(f"✗ Failed to delete sample")
                return 1
                
        except Exception as e:
            print(f"Error deleting sample: {e}")
            return 1
    
    def _handle_report_command(self, args) -> int:
        """Handle report command without subcommand."""
        print("Report generation commands:")
        print("  generate  - Generate scan report")
        print("\nUse 'antivirus-cli report <command> --help' for more information")
        return 0
    
    def _handle_report_generate(self, args) -> int:
        """Handle report generate command."""
        try:
            # Load scan results
            if not os.path.exists(args.scan_results):
                print(f"Error: Scan results file not found: {args.scan_results}")
                return 1
            
            with open(args.scan_results, 'r') as f:
                scan_data = json.load(f)
            
            # Generate report
            if args.educational:
                report_content = self.educational_system.generate_educational_report(scan_data)
            else:
                report_content = self.report_generator.generate_report(scan_data, args.format)
            
            # Output report
            if args.output:
                with open(args.output, 'w') as f:
                    if args.format == 'json':
                        json.dump(report_content, f, indent=2)
                    else:
                        f.write(str(report_content))
                print(f"Report generated: {args.output}")
            else:
                print(report_content)
            
            return 0
            
        except Exception as e:
            print(f"Error generating report: {e}")
            return 1
    
    def _handle_help_command(self, args) -> int:
        """Handle help command."""
        if args.topic:
            # Show help for specific topic
            help_topics = {
                'scan': self._show_scan_help,
                'config': self._show_config_help,
                'quarantine': self._show_quarantine_help,
                'samples': self._show_samples_help,
                'report': self._show_report_help
            }
            
            if args.topic in help_topics:
                help_topics[args.topic]()
            else:
                print(f"Unknown help topic: {args.topic}")
                print(f"Available topics: {', '.join(help_topics.keys())}")
                return 1
        else:
            # Show general help
            self._show_general_help()
        
        return 0    
 
   # Interactive functionality and utility methods
    def _interactive_threat_decision(self, detection) -> ThreatAction:
        """Enhanced interactive callback for threat handling decisions."""
        # Pause progress indicator if running
        if self.progress_indicator:
            self.progress_indicator.stop()
        
        print("\n" + "="*60)
        print("🚨 THREAT DETECTED")
        print("="*60)
        
        # Display threat details using enhanced formatter
        print(ThreatDisplayFormatter.format_threat_details(detection))
        
        # Show educational information about the threat
        self._show_threat_education(detection)
        
        # Present action options
        actions = [
            "Quarantine - Move file to quarantine for safe isolation",
            "Ignore - Leave file in place and continue scanning", 
            "Delete - Permanently delete the file",
            "Skip - Skip this file and continue scanning"
        ]
        
        # Get default action based on risk score
        if detection.risk_score >= 8:
            default_action = 0  # Quarantine for high risk
        elif detection.risk_score >= 5:
            default_action = 0  # Quarantine for medium risk
        else:
            default_action = 1  # Ignore for low risk
        
        print(f"\n🎯 Recommended action for risk level {detection.risk_score}/10: {actions[default_action].split(' - ')[0]}")
        
        try:
            choice = InteractivePrompt.select_option(
                "Choose action for this threat:",
                actions,
                default=default_action
            )
            
            action_map = [
                ThreatAction.QUARANTINE,
                ThreatAction.IGNORE,
                ThreatAction.DELETE,
                ThreatAction.SKIP
            ]
            
            selected_action = action_map[choice]
            
            # Confirm destructive actions
            if selected_action == ThreatAction.DELETE:
                if not InteractivePrompt.confirm(
                    "⚠️  Are you sure you want to permanently delete this file?",
                    default=False
                ):
                    print("Deletion cancelled. Defaulting to quarantine.")
                    selected_action = ThreatAction.QUARANTINE
            
            # Show action confirmation
            action_names = {
                ThreatAction.QUARANTINE: "🛡️  Quarantining",
                ThreatAction.IGNORE: "⏭️  Ignoring", 
                ThreatAction.DELETE: "🗑️  Deleting",
                ThreatAction.SKIP: "⏩ Skipping"
            }
            
            print(f"\n{action_names[selected_action]} file: {os.path.basename(detection.file_path)}")
            
            # Restart progress indicator if it was running
            if self.progress_indicator:
                self.progress_indicator.start()
            
            return selected_action
            
        except KeyboardInterrupt:
            print("\n⚠️  Operation cancelled by user. Skipping file.")
            if self.progress_indicator:
                self.progress_indicator.start()
            return ThreatAction.SKIP
    
    def _show_threat_education(self, detection) -> None:
        """Show educational information about the detected threat."""
        print(f"\n📚 Educational Information:")
        
        if detection.detection_type.value == 'signature':
            print("   🔍 Signature-based detection:")
            print("     • This file matches a known malware signature")
            print("     • Signatures are patterns that identify specific threats")
            print("     • This method is fast and accurate for known threats")
            
            if detection.signature_id:
                print(f"     • Matched signature: {detection.signature_id}")
                
        elif detection.detection_type.value == 'behavioral':
            print("   🧠 Behavioral analysis detection:")
            print("     • This file exhibits suspicious characteristics")
            print("     • Behavioral analysis looks at file properties and patterns")
            print("     • This method can detect unknown or modified threats")
            
            if detection.details:
                if 'entropy' in detection.details:
                    entropy = detection.details['entropy']
                    print(f"     • File entropy: {entropy:.2f} (high entropy may indicate encryption/packing)")
                
                if 'suspicious_patterns' in detection.details:
                    patterns = detection.details['suspicious_patterns']
                    if patterns:
                        print(f"     • Suspicious patterns found: {len(patterns)}")
        
        # Risk level explanation
        risk_level = ThreatDisplayFormatter._get_risk_level(detection.risk_score)
        print(f"\n⚖️  Risk Assessment: {risk_level} ({detection.risk_score}/10)")
        
        if detection.risk_score >= 8:
            print("     • High risk - Immediate action recommended")
            print("     • Likely to be malicious or highly suspicious")
        elif detection.risk_score >= 5:
            print("     • Medium risk - Caution advised")
            print("     • May be suspicious but requires further analysis")
        else:
            print("     • Low risk - Possibly a false positive")
            print("     • May be legitimate software with suspicious characteristics")
    
    def _progress_callback(self, progress_info: Dict[str, Any]) -> None:
        """Enhanced progress callback for scan operations."""
        if self.progress_indicator:
            # Update progress indicator
            self.progress_indicator.update(
                current_item=progress_info.get('files_scanned', 0),
                current_file=progress_info.get('current_file', ''),
                detections=progress_info.get('detections_found', 0),
                errors=progress_info.get('errors_encountered', 0)
            )
        elif self.verbose:
            # Detailed progress information for verbose mode
            current_file = progress_info.get('current_file', '')
            if current_file:
                print(f"🔍 Scanning: {current_file}")
            
            files_scanned = progress_info.get('files_scanned', 0)
            total_files = progress_info.get('total_files', 0)
            detections = progress_info.get('detections_found', 0)
            errors = progress_info.get('errors_encountered', 0)
            
            print(f"📊 Progress: {files_scanned}/{total_files} files")
            if detections > 0:
                print(f"🚨 Detections: {detections}")
            if errors > 0:
                print(f"❌ Errors: {errors}")
            
            if progress_info.get('estimated_remaining', 0) > 0:
                eta = progress_info['estimated_remaining']
                print(f"⏱️  ETA: {eta:.1f} seconds")
            print("-" * 50)
    
    def _create_confirmation_callback(self):
        """Create a confirmation callback for interactive operations."""
        def confirm_callback(message: str) -> bool:
            try:
                response = input(f"{message} [y/N]: ").strip().lower()
                return response in ('y', 'yes')
            except (KeyboardInterrupt, EOFError):
                return False
        
        return confirm_callback
    
    def _display_scan_results(self, scan_result, format_type: str) -> None:
        """Display scan results in the specified format."""
        if format_type == 'json':
            # Export as JSON
            report_data = self.scanner.export_scan_report(scan_result)
            print(json.dumps(report_data, indent=2))
            
        elif format_type == 'csv':
            # Display CSV-style output
            print("File Path,Threat Name,Detection Type,Risk Score,Signature ID")
            for detection in scan_result.detections:
                print(f"{detection.file_path},{detection.threat_name},"
                      f"{detection.detection_type.value},{detection.risk_score},"
                      f"{detection.signature_id or ''}")
                      
        else:
            # Text format (default)
            print("\n" + "="*60)
            print("SCAN RESULTS")
            print("="*60)
            
            print(f"Scan ID: {scan_result.scan_id}")
            print(f"Start Time: {scan_result.start_time}")
            print(f"End Time: {scan_result.end_time}")
            print(f"Status: {scan_result.status.value}")
            print(f"Scanned Paths: {', '.join(scan_result.scanned_paths)}")
            print(f"Total Files: {scan_result.total_files}")
            print(f"Detections Found: {len(scan_result.detections)}")
            print(f"Errors: {len(scan_result.errors)}")
            
            if scan_result.detections:
                print("\nDETECTIONS:")
                print("-" * 40)
                
                for i, detection in enumerate(scan_result.detections, 1):
                    print(f"{i}. {detection.file_path}")
                    print(f"   Threat: {detection.threat_name}")
                    print(f"   Type: {detection.detection_type.value}")
                    print(f"   Risk Score: {detection.risk_score}/10")
                    if detection.signature_id:
                        print(f"   Signature: {detection.signature_id}")
                    print(f"   Detected: {detection.timestamp}")
                    print()
            
            if scan_result.errors:
                print("ERRORS:")
                print("-" * 40)
                for error in scan_result.errors:
                    print(f"  • {error}")
                print()
            
            # Show threat handling summary if available
            if hasattr(scan_result, 'details') and scan_result.details:
                details = scan_result.details
                if 'threat_decisions' in details:
                    print("THREAT HANDLING SUMMARY:")
                    print("-" * 40)
                    print(f"  Quarantined: {details.get('quarantine_actions', 0)}")
                    print(f"  Ignored: {details.get('ignored_threats', 0)}")
                    print(f"  Deleted: {details.get('deleted_threats', 0)}")
                    print()
            
            # Show scan duration
            if scan_result.end_time:
                duration = scan_result.end_time - scan_result.start_time
                print(f"Scan Duration: {duration.total_seconds():.2f} seconds")
            
            print("="*60)
    
    def _save_scan_results(self, scan_result, output_path: str, format_type: str) -> None:
        """Save scan results to file."""
        try:
            if format_type == 'json':
                report_data = self.scanner.export_scan_report(scan_result)
                with open(output_path, 'w') as f:
                    json.dump(report_data, f, indent=2)
                    
            elif format_type == 'csv':
                import csv
                with open(output_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['File Path', 'Threat Name', 'Detection Type', 'Risk Score', 'Signature ID', 'Timestamp'])
                    
                    for detection in scan_result.detections:
                        writer.writerow([
                            detection.file_path,
                            detection.threat_name,
                            detection.detection_type.value,
                            detection.risk_score,
                            detection.signature_id or '',
                            detection.timestamp.isoformat()
                        ])
                        
            else:
                # Text format
                with open(output_path, 'w') as f:
                    # Redirect display output to file
                    import io
                    import contextlib
                    
                    string_buffer = io.StringIO()
                    with contextlib.redirect_stdout(string_buffer):
                        self._display_scan_results(scan_result, 'text')
                    
                    f.write(string_buffer.getvalue())
                    
        except Exception as e:
            raise CLIError(f"Failed to save scan results: {e}")
    
    def _estimate_file_count(self, path: str, scan_options: ScanOptions) -> int:
        """Estimate the number of files to be scanned."""
        try:
            if os.path.isfile(path):
                return 1
            
            file_count = 0
            path_obj = Path(path)
            
            if scan_options.recursive:
                pattern = "**/*"
            else:
                pattern = "*"
            
            for file_path in path_obj.glob(pattern):
                if file_path.is_file():
                    # Check if we should skip this file
                    if self._should_skip_file_estimation(str(file_path), scan_options):
                        continue
                    file_count += 1
            
            return file_count
            
        except Exception:
            # If estimation fails, return a reasonable default
            return 100
    
    def _should_skip_file_estimation(self, file_path: str, scan_options: ScanOptions) -> bool:
        """Check if a file should be skipped during estimation (simplified version)."""
        file_path_lower = file_path.lower()
        
        # Check skip extensions
        for ext in scan_options.skip_extensions:
            if file_path_lower.endswith(ext.lower()):
                return True
        
        # Check common skip extensions
        common_skip_extensions = ['.log', '.tmp', '.cache', '.pyc', '.pyo']
        for ext in common_skip_extensions:
            if file_path_lower.endswith(ext):
                return True
        
        return False
    
    def _display_enhanced_scan_results(self, scan_result, format_type: str) -> None:
        """Display scan results with enhanced formatting."""
        if format_type == 'json':
            # JSON format
            result_data = ScanResultsFormatter.format_json_output(scan_result)
            print(json.dumps(result_data, indent=2))
            
        elif format_type == 'csv':
            # CSV format
            csv_output = ScanResultsFormatter.format_csv_output(scan_result)
            print(csv_output)
            
        else:
            # Enhanced text format (default)
            if self.verbose:
                output = ScanResultsFormatter.format_detailed_results(scan_result)
            else:
                output = ScanResultsFormatter.format_summary(scan_result)
            
            print(output)
            
            # Show individual threats with enhanced formatting
            if scan_result.detections and not self.verbose:
                print(f"\n{'='*60}")
                print("THREATS FOUND")
                print(f"{'='*60}")
                
                for i, detection in enumerate(scan_result.detections, 1):
                    print(f"\n{i}. {ThreatDisplayFormatter.format_threat_summary(detection)}")
    
    def _save_enhanced_scan_results(self, scan_result, output_path: str, format_type: str) -> None:
        """Save scan results with enhanced formatting."""
        try:
            if format_type == 'json':
                result_data = ScanResultsFormatter.format_json_output(scan_result)
                with open(output_path, 'w') as f:
                    json.dump(result_data, f, indent=2)
                    
            elif format_type == 'csv':
                csv_output = ScanResultsFormatter.format_csv_output(scan_result)
                with open(output_path, 'w') as f:
                    f.write(csv_output)
                    
            else:
                # Text format
                detailed_output = ScanResultsFormatter.format_detailed_results(scan_result)
                with open(output_path, 'w') as f:
                    f.write(detailed_output)
                    
        except Exception as e:
            raise CLIError(f"Failed to save scan results: {e}")
    
    def _show_scan_recommendations(self, scan_result) -> None:
        """Show recommendations based on scan results."""
        if not scan_result.detections:
            print("\n✅ No threats detected. Your system appears clean!")
            return
        
        print(f"\n{'='*60}")
        print("RECOMMENDATIONS")
        print(f"{'='*60}")
        
        high_risk_count = len([d for d in scan_result.detections if d.risk_score >= 8])
        medium_risk_count = len([d for d in scan_result.detections if 5 <= d.risk_score < 8])
        
        if high_risk_count > 0:
            print(f"🔴 {high_risk_count} high-risk threat(s) detected!")
            print("   → Review quarantined files immediately")
            print("   → Consider running a full system scan")
            print("   → Update your antivirus signatures")
        
        if medium_risk_count > 0:
            print(f"🟡 {medium_risk_count} medium-risk threat(s) detected")
            print("   → Review detection details carefully")
            print("   → Consider additional analysis if needed")
        
        # Show quarantine recommendations
        if hasattr(scan_result, 'details') and scan_result.details:
            quarantined = scan_result.details.get('quarantine_actions', 0)
            if quarantined > 0:
                print(f"🛡️  {quarantined} file(s) have been quarantined")
                print("   → Use 'antivirus-cli quarantine list' to review")
                print("   → Use 'antivirus-cli quarantine restore <id>' to restore if needed")
        
        print("\n💡 Educational Note:")
        print("   This tool is for educational purposes. In a real environment,")
        print("   always verify detections and follow your organization's")
        print("   incident response procedures.")
    
    def _cleanup(self) -> None:
        """Cleanup resources."""
        try:
            if self.progress_indicator:
                self.progress_indicator.stop()
            if self.scanner:
                self.scanner.close()
        except Exception as e:
            logger.warning(f"Error during cleanup: {e}")
    
    # Help methods
    def _show_general_help(self) -> None:
        """Show general help information."""
        print("""
Educational Antivirus Research Tool - Command Line Interface

DESCRIPTION:
    This tool provides a comprehensive command-line interface for educational
    antivirus research, including file scanning, configuration management,
    quarantine operations, and test sample management.

COMMANDS:
    scan        Scan files or directories for threats
    config      Manage configuration settings
    quarantine  Manage quarantined files
    samples     Manage test samples
    report      Generate reports
    help        Show help information

GLOBAL OPTIONS:
    --config, -c    Path to configuration file
    --verbose, -v   Enable verbose output
    --version       Show version information

EXAMPLES:
    antivirus-cli scan /path/to/scan
    antivirus-cli scan file.exe --interactive
    antivirus-cli config show
    antivirus-cli quarantine list
    antivirus-cli samples create eicar

For detailed help on a specific command, use:
    antivirus-cli <command> --help
    antivirus-cli help <command>
        """)
    
    def _show_scan_help(self) -> None:
        """Show scan command help."""
        print("""
SCAN COMMAND HELP

USAGE:
    antivirus-cli scan <path> [options]

DESCRIPTION:
    Scan files or directories for threats using signature-based and behavioral
    detection engines. Supports interactive mode for threat handling decisions.

OPTIONS:
    --recursive, -r         Scan directories recursively
    --interactive, -i       Interactive mode - prompt for threat decisions
    --output, -o FILE       Save scan results to file
    --format FORMAT         Output format: json, csv, text (default: text)
    --max-size SIZE         Maximum file size to scan in MB
    --skip-extensions EXTS  File extensions to skip
    --follow-symlinks       Follow symbolic links
    --no-quarantine         Disable automatic quarantine actions

EXAMPLES:
    antivirus-cli scan /home/user/documents
    antivirus-cli scan file.exe --interactive
    antivirus-cli scan /tmp --recursive --output results.json --format json
    antivirus-cli scan . --skip-extensions .log .tmp --max-size 50
        """)
    
    def _show_config_help(self) -> None:
        """Show config command help."""
        print("""
CONFIG COMMAND HELP

USAGE:
    antivirus-cli config <action> [options]

ACTIONS:
    show [setting]          Show configuration (all or specific setting)
    set <setting> <value>   Set configuration value
    reset [setting]         Reset to defaults (all or specific setting)
    export <file>           Export configuration template

EXAMPLES:
    antivirus-cli config show
    antivirus-cli config show signature_sensitivity
    antivirus-cli config set behavioral_threshold 8
    antivirus-cli config reset signature_sensitivity --confirm
    antivirus-cli config export config_template.yaml
        """)
    
    def _show_quarantine_help(self) -> None:
        """Show quarantine command help."""
        print("""
QUARANTINE COMMAND HELP

USAGE:
    antivirus-cli quarantine <action> [options]

ACTIONS:
    list                    List quarantined files
    show <id>              Show quarantine details
    restore <id>           Restore quarantined file
    delete <id>            Delete quarantined file permanently
    stats                  Show quarantine statistics

OPTIONS:
    --status STATUS        Filter by status: active, restored
    --type TYPE           Filter by detection type: signature, behavioral
    --limit N             Maximum entries to show
    --force               Skip confirmation prompts

EXAMPLES:
    antivirus-cli quarantine list
    antivirus-cli quarantine list --status active --type signature
    antivirus-cli quarantine show abc123
    antivirus-cli quarantine restore abc123
    antivirus-cli quarantine delete abc123 --force
        """)
    
    def _show_samples_help(self) -> None:
        """Show samples command help."""
        print("""
SAMPLES COMMAND HELP

USAGE:
    antivirus-cli samples <action> [options]

ACTIONS:
    create <type>          Create test sample
    list                   List available samples
    show <id>             Show sample details
    delete <id>           Delete test sample

SAMPLE TYPES:
    eicar                 EICAR test string
    custom_signature      Custom signature test file
    behavioral_trigger    Behavioral analysis trigger file

OPTIONS:
    --name NAME           Custom name for sample
    --signature-name NAME Signature name (for custom_signature)
    --trigger-type TYPE   Trigger type (for behavioral_trigger)
    --type TYPE          Filter by sample type
    --confirm            Confirm deletion

EXAMPLES:
    antivirus-cli samples create eicar
    antivirus-cli samples create custom_signature --signature-name test_sig
    antivirus-cli samples list --type eicar
    antivirus-cli samples show sample_123
    antivirus-cli samples delete sample_123 --confirm
        """)
    
    def _show_report_help(self) -> None:
        """Show report command help."""
        print("""
REPORT COMMAND HELP

USAGE:
    antivirus-cli report <action> [options]

ACTIONS:
    generate <file>        Generate report from scan results

OPTIONS:
    --format FORMAT       Report format: json, csv, text, html
    --output FILE         Output file path
    --educational         Include educational content

EXAMPLES:
    antivirus-cli report generate scan_results.json
    antivirus-cli report generate results.json --format html --output report.html
    antivirus-cli report generate results.json --educational
        """)


def main():
    """Main entry point for the CLI."""
    cli = AntivirusCLI()
    exit_code = cli.run(sys.argv[1:])
    sys.exit(exit_code)


if __name__ == '__main__':
    main()