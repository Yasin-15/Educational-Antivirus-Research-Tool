#!/usr/bin/env python3
"""
Comprehensive usage examples for the Educational Antivirus Research Tool.

This module provides practical examples of how to use the antivirus tool
for various educational and research scenarios.
"""
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class UsageExampleManager:
    """Manages and demonstrates usage examples."""
    
    def __init__(self):
        """Initialize the usage example manager."""
        self.examples = {
            'basic_setup': self._example_basic_setup,
            'sample_creation': self._example_sample_creation,
            'scanning_operations': self._example_scanning_operations,
            'configuration_management': self._example_configuration_management,
            'quarantine_operations': self._example_quarantine_operations,
            'report_generation': self._example_report_generation,
            'educational_workflows': self._example_educational_workflows,
            'research_scenarios': self._example_research_scenarios
        }
    
    def show_all_examples(self) -> None:
        """Show all available usage examples."""
        print("📚 Educational Antivirus Tool - Usage Examples")
        print("=" * 55)
        print()
        
        for i, (example_id, example_func) in enumerate(self.examples.items(), 1):
            title = example_id.replace('_', ' ').title()
            print(f"{i}. {title}")
            print("-" * len(f"{i}. {title}"))
            example_func()
            print()
            if i < len(self.examples):
                input("Press Enter to continue to next example...")
                print()
    
    def show_example(self, example_id: str) -> None:
        """Show a specific usage example.
        
        Args:
            example_id: ID of the example to show
        """
        if example_id in self.examples:
            title = example_id.replace('_', ' ').title()
            print(f"📖 {title}")
            print("=" * (len(title) + 4))
            print()
            self.examples[example_id]()
        else:
            print(f"Example '{example_id}' not found.")
            print(f"Available examples: {', '.join(self.examples.keys())}")
    
    def _example_basic_setup(self) -> None:
        """Show basic setup example."""
        print("Getting started with the Educational Antivirus Tool:")
        print()
        
        print("1. First-time setup:")
        print("   # Install dependencies")
        print("   pip install -r requirements.txt")
        print()
        print("   # Initialize sample databases")
        print("   python main.py init-samples")
        print()
        
        print("2. Verify installation:")
        print("   # Check configuration")
        print("   python main.py config show")
        print()
        print("   # Validate databases")
        print("   python main.py init-samples --validate-only")
        print()
        
        print("3. Run first educational workflow:")
        print("   python main.py examples beginner")
        print()
        
        print("Expected output:")
        print("✓ Sample databases initialized successfully")
        print("✓ Configuration loaded and validated")
        print("✓ Educational workflows ready to run")
    
    def _example_sample_creation(self) -> None:
        """Show sample creation examples."""
        print("Creating and managing test samples:")
        print()
        
        print("1. Create EICAR test file:")
        print("   from samples.sample_manager import SampleManager")
        print("   manager = SampleManager()")
        print("   sample = manager.create_test_sample('eicar', 'my_eicar.txt')")
        print()
        
        print("2. Create custom signature sample:")
        print("   sample = manager.create_test_sample(")
        print("       'custom_signature',")
        print("       'test_virus.txt',")
        print("       signature_name='TestVirus-A'")
        print("   )")
        print()
        
        print("3. Create behavioral trigger sample:")
        print("   sample = manager.create_test_sample(")
        print("       'behavioral_trigger',")
        print("       'high_entropy_test.bin',")
        print("       trigger_type='high_entropy'")
        print("   )")
        print()
        
        print("4. List all samples:")
        print("   samples = manager.list_available_samples()")
        print("   for sample in samples:")
        print("       print(f'{sample.name}: {sample.description}')")
        print()
        
        print("Sample types available:")
        print("• eicar: Standard antivirus test files")
        print("• custom_signature: Files with specific malware patterns")
        print("• behavioral_trigger: Files designed to trigger heuristics")
    
    def _example_scanning_operations(self) -> None:
        """Show scanning operation examples."""
        print("Scanning files and directories:")
        print()
        
        print("1. Basic directory scan:")
        print("   python main.py scan /path/to/directory")
        print()
        
        print("2. Scan with specific options:")
        print("   python main.py scan /path/to/directory \\")
        print("       --recursive \\")
        print("       --max-size 50 \\")
        print("       --output scan_results.json")
        print()
        
        print("3. Scan test samples:")
        print("   python main.py scan samples/")
        print()
        
        print("4. Programmatic scanning:")
        print("   from detection.scan_engine import ScanEngine")
        print("   from core.config import ConfigManager")
        print()
        print("   config = ConfigManager().get_config()")
        print("   scanner = ScanEngine(config)")
        print("   results = scanner.scan_directory('/path/to/scan')")
        print()
        
        print("Scan output includes:")
        print("• File analysis results")
        print("• Threat detection details")
        print("• Risk assessment scores")
        print("• Educational explanations")
        print("• Recommended actions")
    
    def _example_configuration_management(self) -> None:
        """Show configuration management examples."""
        print("Managing configuration settings:")
        print()
        
        print("1. View current configuration:")
        print("   python main.py config show")
        print()
        
        print("2. View specific setting:")
        print("   python main.py config show signature_sensitivity")
        print()
        
        print("3. Programmatic configuration:")
        print("   from core.config import ConfigManager")
        print()
        print("   manager = ConfigManager()")
        print("   config = manager.get_config()")
        print("   print(f'Sensitivity: {config.signature_sensitivity}')")
        print()
        
        print("4. Modify configuration file (config.json):")
        print("   {")
        print('     "signature_sensitivity": 8,')
        print('     "behavioral_threshold": 7,')
        print('     "entropy_threshold": 6.5,')
        print('     "max_file_size_mb": 100')
        print("   }")
        print()
        
        print("Key configuration parameters:")
        print("• signature_sensitivity: Detection sensitivity (1-10)")
        print("• behavioral_threshold: Behavioral analysis threshold")
        print("• entropy_threshold: File entropy threshold")
        print("• max_file_size_mb: Maximum file size to scan")
        print("• quarantine_path: Quarantine directory location")
    
    def _example_quarantine_operations(self) -> None:
        """Show quarantine operation examples."""
        print("Managing quarantined files:")
        print()
        
        print("1. List quarantined files:")
        print("   from quarantine.quarantine_manager import QuarantineManager")
        print()
        print("   manager = QuarantineManager()")
        print("   quarantined = manager.list_quarantined_files()")
        print("   for item in quarantined:")
        print("       print(f'{item.original_path} -> {item.quarantine_path}')")
        print()
        
        print("2. Quarantine a file:")
        print("   result = manager.quarantine_file(")
        print("       '/path/to/suspicious/file.exe',")
        print("       'Detected malware signature'")
        print("   )")
        print()
        
        print("3. Restore a false positive:")
        print("   success = manager.restore_file('quarantine_id')")
        print("   if success:")
        print("       print('File restored successfully')")
        print()
        
        print("4. Permanently delete threat:")
        print("   success = manager.delete_quarantined_file(")
        print("       'quarantine_id',")
        print("       confirm=True")
        print("   )")
        print()
        
        print("Quarantine features:")
        print("• Secure file isolation")
        print("• Metadata preservation")
        print("• Restoration capabilities")
        print("• Audit trail logging")
    
    def _example_report_generation(self) -> None:
        """Show report generation examples."""
        print("Generating and analyzing reports:")
        print()
        
        print("1. Generate scan report:")
        print("   from reporting.report_generator import ReportGenerator")
        print()
        print("   generator = ReportGenerator()")
        print("   report = generator.generate_scan_report(scan_results)")
        print("   generator.save_report(report, 'scan_report.json')")
        print()
        
        print("2. Generate educational report:")
        print("   educational_report = generator.generate_educational_report(")
        print("       scan_results,")
        print("       include_explanations=True")
        print("   )")
        print()
        
        print("3. Export to different formats:")
        print("   # JSON format")
        print("   generator.save_report(report, 'report.json', format='json')")
        print()
        print("   # CSV format")
        print("   generator.save_report(report, 'report.csv', format='csv')")
        print()
        print("   # Text format")
        print("   generator.save_report(report, 'report.txt', format='text')")
        print()
        
        print("4. Command-line report generation:")
        print("   python main.py scan /path --output report.json")
        print("   python main.py scan /path --format csv --output report.csv")
        print()
        
        print("Report contents:")
        print("• Scan summary and statistics")
        print("• Detailed threat analysis")
        print("• Educational explanations")
        print("• Risk assessments")
        print("• Recommended actions")
    
    def _example_educational_workflows(self) -> None:
        """Show educational workflow examples."""
        print("Running educational workflows:")
        print()
        
        print("1. Beginner workflow:")
        print("   python main.py examples beginner")
        print("   # Covers basic malware detection concepts")
        print()
        
        print("2. Intermediate workflow:")
        print("   python main.py examples intermediate")
        print("   # Advanced analysis techniques")
        print()
        
        print("3. Advanced workflow:")
        print("   python main.py examples advanced")
        print("   # Research-level topics")
        print()
        
        print("4. Scanning scenarios:")
        print("   python main.py examples scenarios")
        print("   # Hands-on scanning demonstrations")
        print()
        
        print("5. Interactive help system:")
        print("   python main.py help-system")
        print("   # Comprehensive help with examples")
        print()
        
        print("6. Programmatic workflow execution:")
        print("   from examples.educational_workflows import EducationalWorkflowManager")
        print()
        print("   manager = EducationalWorkflowManager()")
        print("   manager.run_beginner_workflow()")
        print()
        
        print("Workflow features:")
        print("• Step-by-step guided learning")
        print("• Interactive demonstrations")
        print("• Comprehensive explanations")
        print("• Hands-on practice")
    
    def _example_research_scenarios(self) -> None:
        """Show research scenario examples."""
        print("Research and analysis scenarios:")
        print()
        
        print("1. Malware family analysis:")
        print("   # Create samples representing different malware families")
        print("   families = ['TestVirus-A', 'TestTrojan-X', 'TestWorm-Y']")
        print("   for family in families:")
        print("       sample = manager.create_test_sample(")
        print("           'custom_signature',")
        print("           f'{family.lower()}_sample.txt',")
        print("           signature_name=family")
        print("       )")
        print()
        
        print("2. Detection effectiveness testing:")
        print("   # Test different sensitivity settings")
        print("   sensitivities = [3, 5, 7, 9]")
        print("   for sensitivity in sensitivities:")
        print("       config.signature_sensitivity = sensitivity")
        print("       results = scanner.scan_directory('samples/')")
        print("       analyze_detection_rate(results)")
        print()
        
        print("3. False positive analysis:")
        print("   # Scan known clean files")
        print("   clean_files = ['/path/to/clean/files']")
        print("   results = scanner.scan_files(clean_files)")
        print("   false_positives = [r for r in results if r.threat_detected]")
        print()
        
        print("4. Behavioral analysis research:")
        print("   # Create files with different entropy levels")
        print("   entropy_levels = ['low', 'medium', 'high']")
        print("   for level in entropy_levels:")
        print("       sample = create_entropy_sample(level)")
        print("       analyze_behavioral_detection(sample)")
        print()
        
        print("Research applications:")
        print("• Detection algorithm evaluation")
        print("• False positive rate analysis")
        print("• Malware classification studies")
        print("• Educational content development")


def main():
    """Main function for running usage examples."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Educational Antivirus Tool - Usage Examples",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'example',
        nargs='?',
        choices=list(UsageExampleManager().examples.keys()) + ['all'],
        default='all',
        help='Specific example to show (default: all)'
    )
    
    args = parser.parse_args()
    
    try:
        manager = UsageExampleManager()
        
        if args.example == 'all':
            manager.show_all_examples()
        else:
            manager.show_example(args.example)
            
    except KeyboardInterrupt:
        print("\n\nExamples interrupted by user.")
    except Exception as e:
        print(f"Error showing examples: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())