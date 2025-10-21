#!/usr/bin/env python3
"""
Test script for integrated scanning with quarantine functionality.

This script demonstrates the integrated scanning capabilities including:
- Detection engine coordination
- Automatic threat decision making
- Quarantine management
- User interaction for threat handling
"""
import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.scan_engine import ScanEngine, ThreatAction
from core.models import Config, ScanOptions, Detection
from core.logging_config import LoggingManager


def interactive_threat_handler(detection: Detection) -> ThreatAction:
    """Interactive threat decision handler for user input."""
    print(f"\n🚨 THREAT DETECTED:")
    print(f"   File: {detection.file_path}")
    print(f"   Threat: {detection.threat_name}")
    print(f"   Type: {detection.detection_type.value}")
    print(f"   Risk Score: {detection.risk_score}/10")
    
    if detection.signature_id:
        print(f"   Signature ID: {detection.signature_id}")
    
    print(f"\nWhat would you like to do?")
    print(f"   [Q] Quarantine (recommended)")
    print(f"   [I] Ignore")
    print(f"   [D] Delete permanently")
    print(f"   [S] Skip (no action)")
    
    while True:
        choice = input("Enter your choice (Q/I/D/S): ").upper().strip()
        
        if choice == 'Q':
            return ThreatAction.QUARANTINE
        elif choice == 'I':
            return ThreatAction.IGNORE
        elif choice == 'D':
            confirm = input("Are you sure you want to delete permanently? (yes/no): ").lower().strip()
            if confirm == 'yes':
                return ThreatAction.DELETE
            else:
                print("Delete cancelled. Please choose another option.")
        elif choice == 'S':
            return ThreatAction.SKIP
        else:
            print("Invalid choice. Please enter Q, I, D, or S.")


def test_automatic_scanning():
    """Test automatic scanning with default threat handling."""
    print("=== Testing Automatic Scanning ===")
    
    # Setup logging
    logging_manager = LoggingManager()
    logging_manager.setup_logging()
    
    # Create configuration
    config = Config()
    
    # Initialize scan engine
    with ScanEngine(config) as scanner:
        # Test with samples directory
        samples_path = "samples"
        if not os.path.exists(samples_path):
            print(f"Samples directory not found: {samples_path}")
            return
        
        print(f"Scanning {samples_path} with automatic threat handling...")
        
        # Perform scan with automatic decisions
        scan_result = scanner.scan_with_quarantine(
            samples_path, 
            interactive=False
        )
        
        # Display results
        print(f"\n📊 SCAN RESULTS:")
        print(f"   Files scanned: {scan_result.total_files}")
        print(f"   Threats detected: {len(scan_result.detections)}")
        print(f"   Errors: {len(scan_result.errors)}")
        print(f"   Status: {scan_result.status.value}")
        
        # Display threat handling results
        if hasattr(scan_result, 'details') and scan_result.details:
            details = scan_result.details
            print(f"\n🛡️  THREAT HANDLING:")
            print(f"   Quarantined: {details.get('quarantine_actions', 0)}")
            print(f"   Ignored: {details.get('ignored_threats', 0)}")
            print(f"   Deleted: {details.get('deleted_threats', 0)}")
        
        # Display quarantine summary
        quarantine_summary = scanner.get_quarantine_summary()
        if 'quarantine_stats' in quarantine_summary:
            stats = quarantine_summary['quarantine_stats']
            print(f"\n📦 QUARANTINE STATUS:")
            print(f"   Total quarantined: {stats.get('total_quarantined', 0)}")
            print(f"   Active quarantined: {stats.get('active_quarantined', 0)}")
            print(f"   Restored files: {stats.get('restored_files', 0)}")


def test_interactive_scanning():
    """Test interactive scanning with user decisions."""
    print("\n=== Testing Interactive Scanning ===")
    
    # Setup logging
    logging_manager = LoggingManager()
    logging_manager.setup_logging()
    
    # Create configuration
    config = Config()
    
    # Initialize scan engine
    with ScanEngine(config) as scanner:
        # Set interactive callback
        scanner.set_threat_decision_callback(interactive_threat_handler)
        
        # Test with samples directory
        samples_path = "samples"
        if not os.path.exists(samples_path):
            print(f"Samples directory not found: {samples_path}")
            return
        
        print(f"Scanning {samples_path} with interactive threat handling...")
        
        # Perform scan with interactive decisions
        scan_result = scanner.scan_with_quarantine(
            samples_path, 
            interactive=True
        )
        
        # Display results
        print(f"\n📊 SCAN RESULTS:")
        print(f"   Files scanned: {scan_result.total_files}")
        print(f"   Threats detected: {len(scan_result.detections)}")
        print(f"   Errors: {len(scan_result.errors)}")
        print(f"   Status: {scan_result.status.value}")


def test_quarantine_management():
    """Test quarantine management operations."""
    print("\n=== Testing Quarantine Management ===")
    
    # Setup logging
    logging_manager = LoggingManager()
    logging_manager.setup_logging()
    
    # Create configuration
    config = Config()
    
    # Initialize scan engine
    with ScanEngine(config) as scanner:
        # List quarantined files
        quarantined_files = scanner.list_quarantined_files()
        
        if not quarantined_files:
            print("No quarantined files found.")
            return
        
        print(f"Found {len(quarantined_files)} quarantined files:")
        
        for i, file_info in enumerate(quarantined_files, 1):
            print(f"\n{i}. {file_info['original_path']}")
            print(f"   Quarantine ID: {file_info['quarantine_id']}")
            print(f"   Threat: {file_info['threat_name']}")
            print(f"   Risk Score: {file_info['risk_score']}")
            print(f"   Quarantined: {file_info['quarantine_date']}")
            print(f"   Restored: {file_info['restored']}")
        
        # Ask user what to do
        print(f"\nQuarantine management options:")
        print(f"   [L] List decision history")
        print(f"   [S] Show quarantine summary")
        print(f"   [R] Restore a file")
        print(f"   [Q] Quit")
        
        while True:
            choice = input("Enter your choice (L/S/R/Q): ").upper().strip()
            
            if choice == 'L':
                # Show decision history
                decisions = scanner.get_decision_history(limit=10)
                print(f"\nRecent threat decisions:")
                for decision in decisions:
                    print(f"   {decision['file_path']} -> {decision['action']} ({decision['reason']})")
                break
            
            elif choice == 'S':
                # Show quarantine summary
                summary = scanner.get_quarantine_summary()
                print(f"\nQuarantine Summary:")
                if 'quarantine_stats' in summary:
                    stats = summary['quarantine_stats']
                    for key, value in stats.items():
                        print(f"   {key}: {value}")
                break
            
            elif choice == 'R':
                # Restore a file
                if quarantined_files:
                    try:
                        index = int(input(f"Enter file number to restore (1-{len(quarantined_files)}): ")) - 1
                        if 0 <= index < len(quarantined_files):
                            quarantine_id = quarantined_files[index]['quarantine_id']
                            success = scanner.restore_quarantined_file(quarantine_id)
                            if success:
                                print(f"File restored successfully!")
                            else:
                                print(f"Failed to restore file.")
                        else:
                            print("Invalid file number.")
                    except ValueError:
                        print("Please enter a valid number.")
                break
            
            elif choice == 'Q':
                break
            
            else:
                print("Invalid choice. Please enter L, S, R, or Q.")


def main():
    """Main test function."""
    print("🔍 Educational Antivirus - Integrated Scanning Test")
    print("=" * 50)
    
    # Check if we have test samples
    if not os.path.exists("samples"):
        print("⚠️  No samples directory found. Creating test samples...")
        # You could add sample creation here if needed
        print("Please run the sample generator first to create test files.")
        return
    
    try:
        # Test automatic scanning
        test_automatic_scanning()
        
        # Ask if user wants to test interactive mode
        print(f"\nWould you like to test interactive scanning? (y/n): ", end="")
        if input().lower().strip() == 'y':
            test_interactive_scanning()
        
        # Test quarantine management
        print(f"\nWould you like to test quarantine management? (y/n): ", end="")
        if input().lower().strip() == 'y':
            test_quarantine_management()
        
        print(f"\n✅ Testing completed successfully!")
        
    except KeyboardInterrupt:
        print(f"\n\n⚠️  Testing interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback