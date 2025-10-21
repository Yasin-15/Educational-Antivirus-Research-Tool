"""
Command-line interface for quarantine management operations.
"""
import argparse
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

from quarantine.quarantine_interface import QuarantineInterface, create_simple_confirmation_callback
from quarantine.quarantine_manager import QuarantineManager
from core.exceptions import QuarantineError, FileAccessError
from core.models import Detection, DetectionType


def list_quarantined_command(interface: QuarantineInterface, args) -> None:
    """Handle quarantined files listing command."""
    try:
        entries = interface.list_quarantined_files(
            status_filter=args.status_filter,
            detection_type_filter=args.detection_type,
            limit=args.limit if hasattr(args, 'limit') else None
        )
        
        if not entries:
            print("No quarantined files found.")
            return
        
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
            
    except Exception as e:
        print(f"Error: {e}")


def show_quarantine_command(interface: QuarantineInterface, args) -> None:
    """Handle quarantine details command."""
    try:
        details = interface.get_quarantine_details(args.quarantine_id)
        
        if not details:
            print("Quarantine entry not found.")
            return
        
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
            
    except Exception as e:
        print(f"Error: {e}")


def restore_file_command(interface: QuarantineInterface, args) -> None:
    """Handle file restoration command."""
    try:
        # Create confirmation callback if not forcing
        confirm_callback = None if args.force else create_simple_confirmation_callback()
        
        success, message = interface.restore_quarantined_file(
            args.quarantine_id,
            force_overwrite=args.force,
            confirm_callback=confirm_callback
        )
        
        if success:
            print(f"✓ {message}")
        else:
            print(f"✗ {message}")
            
    except Exception as e:
        print(f"Unexpected error: {e}")


def delete_quarantined_command(interface: QuarantineInterface, args) -> None:
    """Handle quarantined file deletion command."""
    try:
        # Create confirmation callback if not forcing
        confirm_callback = None if args.force else create_simple_confirmation_callback()
        
        success, message = interface.delete_quarantined_file(
            args.quarantine_id,
            confirm_callback=confirm_callback
        )
        
        if success:
            print(f"✓ {message}")
        else:
            print(f"✗ {message}")
            
    except Exception as e:
        print(f"Unexpected error: {e}")


def stats_command(interface: QuarantineInterface, args) -> None:
    """Handle quarantine statistics command."""
    try:
        stats = interface.get_quarantine_statistics()
        
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
            
    except Exception as e:
        print(f"Error: {e}")


def cleanup_command(interface: QuarantineInterface, args) -> None:
    """Handle quarantine cleanup command."""
    try:
        # Create confirmation callback if not forcing
        confirm_callback = None if args.force else create_simple_confirmation_callback()
        
        success, result = interface.cleanup_old_quarantine_files(
            days_old=args.days,
            confirm_callback=confirm_callback
        )
        
        if success:
            print(f"✓ Cleanup completed:")
            print(f"  Files removed: {result.get('removed_count', 0)}")
            if 'cutoff_date' in result:
                print(f"  Cutoff date: {result['cutoff_date']}")
            if 'message' in result:
                print(f"  {result['message']}")
            
            if 'errors' in result and result['errors']:
                print(f"  Errors encountered: {len(result['errors'])}")
                for error in result['errors']:
                    print(f"    - {error}")
        else:
            print(f"✗ Cleanup failed: {result.get('message', 'Unknown error')}")
                
    except Exception as e:
        print(f"Unexpected error: {e}")


def export_command(interface: QuarantineInterface, args) -> None:
    """Handle quarantine report export command."""
    try:
        success, result = interface.export_quarantine_report(
            output_path=args.output_file,
            include_statistics=True
        )
        
        if success:
            print(f"✓ Enhanced quarantine report exported to: {result}")
        else:
            print(f"✗ Export failed: {result}")
        
    except Exception as e:
        print(f"Unexpected error: {e}")


def quarantine_file_command(interface: QuarantineInterface, args) -> None:
    """Handle manual file quarantine command (for testing)."""
    try:
        # Create a mock detection for manual quarantine
        detection = Detection(
            file_path=args.file_path,
            detection_type=DetectionType.SIGNATURE if args.detection_type == 'signature' else DetectionType.BEHAVIORAL,
            threat_name=args.threat_name or "Manual Quarantine",
            risk_score=args.risk_score or 5,
            signature_id=args.signature_id,
            details={'manual_quarantine': True, 'reason': args.reason or 'Manual quarantine via CLI'}
        )
        
        quarantine_id = interface.manager.quarantine_file(args.file_path, detection)
        print(f"✓ File quarantined successfully:")
        print(f"  Quarantine ID: {quarantine_id}")
        print(f"  Original Path: {args.file_path}")
        print(f"  Threat: {detection.threat_name}")
        
    except (QuarantineError, FileAccessError) as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


def validate_command(interface: QuarantineInterface, args) -> None:
    """Handle quarantine validation command."""
    try:
        print("Validating quarantine integrity...")
        validation = interface.validate_quarantine_integrity()
        
        print(f"✓ Validation completed:")
        print(f"  Total entries: {validation['total_entries']}")
        print(f"  Valid entries: {validation['valid_entries']}")
        print(f"  Issues found: {'Yes' if validation['issues_found'] else 'No'}")
        
        if validation.get('missing_files'):
            print(f"\n  Missing files ({len(validation['missing_files'])}):")
            for missing in validation['missing_files']:
                print(f"    - {missing['quarantine_id']}: {missing['original_path']}")
        
        if validation.get('corrupted_entries'):
            print(f"\n  Corrupted entries ({len(validation['corrupted_entries'])}):")
            for corrupted in validation['corrupted_entries']:
                print(f"    - {corrupted['quarantine_id']}: {corrupted['error']}")
        
        if validation.get('orphaned_files'):
            print(f"\n  Orphaned files ({len(validation['orphaned_files'])}):")
            for orphaned in validation['orphaned_files']:
                print(f"    - {orphaned}")
        
        if not validation['issues_found']:
            print("\n✓ Quarantine system is healthy!")
        
    except Exception as e:
        print(f"Validation failed: {e}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Educational Antivirus Quarantine Management Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--quarantine-path',
        default='quarantine/',
        help='Path to quarantine directory (default: quarantine/)'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List quarantined files')
    list_parser.add_argument('--status', dest='status_filter', choices=['active', 'restored'], 
                           help='Filter by status')
    list_parser.add_argument('--type', dest='detection_type', choices=['signature', 'behavioral'], 
                           help='Filter by detection type')
    list_parser.add_argument('--limit', type=int, help='Maximum number of entries to show')
    
    # Show command
    show_parser = subparsers.add_parser('show', help='Show quarantine details')
    show_parser.add_argument('quarantine_id', help='Quarantine ID')
    
    # Restore command
    restore_parser = subparsers.add_parser('restore', help='Restore quarantined file')
    restore_parser.add_argument('quarantine_id', help='Quarantine ID')
    restore_parser.add_argument('--force', action='store_true', help='Force restoration without confirmation')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete quarantined file permanently')
    delete_parser.add_argument('quarantine_id', help='Quarantine ID')
    delete_parser.add_argument('--force', action='store_true', help='Skip confirmation')
    
    # Stats command
    subparsers.add_parser('stats', help='Show quarantine statistics')
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up old quarantined files')
    cleanup_parser.add_argument('--days', type=int, default=30, 
                              help='Remove files older than this many days (default: 30)')
    cleanup_parser.add_argument('--force', action='store_true', help='Skip confirmation')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export quarantine report')
    export_parser.add_argument('output_file', nargs='?', help='Output file path (optional)')
    
    # Quarantine command (for manual testing)
    quarantine_parser = subparsers.add_parser('quarantine', help='Manually quarantine a file (for testing)')
    quarantine_parser.add_argument('file_path', help='Path to file to quarantine')
    quarantine_parser.add_argument('--threat-name', help='Threat name (default: Manual Quarantine)')
    quarantine_parser.add_argument('--detection-type', choices=['signature', 'behavioral'], 
                                 default='signature', help='Detection type')
    quarantine_parser.add_argument('--risk-score', type=int, help='Risk score (1-10)')
    quarantine_parser.add_argument('--signature-id', help='Signature ID (for signature detection)')
    quarantine_parser.add_argument('--reason', help='Reason for quarantine')
    
    # Validate command
    subparsers.add_parser('validate', help='Validate quarantine system integrity')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize quarantine interface
    try:
        interface = QuarantineInterface(args.quarantine_path)
    except Exception as e:
        print(f"Error initializing quarantine interface: {e}")
        return
    
    # Execute command
    command_handlers = {
        'list': list_quarantined_command,
        'show': show_quarantine_command,
        'restore': restore_file_command,
        'delete': delete_quarantined_command,
        'stats': stats_command,
        'cleanup': cleanup_command,
        'export': export_command,
        'quarantine': quarantine_file_command,
        'validate': validate_command,
    }
    
    handler = command_handlers.get(args.command)
    if handler:
        handler(interface, args)
    else:
        print(f"Unknown command: {args.command}")


if __name__ == '__main__':
    main()