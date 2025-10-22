"""
Command-line interface for sample management operations.
"""
import argparse
import sys
from pathlib import Path
from typing import Optional

from samples.sample_manager import SampleManager, SampleManagerError


def create_sample_command(manager: SampleManager, args) -> None:
    """Handle sample creation command."""
    try:
        kwargs = {}
        
        if args.sample_type == 'custom_signature':
            if not args.signature_name:
                print("Error: --signature-name required for custom_signature type")
                return
            kwargs['signature_name'] = args.signature_name
            
        elif args.sample_type == 'behavioral_trigger':
            if not args.trigger_type:
                print("Error: --trigger-type required for behavioral_trigger type")
                return
            kwargs['trigger_type'] = args.trigger_type
        
        sample_info = manager.create_test_sample(
            sample_type=args.sample_type,
            name=args.name,
            **kwargs
        )
        
        print(f"✓ Created sample: {sample_info.name}")
        print(f"  ID: {sample_info.sample_id}")
        print(f"  Type: {sample_info.sample_type}")
        print(f"  Path: {sample_info.file_path}")
        print(f"  Description: {sample_info.description}")
        
    except SampleManagerError as e:
        print(f"Error: {e}")


def list_samples_command(manager: SampleManager, args) -> None:
    """Handle sample listing command."""
    try:
        samples = manager.list_available_samples()
        
        if not samples:
            print("No samples found.")
            return
        
        if args.type_filter:
            samples = [s for s in samples if s.sample_type == args.type_filter]
        
        print(f"Found {len(samples)} sample(s):")
        print()
        
        for sample in samples:
            print(f"Name: {sample.name}")
            print(f"  ID: {sample.sample_id}")
            print(f"  Type: {sample.sample_type}")
            print(f"  Created: {sample.creation_date.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Path: {sample.file_path}")
            print(f"  Description: {sample.description}")
            if sample.signatures:
                print(f"  Signatures: {', '.join(sample.signatures)}")
            print()
            
    except SampleManagerError as e:
        print(f"Error: {e}")


def show_sample_command(manager: SampleManager, args) -> None:
    """Handle sample details command."""
    try:
        sample = None
        
        if args.sample_id:
            sample = manager.get_sample_metadata(args.sample_id)
        elif args.name:
            sample = manager.get_sample_by_name(args.name)
        else:
            print("Error: Either --id or --name must be specified")
            return
        
        if not sample:
            print("Sample not found.")
            return
        
        print("Sample Details:")
        print(f"  Name: {sample.name}")
        print(f"  ID: {sample.sample_id}")
        print(f"  Type: {sample.sample_type}")
        print(f"  Created: {sample.creation_date.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  File Path: {sample.file_path}")
        print(f"  Description: {sample.description}")
        
        if sample.signatures:
            print(f"  Signatures: {', '.join(sample.signatures)}")
        
        # Check if file exists
        file_path = Path(sample.file_path)
        if file_path.exists():
            print(f"  File Size: {file_path.stat().st_size} bytes")
            print("  Status: ✓ File exists")
        else:
            print("  Status: ✗ File missing")
            
    except SampleManagerError as e:
        print(f"Error: {e}")


def delete_sample_command(manager: SampleManager, args) -> None:
    """Handle sample deletion command."""
    try:
        sample = None
        
        if args.sample_id:
            sample = manager.get_sample_metadata(args.sample_id)
        elif args.name:
            sample = manager.get_sample_by_name(args.name)
        else:
            print("Error: Either --id or --name must be specified")
            return
        
        if not sample:
            print("Sample not found.")
            return
        
        if not args.force:
            response = input(f"Delete sample '{sample.name}' (y/N)? ")
            if response.lower() != 'y':
                print("Deletion cancelled.")
                return
        
        success = manager.delete_sample(sample.sample_id, confirm=True)
        if success:
            print(f"✓ Deleted sample: {sample.name}")
        else:
            print("Failed to delete sample.")
            
    except SampleManagerError as e:
        print(f"Error: {e}")


def stats_command(manager: SampleManager, args) -> None:
    """Handle statistics command."""
    try:
        stats = manager.get_sample_statistics()
        validation = manager.validate_samples()
        
        print("Sample Statistics:")
        print(f"  Total samples: {stats.get('total', 0)}")
        
        for sample_type, count in stats.items():
            if sample_type != 'total':
                print(f"  {sample_type}: {count}")
        
        print()
        print("Validation Results:")
        print(f"  Valid samples: {len(validation['valid'])}")
        print(f"  Missing files: {len(validation['missing_files'])}")
        print(f"  Corrupted metadata: {len(validation['corrupted_metadata'])}")
        
        if validation['missing_files']:
            print(f"  Missing file IDs: {', '.join(validation['missing_files'])}")
        
        if validation['corrupted_metadata']:
            print(f"  Corrupted metadata IDs: {', '.join(validation['corrupted_metadata'])}")
            
    except SampleManagerError as e:
        print(f"Error: {e}")


def cleanup_command(manager: SampleManager, args) -> None:
    """Handle cleanup command."""
    try:
        cleaned_files = manager.cleanup_orphaned_files()
        
        if cleaned_files:
            print(f"✓ Cleaned up {len(cleaned_files)} orphaned file(s):")
            for file_path in cleaned_files:
                print(f"  - {file_path}")
        else:
            print("No orphaned files found.")
            
    except SampleManagerError as e:
        print(f"Error: {e}")


def export_command(manager: SampleManager, args) -> None:
    """Handle export command."""
    try:
        success = manager.export_sample_list(args.output_file, args.format)
        if success:
            print(f"✓ Exported sample list to: {args.output_file}")
        else:
            print("Export failed.")
            
    except SampleManagerError as e:
        print(f"Error: {e}")


def list_types_command(manager: SampleManager, args) -> None:
    """Handle list types command."""
    print("Available Sample Types:")
    print()
    
    print("1. eicar")
    print("   - EICAR standard antivirus test file")
    print()
    
    print("2. custom_signature")
    print("   - Files with embedded custom signatures")
    print("   Available signatures:")
    for sig in manager.get_available_signature_types():
        print(f"     - {sig}")
    print()
    
    print("3. behavioral_trigger")
    print("   - Files designed to trigger behavioral analysis")
    print("   Available triggers:")
    for trigger in manager.get_available_behavioral_triggers():
        print(f"     - {trigger}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Educational Antivirus Sample Management Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--samples-path',
        default='samples/',
        help='Path to samples directory (default: samples/)'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Create command
    create_parser = subparsers.add_parser('create', help='Create a new test sample')
    create_parser.add_argument('sample_type', choices=['eicar', 'custom_signature', 'behavioral_trigger'])
    create_parser.add_argument('--name', help='Custom name for the sample')
    create_parser.add_argument('--signature-name', help='Signature name (for custom_signature type)')
    create_parser.add_argument('--trigger-type', help='Trigger type (for behavioral_trigger type)')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all samples')
    list_parser.add_argument('--type', dest='type_filter', help='Filter by sample type')
    
    # Show command
    show_parser = subparsers.add_parser('show', help='Show sample details')
    show_group = show_parser.add_mutually_exclusive_group(required=True)
    show_group.add_argument('--id', dest='sample_id', help='Sample ID')
    show_group.add_argument('--name', help='Sample name')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a sample')
    delete_group = delete_parser.add_mutually_exclusive_group(required=True)
    delete_group.add_argument('--id', dest='sample_id', help='Sample ID')
    delete_group.add_argument('--name', help='Sample name')
    delete_parser.add_argument('--force', action='store_true', help='Skip confirmation')
    
    # Stats command
    subparsers.add_parser('stats', help='Show sample statistics')
    
    # Cleanup command
    subparsers.add_parser('cleanup', help='Clean up orphaned files')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export sample list')
    export_parser.add_argument('output_file', help='Output file path')
    export_parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Export format')
    
    # List types command
    subparsers.add_parser('types', help='List available sample types')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize sample manager
    try:
        manager = SampleManager(args.samples_path)
    except Exception as e:
        print(f"Error initializing sample manager: {e}")
        return
    
    # Execute command
    command_handlers = {
        'create': create_sample_command,
        'list': list_samples_command,
        'show': show_sample_command,
        'delete': delete_sample_command,
        'stats': stats_command,
        'cleanup': cleanup_command,
        'export': export_command,
        'types': list_types_command,
    }
    
    handler = command_handlers.get(args.command)
    if handler:
        handler(manager, args)
    else:
        print(f"Unknown command: {args.command}")


if __name__ == '__main__':
    main()