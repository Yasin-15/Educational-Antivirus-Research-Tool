#!/usr/bin/env python3
"""
Test script for the initialization system.
"""
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.initialization import initialize_system, check_initialization, InitializationManager


def main():
    """Test the initialization system."""
    print("Educational Antivirus Research Tool - Initialization Test")
    print("=" * 60)
    
    try:
        # Check current system status
        print("\n1. Checking current system status...")
        manager = InitializationManager()
        status = manager.check_system_status()
        
        for component, is_ok in status.items():
            status_symbol = "✓" if is_ok else "✗"
            print(f"   {status_symbol} {component.replace('_', ' ').title()}: {'OK' if is_ok else 'Missing'}")
        
        # Initialize system
        print("\n2. Initializing system...")
        config = initialize_system(force_reset=False)
        
        print(f"\n3. Configuration loaded:")
        print(f"   - Signature sensitivity: {config.signature_sensitivity}")
        print(f"   - Behavioral threshold: {config.behavioral_threshold}")
        print(f"   - Signature DB path: {config.signature_db_path}")
        print(f"   - Quarantine path: {config.quarantine_path}")
        print(f"   - Samples path: {config.samples_path}")
        print(f"   - Reports path: {config.reports_path}")
        
        # Final status check
        print("\n4. Final system status check...")
        final_status = manager.check_system_status()
        
        all_ok = True
        for component, is_ok in final_status.items():
            status_symbol = "✓" if is_ok else "✗"
            print(f"   {status_symbol} {component.replace('_', ' ').title()}: {'OK' if is_ok else 'Missing'}")
            if not is_ok:
                all_ok = False
        
        if all_ok:
            print("\n✓ System initialization completed successfully!")
            print("The Educational Antivirus Research Tool is ready to use.")
        else:
            print("\n⚠ System initialization completed with some issues.")
            print("Some components may not function properly.")
        
        # Test sample database
        print("\n5. Testing sample database...")
        from core.sample_database import SampleDatabaseManager
        
        sample_manager = SampleDatabaseManager(config)
        samples = sample_manager.get_all_samples()
        
        print(f"   Found {len(samples)} educational samples:")
        for sample in samples:
            print(f"   - {sample.name} ({sample.sample_type}, threat level: {sample.threat_level})")
        
        print("\nInitialization test completed!")
        
    except Exception as e:
        print(f"\n✗ Initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())