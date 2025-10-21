#!/usr/bin/env python3
"""
Test script for sample management functionality.
"""
import os
import sys
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from samples.sample_manager import SampleManager, SampleManagerError


def test_sample_management():
    """Test the sample management system."""
    print("=== Educational Antivirus Sample Management Test ===\n")
    
    # Initialize sample manager
    try:
        manager = SampleManager("test_samples/")
        print("✓ Sample manager initialized")
    except Exception as e:
        print(f"✗ Failed to initialize sample manager: {e}")
        return
    
    # Test 1: Create EICAR sample
    print("\n1. Creating EICAR test sample...")
    try:
        eicar_sample = manager.create_test_sample("eicar", "test_eicar.txt")
        print(f"✓ Created EICAR sample: {eicar_sample.name}")
        print(f"  ID: {eicar_sample.sample_id}")
        print(f"  Path: {eicar_sample.file_path}")
    except SampleManagerError as e:
        print(f"✗ Failed to create EICAR sample: {e}")
    
    # Test 2: Create custom signature sample
    print("\n2. Creating custom signature sample...")
    try:
        custom_sample = manager.create_test_sample(
            "custom_signature", 
            "test_virus.bin",
            signature_name="TestVirus.A"
        )
        print(f"✓ Created custom signature sample: {custom_sample.name}")
        print(f"  ID: {custom_sample.sample_id}")
        print(f"  Signatures: {custom_sample.signatures}")
    except SampleManagerError as e:
        print(f"✗ Failed to create custom signature sample: {e}")
    
    # Test 3: Create behavioral trigger sample
    print("\n3. Creating behavioral trigger sample...")
    try:
        behavioral_sample = manager.create_test_sample(
            "behavioral_trigger",
            "test_high_entropy",
            trigger_type="high_entropy"
        )
        print(f"✓ Created behavioral trigger sample: {behavioral_sample.name}")
        print(f"  ID: {behavioral_sample.sample_id}")
        print(f"  Type: {behavioral_sample.sample_type}")
    except SampleManagerError as e:
        print(f"✗ Failed to create behavioral trigger sample: {e}")
    
    # Test 4: List all samples
    print("\n4. Listing all samples...")
    try:
        samples = manager.list_available_samples()
        print(f"✓ Found {len(samples)} sample(s):")
        for sample in samples:
            print(f"  - {sample.name} ({sample.sample_type})")
    except Exception as e:
        print(f"✗ Failed to list samples: {e}")
    
    # Test 5: Get sample statistics
    print("\n5. Sample statistics...")
    try:
        stats = manager.get_sample_statistics()
        print("✓ Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
    except Exception as e:
        print(f"✗ Failed to get statistics: {e}")
    
    # Test 6: Validate samples
    print("\n6. Validating samples...")
    try:
        validation = manager.validate_samples()
        print("✓ Validation results:")
        print(f"  Valid: {len(validation['valid'])}")
        print(f"  Missing files: {len(validation['missing_files'])}")
        print(f"  Corrupted metadata: {len(validation['corrupted_metadata'])}")
    except Exception as e:
        print(f"✗ Failed to validate samples: {e}")
    
    # Test 7: Show available types
    print("\n7. Available sample types...")
    try:
        signatures = manager.get_available_signature_types()
        triggers = manager.get_available_behavioral_triggers()
        
        print("✓ Available custom signatures:")
        for sig in signatures:
            print(f"  - {sig}")
        
        print("✓ Available behavioral triggers:")
        for trigger in triggers:
            print(f"  - {trigger}")
    except Exception as e:
        print(f"✗ Failed to get available types: {e}")
    
    print("\n=== Test completed ===")
    print(f"Sample files created in: {manager.samples_path}")


if __name__ == "__main__":
    test_sample_management()