#!/usr/bin/env python3
"""
Test script to verify signature scanning functionality.
This demonstrates the implementation of task 4.2: Build signature scanning functionality.
"""
import os
import tempfile
from pathlib import Path

from detection.signature_engine import SignatureEngine
from core.logging_config import setup_logging
from core.exceptions import SignatureError, ScanError

def test_signature_scanning():
    """Test the signature scanning functionality."""
    print("Testing Signature Scanning Functionality")
    print("=" * 50)
    
    # Setup logging
    setup_logging("INFO")
    
    # Create temporary database
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = os.path.join(temp_dir, "test_signatures.db")
        
        # Initialize signature engine
        print("1. Initializing signature engine...")
        engine = SignatureEngine(db_path, sensitivity=7)
        
        try:
            # Initialize the engine (loads default signatures)
            engine.initialize()
            print(f"   ✓ Engine initialized with sensitivity level: {engine.sensitivity}")
            
            # List available signatures
            signatures = engine.list_signatures()
            print(f"   ✓ Loaded {len(signatures)} signatures")
            
            # Display some signature information
            print("\n2. Available signatures:")
            for i, sig in enumerate(signatures[:5]):  # Show first 5
                print(f"   - {sig['name']} (Type: {sig['type']}, Severity: {sig['severity']})")
            if len(signatures) > 5:
                print(f"   ... and {len(signatures) - 5} more signatures")
            
            # Create test files with known patterns
            print("\n3. Creating test files...")
            test_files = create_test_files(temp_dir)
            
            # Test file scanning
            print("\n4. Testing file scanning:")
            total_detections = 0
            
            for test_file in test_files:
                print(f"\n   Scanning: {os.path.basename(test_file)}")
                try:
                    detections = engine.scan_file(test_file)
                    total_detections += len(detections)
                    
                    if detections:
                        for detection in detections:
                            print(f"   ✓ DETECTED: {detection.threat_name}")
                            print(f"     Risk Score: {detection.risk_score}/10")
                            print(f"     Detection Type: {detection.detection_type.value}")
                            if detection.details.get('educational_info'):
                                print(f"     Info: {detection.details['educational_info']}")
                    else:
                        print("   ✓ No threats detected")
                        
                except (ScanError, Exception) as e:
                    print(f"   ✗ Scan failed: {e}")
            
            # Test directory scanning
            print(f"\n5. Testing directory scanning...")
            try:
                all_detections = engine.scan_directory(temp_dir, recursive=True)
                print(f"   ✓ Directory scan completed: {len(all_detections)} total detections")
            except Exception as e:
                print(f"   ✗ Directory scan failed: {e}")
            
            # Test sensitivity configuration
            print(f"\n6. Testing sensitivity configuration...")
            original_sensitivity = engine.sensitivity
            
            # Test different sensitivity levels
            for sensitivity in [3, 8]:
                try:
                    engine.update_sensitivity(sensitivity)
                    print(f"   ✓ Updated sensitivity to {sensitivity}")
                    
                    # Re-scan a test file to show sensitivity impact
                    if test_files:
                        detections = engine.scan_file(test_files[0])
                        print(f"     Detections at sensitivity {sensitivity}: {len(detections)}")
                        
                except Exception as e:
                    print(f"   ✗ Sensitivity update failed: {e}")
            
            # Restore original sensitivity
            engine.update_sensitivity(original_sensitivity)
            
            # Display scan statistics
            print(f"\n7. Scan statistics:")
            stats = engine.get_scan_statistics()
            print(f"   Files scanned: {stats['files_scanned']}")
            print(f"   Total matches: {stats['total_matches']}")
            print(f"   Signatures matched: {stats['signatures_matched']}")
            print(f"   Average scan time: {stats['avg_scan_time']:.4f}s")
            print(f"   Detection rate: {stats['detection_rate']:.2%}")
            
            # Test custom signature addition
            print(f"\n8. Testing custom signature addition...")
            try:
                success = engine.add_custom_signature(
                    name="Test Custom Signature",
                    pattern=b"CUSTOM_TEST_PATTERN_12345",
                    signature_type="exact_match",
                    description="Custom test signature for demonstration",
                    threat_category="Test",
                    severity=5
                )
                if success:
                    print("   ✓ Custom signature added successfully")
                    
                    # Create a file with the custom pattern and test
                    custom_test_file = os.path.join(temp_dir, "custom_test.txt")
                    with open(custom_test_file, 'wb') as f:
                        f.write(b"This file contains CUSTOM_TEST_PATTERN_12345 for testing")
                    
                    detections = engine.scan_file(custom_test_file)
                    if detections:
                        print(f"   ✓ Custom signature detected: {detections[0].threat_name}")
                    else:
                        print("   ✗ Custom signature not detected")
                        
            except Exception as e:
                print(f"   ✗ Custom signature test failed: {e}")
            
            print(f"\n" + "=" * 50)
            print("✓ Signature scanning functionality test completed successfully!")
            print(f"Total detections found: {total_detections}")
            
        finally:
            engine.close()

def create_test_files(temp_dir: str) -> list:
    """Create test files with various patterns for scanning."""
    test_files = []
    
    # EICAR test file
    eicar_file = os.path.join(temp_dir, "eicar_test.txt")
    with open(eicar_file, 'wb') as f:
        f.write(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
    test_files.append(eicar_file)
    
    # Educational malware simulation file
    edu_malware_file = os.path.join(temp_dir, "educational_malware.txt")
    with open(edu_malware_file, 'wb') as f:
        f.write(b'This file contains EDUCATIONAL_TROJAN_SIGNATURE_DO_NOT_EXECUTE for testing purposes')
    test_files.append(edu_malware_file)
    
    # Suspicious batch file simulation
    batch_file = os.path.join(temp_dir, "suspicious.bat")
    with open(batch_file, 'wb') as f:
        f.write(b'@echo off\ndel *.* /q\necho This is a test batch file')
    test_files.append(batch_file)
    
    # Clean file (should not trigger detections)
    clean_file = os.path.join(temp_dir, "clean_file.txt")
    with open(clean_file, 'w') as f:
        f.write("This is a completely clean file with no suspicious patterns.")
    test_files.append(clean_file)
    
    # PowerShell encoded command simulation
    ps_file = os.path.join(temp_dir, "suspicious.ps1")
    with open(ps_file, 'wb') as f:
        f.write(b'powershell -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==')
    test_files.append(ps_file)
    
    return test_files

if __name__ == "__main__":
    test_signature_scanning()