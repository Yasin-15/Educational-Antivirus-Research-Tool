#!/usr/bin/env python3
"""
Test script for the core scanning engine implementation.

This script tests the basic functionality of the ScanEngine and IntegratedScanner
to ensure they work correctly with the detection engines and quarantine system.
"""
import os
import tempfile
from pathlib import Path

from core.models import Config, ScanOptions
from core.scan_engine import ScanEngine
from core.integrated_scanner import IntegratedScanner, ThreatAction
from core.threat_handler import ThreatHandler, InteractionMode


def create_test_files():
    """Create temporary test files for scanning."""
    test_dir = Path(tempfile.mkdtemp(prefix="antivirus_test_"))
    
    # Create a harmless test file with EICAR signature
    eicar_file = test_dir / "eicar_test.txt"
    eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    eicar_file.write_text(eicar_content)
    
    # Create a normal text file
    normal_file = test_dir / "normal_file.txt"
    normal_file.write_text("This is a normal text file with no threats.")
    
    # Create a high-entropy file (simulates packed/encrypted content)
    entropy_file = test_dir / "high_entropy.bin"
    import random
    entropy_content = bytes([random.randint(0, 255) for _ in range(1024)])
    entropy_file.write_bytes(entropy_content)
    
    print(f"Created test files in: {test_dir}")
    return test_dir


def test_basic_scan_engine():
    """Test basic ScanEngine functionality."""
    print("\n" + "="*60)
    print("Testing Basic ScanEngine")
    print("="*60)
    
    try:
        # Create test files
        test_dir = create_test_files()
        
        # Initialize scan engine
        config = Config()
        config.signature_db_path = "detection/signatures.db"  # Use existing if available
        
        with ScanEngine(config) as scanner:
            print("✓ ScanEngine initialized successfully")
            
            # Scan the test directory
            options = ScanOptions(recursive=True)
            result = scanner.scan_path(str(test_dir), options)
            
            print(f"✓ Scan completed: {result.total_files} files scanned")
            print(f"✓ Detections found: {len(result.detections)}")
            
            for detection in result.detections:
                print(f"  - {detection.threat_name} in {Path(detection.file_path).name}")
                print(f"    Risk: {detection.risk_score}/10, Type: {detection.detection_type.value}")
            
            if result.errors:
                print(f"⚠️ Errors encountered: {len(result.errors)}")
                for error in result.errors[:3]:  # Show first 3 errors
                    print(f"  - {error}")
        
        # Cleanup
        import shutil
        shutil.rmtree(test_dir)
        print("✓ Test completed successfully")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()


def test_integrated_scanner():
    """Test IntegratedScanner with automatic threat handling."""
    print("\n" + "="*60)
    print("Testing IntegratedScanner")
    print("="*60)
    
    try:
        # Create test files
        test_dir = create_test_files()
        
        # Initialize integrated scanner
        config = Config()
        config.signature_db_path = "detection/signatures.db"
        
        with IntegratedScanner(config) as scanner:
            print("✓ IntegratedScanner initialized successfully")
            
            # Set up automatic threat handling (no user interaction)
            def auto_threat_handler(detection):
                # Automatically quarantine high-risk threats, ignore low-risk
                if detection.risk_score >= 7:
                    return ThreatAction.QUARANTINE
                else:
                    return ThreatAction.IGNORE
            
            scanner.set_threat_decision_callback(auto_threat_handler)
            
            # Scan with integration
            options = ScanOptions(recursive=True)
            result = scanner.scan_with_interaction(str(test_dir), options, interactive=False)
            
            print(f"✓ Integrated scan completed: {result.total_files} files scanned")
            print(f"✓ Detections found: {len(result.detections)}")
            
            # Show quarantine summary
            quarantine_summary = scanner.get_quarantine_summary()
            stats = quarantine_summary.get('quarantine_stats', {})
            print(f"✓ Files quarantined: {stats.get('active_quarantined', 0)}")
            
            # List quarantined files
            quarantined = scanner.list_quarantined_files()
            for item in quarantined:
                print(f"  - Quarantined: {Path(item['original_path']).name}")
                print(f"    Threat: {item['threat_name']}, Risk: {item['risk_score']}/10")
        
        # Cleanup
        import shutil
        shutil.rmtree(test_dir)
        print("✓ Integrated test completed successfully")
        
    except Exception as e:
        print(f"❌ Integrated test failed: {e}")
        import traceback
        traceback.print_exc()


def test_threat_handler():
    """Test ThreatHandler in automatic mode."""
    print("\n" + "="*60)
    print("Testing ThreatHandler")
    print("="*60)
    
    try:
        from core.models import Detection, DetectionType
        from datetime import datetime
        
        # Create a mock detection
        detection = Detection(
            file_path="/test/mock_threat.exe",
            detection_type=DetectionType.SIGNATURE,
            threat_name="Test.Malware.EICAR",
            risk_score=8,
            signature_id="test_sig_001",
            timestamp=datetime.now(),
            details={'educational_info': 'This is a test threat for educational purposes'}
        )
        
        # Test automatic mode
        handler = ThreatHandler(InteractionMode.AUTOMATIC)
        action = handler.handle_threat_decision(detection)
        print(f"✓ Automatic decision for high-risk threat: {action.value}")
        
        # Test with low-risk detection
        detection.risk_score = 3
        action = handler.handle_threat_decision(detection)
        print(f"✓ Automatic decision for low-risk threat: {action.value}")
        
        # Test batch mode
        handler = ThreatHandler(InteractionMode.BATCH)
        handler.set_batch_decisions({
            'eicar': 'quarantine',
            'test': 'ignore'
        })
        handler.set_default_action(ThreatAction.QUARANTINE)
        
        detection.file_path = "/test/eicar_sample.txt"
        action = handler.handle_threat_decision(detection)
        print(f"✓ Batch decision for EICAR pattern: {action.value}")
        
        print("✓ ThreatHandler test completed successfully")
        
    except Exception as e:
        print(f"❌ ThreatHandler test failed: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Run all tests."""
    print("Educational Antivirus Research Tool - Core Scanning Engine Tests")
    print("="*80)
    
    # Test basic scan engine
    test_basic_scan_engine()
    
    # Test integrated scanner
    test_integrated_scanner()
    
    # Test threat handler
    test_threat_handler()
    
    print("\n" + "="*80)
    print("All tests completed!")
    print("="*80)


if __name__ == "__main__":
    main()