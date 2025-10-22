#!/usr/bin/env python3
"""
Test script for behavioral analysis engine.
"""
import os
import tempfile
from pathlib import Path

from core.models import Config
from detection.behavioral_engine import BehavioralAnalysisEngine


def create_test_file(content: bytes, filename: str) -> str:
    """Create a temporary test file."""
    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, filename)
    
    with open(file_path, 'wb') as f:
        f.write(content)
    
    return file_path


def test_behavioral_analysis():
    """Test behavioral analysis functionality."""
    print("Testing Behavioral Analysis Engine...")
    
    # Initialize engine with default config
    config = Config()
    engine = BehavioralAnalysisEngine(config)
    
    # Test 1: High entropy file (simulated encrypted/packed file)
    print("\n1. Testing high entropy file...")
    high_entropy_content = bytes(range(256)) * 100  # Random-like content
    high_entropy_file = create_test_file(high_entropy_content, "suspicious.exe")
    
    try:
        result = engine.analyze_file(high_entropy_file)
        print(f"   File: {result.file_path}")
        print(f"   Risk Score: {result.risk_score}/10")
        print(f"   Entropy: {result.entropy:.2f}")
        print(f"   Suspicious Patterns: {len(result.suspicious_patterns)}")
        for pattern in result.suspicious_patterns:
            print(f"     - {pattern}")
        
        # Test comprehensive assessment
        assessment = engine.get_comprehensive_assessment(high_entropy_file)
        print(f"   Risk Category: {assessment.risk_category.value}")
        print(f"   Confidence: {assessment.confidence:.2f}")
        print(f"   Recommendations: {len(assessment.recommendations)}")
        
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 2: Normal text file
    print("\n2. Testing normal text file...")
    normal_content = b"This is a normal text file with regular content. " * 50
    normal_file = create_test_file(normal_content, "document.txt")
    
    try:
        result = engine.analyze_file(normal_file)
        print(f"   File: {result.file_path}")
        print(f"   Risk Score: {result.risk_score}/10")
        print(f"   Entropy: {result.entropy:.2f}")
        print(f"   Suspicious Patterns: {len(result.suspicious_patterns)}")
        
        assessment = engine.get_comprehensive_assessment(normal_file)
        print(f"   Risk Category: {assessment.risk_category.value}")
        print(f"   Confidence: {assessment.confidence:.2f}")
        
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 3: Suspicious filename patterns
    print("\n3. Testing suspicious filename...")
    suspicious_content = b"Normal content but suspicious name"
    suspicious_file = create_test_file(suspicious_content, "virus_keylogger.exe")
    
    try:
        result = engine.analyze_file(suspicious_file)
        print(f"   File: {result.file_path}")
        print(f"   Risk Score: {result.risk_score}/10")
        print(f"   Suspicious Patterns: {len(result.suspicious_patterns)}")
        for pattern in result.suspicious_patterns:
            print(f"     - {pattern}")
        
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 4: Configuration threshold testing
    print("\n4. Testing threshold configuration...")
    
    # Test with different thresholds
    for threshold in [3, 5, 7, 9]:
        config.behavioral_threshold = threshold
        engine.update_config(config)
        
        result = engine.analyze_file(high_entropy_file)
        is_suspicious = engine.is_file_suspicious(high_entropy_file)
        
        print(f"   Threshold {threshold}: Score {result.risk_score}, Suspicious: {is_suspicious}")
    
    print("\nBehavioral Analysis Engine test completed!")


if __name__ == "__main__":
    test_behavioral_analysis()