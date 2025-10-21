#!/usr/bin/env python3
"""
Demo script for the Educational Antivirus Research Tool reporting system.

This script demonstrates the reporting and educational content features.
"""
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.models import ScanResult, Detection, DetectionType, ScanOptions, ScanStatus
from reporting import EducationalReportSystem, ReportGenerator, EducationalDatabase


def create_sample_scan_results():
    """Create sample scan results for demonstration."""
    scan_results = []
    
    # Sample scan 1 - EICAR detection
    scan1 = ScanResult(
        scan_id="demo-scan-001",
        start_time=datetime.now() - timedelta(hours=2),
        end_time=datetime.now() - timedelta(hours=2) + timedelta(minutes=5),
        scanned_paths=["test_samples/"],
        total_files=10,
        status=ScanStatus.COMPLETED,
        scan_options=ScanOptions(recursive=True, behavioral_threshold=7)
    )
    
    # Add EICAR detection
    eicar_detection = Detection(
        file_path="test_samples/eicar.txt",
        detection_type=DetectionType.SIGNATURE,
        threat_name="EICAR",
        risk_score=2,
        signature_id="EICAR-TEST-001",
        timestamp=scan1.start_time + timedelta(minutes=1),
        details={
            'signature_match': 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
            'file_size': 68
        }
    )
    scan1.detections.append(eicar_detection)
    
    scan_results.append(scan1)
    
    # Sample scan 2 - Behavioral detections
    scan2 = ScanResult(
        scan_id="demo-scan-002",
        start_time=datetime.now() - timedelta(hours=1),
        end_time=datetime.now() - timedelta(hours=1) + timedelta(minutes=8),
        scanned_paths=["samples/"],
        total_files=25,
        status=ScanStatus.COMPLETED,
        scan_options=ScanOptions(recursive=True, behavioral_threshold=6)
    )
    
    # Add high entropy detection
    entropy_detection = Detection(
        file_path="samples/high_entropy_test.bin",
        detection_type=DetectionType.BEHAVIORAL,
        threat_name="High Entropy Content",
        risk_score=7,
        timestamp=scan2.start_time + timedelta(minutes=3),
        details={
            'entropy': 7.8,
            'behavioral_threshold': 6,
            'suspicious_patterns': ['high_entropy', 'binary_content'],
            'file_size': 2048
        }
    )
    scan2.detections.append(entropy_detection)
    
    # Add suspicious extension detection
    suspicious_detection = Detection(
        file_path="samples/test_script.bat",
        detection_type=DetectionType.BEHAVIORAL,
        threat_name="Suspicious File Extension",
        risk_score=6,
        timestamp=scan2.start_time + timedelta(minutes=5),
        details={
            'file_extension': '.bat',
            'suspicious_patterns': ['executable_extension', 'script_file'],
            'behavioral_threshold': 6
        }
    )
    scan2.detections.append(suspicious_detection)
    
    scan_results.append(scan2)
    
    # Sample scan 3 - Clean scan
    scan3 = ScanResult(
        scan_id="demo-scan-003",
        start_time=datetime.now() - timedelta(minutes=30),
        end_time=datetime.now() - timedelta(minutes=25),
        scanned_paths=["core/"],
        total_files=15,
        status=ScanStatus.COMPLETED,
        scan_options=ScanOptions(recursive=True)
    )
    # No detections for this scan
    
    scan_results.append(scan3)
    
    return scan_results


def demo_basic_reporting():
    """Demonstrate basic report generation."""
    print("=" * 60)
    print("BASIC REPORTING DEMO")
    print("=" * 60)
    
    # Create sample data
    scan_results = create_sample_scan_results()
    
    # Initialize report generator
    report_generator = ReportGenerator("demo_reports")
    
    # Generate reports in different formats
    formats = ['text', 'json', 'csv']
    
    for format_type in formats:
        print(f"\nGenerating {format_type.upper()} report...")
        
        try:
            report_content = report_generator.generate_report(scan_results, format_type)
            
            # Save the report
            filename = f"demo_basic_report.{report_generator._get_file_extension(format_type)}"
            saved_path = report_generator.save_report(report_content, filename, format_type)
            
            print(f"✅ {format_type.upper()} report saved to: {saved_path}")
            
            # Show preview for text format
            if format_type == 'text':
                print("\nText Report Preview (first 500 characters):")
                print("-" * 40)
                print(report_content[:500] + "..." if len(report_content) > 500 else report_content)
                
        except Exception as e:
            print(f"❌ Error generating {format_type} report: {e}")


def demo_educational_reporting():
    """Demonstrate educational reporting features."""
    print("\n" + "=" * 60)
    print("EDUCATIONAL REPORTING DEMO")
    print("=" * 60)
    
    # Create sample data
    scan_results = create_sample_scan_results()
    
    # Initialize educational report system
    edu_system = EducationalReportSystem("demo_reports")
    
    print("\n1. Generating educational report...")
    try:
        edu_report = edu_system.generate_educational_report(
            scan_results, 
            format_type='text',
            include_learning_content=True
        )
        
        saved_path = edu_system.save_educational_report(
            scan_results,
            filename="demo_educational_report.txt"
        )
        
        print(f"✅ Educational report saved to: {saved_path}")
        
        # Show preview
        print("\nEducational Report Preview (first 800 characters):")
        print("-" * 50)
        print(edu_report[:800] + "..." if len(edu_report) > 800 else edu_report)
        
    except Exception as e:
        print(f"❌ Error generating educational report: {e}")
    
    print("\n2. Generating threat explanation report...")
    try:
        # Collect all detections
        all_detections = []
        for result in scan_results:
            all_detections.extend(result.detections)
        
        threat_report = edu_system.generate_threat_explanation_report(all_detections)
        saved_path = edu_system.save_threat_explanation_report(
            all_detections,
            filename="demo_threat_explanations.txt"
        )
        
        print(f"✅ Threat explanation report saved to: {saved_path}")
        
        # Show preview
        print("\nThreat Explanation Preview (first 600 characters):")
        print("-" * 50)
        print(threat_report[:600] + "..." if len(threat_report) > 600 else threat_report)
        
    except Exception as e:
        print(f"❌ Error generating threat explanation report: {e}")


def demo_educational_content():
    """Demonstrate educational content features."""
    print("\n" + "=" * 60)
    print("EDUCATIONAL CONTENT DEMO")
    print("=" * 60)
    
    # Initialize educational system
    edu_system = EducationalReportSystem("demo_reports")
    
    print("\n1. Available educational content:")
    try:
        content_list = edu_system.list_educational_content()
        print(content_list[:1000] + "..." if len(content_list) > 1000 else content_list)
    except Exception as e:
        print(f"❌ Error listing educational content: {e}")
    
    print("\n2. Detection method guide:")
    try:
        method_guide = edu_system.generate_detection_method_guide()
        
        # Save the guide
        guide_path = edu_system.report_generator.save_report(
            method_guide, 
            "demo_detection_methods_guide.txt", 
            'text'
        )
        
        print(f"✅ Detection method guide saved to: {guide_path}")
        
        # Show preview
        print("\nDetection Method Guide Preview (first 600 characters):")
        print("-" * 50)
        print(method_guide[:600] + "..." if len(method_guide) > 600 else method_guide)
        
    except Exception as e:
        print(f"❌ Error generating detection method guide: {e}")
    
    print("\n3. Individual threat explanations:")
    try:
        # Create a sample detection for demonstration
        sample_detection = Detection(
            file_path="demo/sample_file.exe",
            detection_type=DetectionType.BEHAVIORAL,
            threat_name="High Entropy Content",
            risk_score=8,
            details={
                'entropy': 7.9,
                'suspicious_patterns': ['high_entropy', 'executable_extension'],
                'behavioral_threshold': 7
            }
        )
        
        # Get quick summary
        quick_summary = edu_system.get_quick_threat_summary(sample_detection)
        print("Quick Threat Summary:")
        print(quick_summary)
        
        print("\nDetailed Threat Explanation:")
        detailed_explanation = edu_system.get_detailed_threat_explanation(sample_detection)
        print(detailed_explanation[:800] + "..." if len(detailed_explanation) > 800 else detailed_explanation)
        
    except Exception as e:
        print(f"❌ Error generating threat explanations: {e}")


def demo_learning_recommendations():
    """Demonstrate learning recommendation features."""
    print("\n" + "=" * 60)
    print("LEARNING RECOMMENDATIONS DEMO")
    print("=" * 60)
    
    # Create sample data
    scan_results = create_sample_scan_results()
    
    # Initialize educational system
    edu_system = EducationalReportSystem("demo_reports")
    
    try:
        recommendations = edu_system.get_learning_recommendations(scan_results)
        print(recommendations)
        
        # Save recommendations
        rec_path = edu_system.report_generator.save_report(
            recommendations,
            "demo_learning_recommendations.txt",
            'text'
        )
        print(f"\n✅ Learning recommendations saved to: {rec_path}")
        
    except Exception as e:
        print(f"❌ Error generating learning recommendations: {e}")


def main():
    """Main demo function."""
    print("Educational Antivirus Research Tool - Reporting System Demo")
    print("=" * 80)
    
    # Create demo reports directory
    os.makedirs("demo_reports", exist_ok=True)
    
    try:
        # Run all demos
        demo_basic_reporting()
        demo_educational_reporting()
        demo_educational_content()
        demo_learning_recommendations()
        
        print("\n" + "=" * 80)
        print("DEMO COMPLETED SUCCESSFULLY!")
        print("=" * 80)
        print("\nGenerated files can be found in the 'demo_reports' directory.")
        print("Review the reports to see the educational content and explanations.")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()