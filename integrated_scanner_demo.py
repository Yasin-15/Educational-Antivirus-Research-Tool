#!/usr/bin/env python3
"""
Integrated Scanner Demo - Educational Antivirus Research Tool

This script demonstrates the key integration features implemented in task 8.2:
1. Detection engine coordination (signature + behavioral)
2. Automatic threat decision making
3. Quarantine management integration
4. User interaction capabilities

Usage:
    python integrated_scanner_demo.py [path_to_scan]
"""
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.scan_engine import ScanEngine, ThreatAction
from core.models import Config, ScanOptions
from core.logging_config import LoggingManager


def demo_automatic_scanning(scanner: ScanEngine, path: str):
    """Demonstrate automatic scanning with integrated threat handling."""
    print("🔍 AUTOMATIC SCANNING DEMO")
    print("=" * 40)
    
    # Configure automatic decision thresholds
    scanner.update_auto_decision_thresholds(
        quarantine_threshold=7,  # Quarantine threats with risk >= 7
        ignore_threshold=4       # Ignore threats with risk <= 4
    )
    
    print(f"Scanning: {path}")
    print("Auto-quarantine threshold: 7")
    print("Auto-ignore threshold: 4")
    print()
    
    # Perform integrated scan
    result = scanner.scan_with_quarantine(path, interactive=False)
    
    # Display results
    print(f"📊 RESULTS:")
    print(f"   Files scanned: {result.total_files}")
    print(f"   Threats detected: {len(result.detections)}")
    print(f"   Status: {result.status.value}")
    
    if hasattr(result, 'details') and result.details:
        details = result.details
        print(f"\n🛡️  THREAT HANDLING:")
        print(f"   Quarantined: {details.get('quarantine_actions', 0)}")
        print(f"   Ignored: {details.get('ignored_threats', 0)}")
        print(f"   Deleted: {details.get('deleted_threats', 0)}")
    
    return result


def demo_quarantine_management(scanner: ScanEngine):
    """Demonstrate quarantine management capabilities."""
    print("\n📦 QUARANTINE MANAGEMENT DEMO")
    print("=" * 40)
    
    # Get quarantine summary
    summary = scanner.get_quarantine_summary()
    
    if 'quarantine_stats' in summary:
        stats = summary['quarantine_stats']
        print(f"Quarantine Statistics:")
        print(f"   Total quarantined: {stats.get('total_quarantined', 0)}")
        print(f"   Active quarantined: {stats.get('active_quarantined', 0)}")
        print(f"   Signature detections: {stats.get('signature_detections', 0)}")
        print(f"   Behavioral detections: {stats.get('behavioral_detections', 0)}")
    
    # List quarantined files
    quarantined_files = scanner.list_quarantined_files()
    
    if quarantined_files:
        print(f"\n📋 QUARANTINED FILES ({len(quarantined_files)}):")
        for i, file_info in enumerate(quarantined_files[:5], 1):  # Show first 5
            print(f"   {i}. {Path(file_info['original_path']).name}")
            print(f"      Threat: {file_info['threat_name']}")
            print(f"      Risk: {file_info['risk_score']}/10")
            print(f"      Type: {file_info['detection_type']}")
        
        if len(quarantined_files) > 5:
            print(f"   ... and {len(quarantined_files) - 5} more files")
    else:
        print("\n📋 No files currently quarantined")


def demo_decision_history(scanner: ScanEngine):
    """Demonstrate decision history tracking."""
    print("\n📈 DECISION HISTORY DEMO")
    print("=" * 40)
    
    # Get recent decisions
    decisions = scanner.get_decision_history(limit=10)
    
    if decisions:
        print(f"Recent Threat Decisions ({len(decisions)}):")
        
        action_counts = {}
        for decision in decisions:
            action = decision['action']
            action_counts[action] = action_counts.get(action, 0) + 1
            
            file_name = Path(decision['file_path']).name
            print(f"   • {file_name} -> {action.upper()}")
            print(f"     Risk: {decision['risk_score']}/10, {decision['reason']}")
        
        print(f"\nAction Summary:")
        for action, count in action_counts.items():
            print(f"   {action.capitalize()}: {count}")
    else:
        print("No threat decisions recorded yet")


def demo_engine_statistics(scanner: ScanEngine):
    """Demonstrate comprehensive engine statistics."""
    print("\n📊 ENGINE STATISTICS DEMO")
    print("=" * 40)
    
    stats = scanner.get_engine_statistics()
    
    # Overall statistics
    print(f"Overall Statistics:")
    print(f"   Total files scanned: {stats.get('total_files_scanned', 0)}")
    print(f"   Total detections: {stats.get('total_detections', 0)}")
    print(f"   Detection rate: {stats.get('detection_rate', 0):.2%}")
    
    # Decision statistics
    if 'decision_stats' in stats:
        decision_stats = stats['decision_stats']
        print(f"\nDecision Statistics:")
        print(f"   Total decisions: {decision_stats.get('total_decisions', 0)}")
        print(f"   Automatic decisions: {decision_stats.get('auto_decisions', 0)}")
        print(f"   Manual decisions: {decision_stats.get('manual_decisions', 0)}")
    
    # Signature engine statistics
    if 'signature_engine' in stats:
        sig_stats = stats['signature_engine']
        print(f"\nSignature Engine:")
        print(f"   Files scanned: {sig_stats.get('files_scanned', 0)}")
        print(f"   Signatures matched: {sig_stats.get('signatures_matched', 0)}")
        print(f"   Average scan time: {sig_stats.get('avg_scan_time', 0):.3f}s")


def main():
    """Main demonstration function."""
    print("🔬 Educational Antivirus - Integrated Scanner Demo")
    print("=" * 55)
    print("This demo shows the integration of detection engines with quarantine management")
    print()
    
    # Setup logging (minimal for demo)
    logging_manager = LoggingManager()
    logger = logging_manager.setup_logging()
    logger.setLevel('WARNING')  # Reduce log noise for demo
    
    # Determine scan path
    if len(sys.argv) > 1:
        scan_path = sys.argv[1]
    else:
        scan_path = "samples"
    
    if not os.path.exists(scan_path):
        print(f"❌ Path not found: {scan_path}")
        print("Please provide a valid path to scan, or ensure 'samples' directory exists")
        return
    
    # Create configuration
    config = Config()
    
    try:
        # Initialize integrated scanner
        with ScanEngine(config) as scanner:
            # Demo 1: Automatic scanning with threat handling
            scan_result = demo_automatic_scanning(scanner, scan_path)
            
            # Demo 2: Quarantine management
            demo_quarantine_management(scanner)
            
            # Demo 3: Decision history
            demo_decision_history(scanner)
            
            # Demo 4: Engine statistics
            demo_engine_statistics(scanner)
            
            print(f"\n✅ Integration Demo Completed Successfully!")
            print(f"\nKey Features Demonstrated:")
            print(f"   ✓ Detection engine coordination (signature + behavioral)")
            print(f"   ✓ Automatic threat decision making")
            print(f"   ✓ Quarantine management integration")
            print(f"   ✓ Comprehensive statistics and reporting")
            
    except KeyboardInterrupt:
        print(f"\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()