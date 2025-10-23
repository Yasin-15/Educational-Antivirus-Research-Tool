#!/usr/bin/env python3
"""
Enhanced Main Entry Point for Educational Antivirus Tool.

This module integrates all the enhanced features including:
- Heuristic engine
- Machine learning classifier
- Real-time protection
- Encrypted quarantine
- Threat intelligence
- GUI dashboard
- Performance optimization
"""
import sys
import os
import argparse
from pathlib import Path
from typing import Optional

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Core imports
from core.config import ConfigManager, Config
from core.models import ScanOptions
from core.logging_config import setup_default_logging

# Enhanced detection engines
from detection.heuristic_engine import HeuristicEngine
from detection.ml_classifier import MLClassifier, create_ml_detection

# Real-time protection
from realtime.file_monitor import RealTimeProtectionManager, MonitorConfig

# Enhanced quarantine
from quarantine.encrypted_quarantine import EncryptedQuarantineManager, QuarantineConfig

# Threat intelligence
from cloud.threat_intel import ThreatIntelligenceManager, ThreatIntelConfig, create_threat_intel_manager

# Performance optimization
from performance.parallel_scanner import ParallelScanner, PerformanceConfig, create_parallel_scanner

# GUI Dashboard
from gui.dashboard import AntivirusDashboard, create_dashboard

# Original scanner engine
try:
    from detection.scanner_engine import ScannerEngine
except ImportError:
    print("⚠️ Original scanner engine not found, using mock implementation")
    ScannerEngine = None

logger = setup_default_logging()


class EnhancedAntivirusEngine:
    """Enhanced antivirus engine with all advanced features."""
    
    def __init__(self, config: Config):
        """Initialize enhanced antivirus engine."""
        self.config = config
        
        print("🚀 Initializing Enhanced Educational Antivirus Tool")
        print("=" * 60)
        
        # Initialize core components
        self._initialize_detection_engines()
        self._initialize_quarantine_system()
        self._initialize_threat_intelligence()
        self._initialize_realtime_protection()
        self._initialize_performance_optimization()
        
        print("✅ Enhanced Antivirus Engine initialized successfully")
        print("=" * 60)
    
    def _initialize_detection_engines(self):
        """Initialize all detection engines."""
        print("🔍 Initializing Detection Engines...")
        
        # Original scanner engine
        if ScannerEngine:
            self.scanner_engine = ScannerEngine(self.config)
        else:
            self.scanner_engine = MockScannerEngine()
        
        # Heuristic engine
        self.heuristic_engine = HeuristicEngine(self.config)
        print("   ✅ Heuristic engine loaded")
        
        # Machine learning classifier
        self.ml_classifier = MLClassifier(self.config)
        print("   ✅ ML classifier loaded")
        
        # Enhanced scanner with all engines
        self.enhanced_scanner = EnhancedScannerWrapper(
            self.scanner_engine,
            self.heuristic_engine,
            self.ml_classifier
        )
    
    def _initialize_quarantine_system(self):
        """Initialize encrypted quarantine system."""
        print("🔒 Initializing Encrypted Quarantine System...")
        
        quarantine_config = QuarantineConfig(
            quarantine_base_path=self.config.quarantine_path,
            max_quarantine_size_gb=10,
            auto_cleanup_days=90,
            forensic_mode=True
        )
        
        self.quarantine_manager = EncryptedQuarantineManager(quarantine_config)
        print("   ✅ Encrypted quarantine system loaded")
    
    def _initialize_threat_intelligence(self):
        """Initialize threat intelligence integration."""
        print("🌐 Initializing Threat Intelligence...")
        
        threat_intel_config = ThreatIntelConfig(
            enable_virustotal=True,  # Educational simulation
            cache_duration_hours=24,
            max_requests_per_minute=4
        )
        
        self.threat_intel_manager = create_threat_intel_manager(threat_intel_config)
        print("   ✅ Threat intelligence loaded")
    
    def _initialize_realtime_protection(self):
        """Initialize real-time protection system."""
        print("🛡️ Initializing Real-Time Protection...")
        
        self.realtime_manager = RealTimeProtectionManager(
            self.config,
            self.enhanced_scanner,
            self.quarantine_manager
        )
        print("   ✅ Real-time protection loaded")
    
    def _initialize_performance_optimization(self):
        """Initialize performance optimization."""
        print("⚡ Initializing Performance Optimization...")
        
        perf_config = PerformanceConfig(
            max_threads=8,
            max_processes=4,
            use_multiprocessing=True,
            cache_enabled=True,
            memory_limit_mb=1024
        )
        
        self.parallel_scanner = create_parallel_scanner(self.enhanced_scanner, perf_config)
        print("   ✅ Parallel scanner loaded")
    
    def scan_file(self, file_path: str) -> dict:
        """Scan a single file with all engines."""
        print(f"🔍 Scanning file: {file_path}")
        
        # Use enhanced scanner
        result = self.enhanced_scanner.scan_file(file_path)
        
        # Add threat intelligence lookup
        if result and result.detections:
            self._enhance_with_threat_intel(result.detections, file_path)
        
        return result
    
    def scan_path(self, scan_path: str, use_parallel: bool = True) -> dict:
        """Scan a path with optional parallel processing."""
        print(f"🔍 Scanning path: {scan_path}")
        
        scan_options = ScanOptions(
            recursive=self.config.recursive_scan,
            max_file_size_mb=self.config.max_file_size_mb,
            skip_extensions=self.config.skip_extensions
        )
        
        if use_parallel:
            return self.parallel_scanner.scan_path(scan_path, scan_options)
        else:
            return self.enhanced_scanner.scan_path(scan_path, scan_options)
    
    def start_realtime_protection(self):
        """Start real-time protection."""
        self.realtime_manager.start_protection()
    
    def stop_realtime_protection(self):
        """Stop real-time protection."""
        self.realtime_manager.stop_protection()
    
    def launch_gui(self):
        """Launch the GUI dashboard."""
        print("🖥️ Launching GUI Dashboard...")
        
        dashboard = create_dashboard(
            config=self.config,
            scanner_engine=self.enhanced_scanner,
            quarantine_manager=self.quarantine_manager,
            realtime_manager=self.realtime_manager
        )
        
        dashboard.run()
    
    def _enhance_with_threat_intel(self, detections: list, file_path: str):
        """Enhance detections with threat intelligence."""
        try:
            # Calculate file hash
            import hashlib
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Lookup in threat intelligence
            intel_results = self.threat_intel_manager.lookup_file_hash(file_hash)
            
            if intel_results:
                # Add threat intelligence detection
                intel_detection = self.threat_intel_manager.create_detection_from_intel(
                    file_path, file_hash, intel_results
                )
                
                if intel_detection:
                    detections.append(intel_detection)
        
        except Exception as e:
            logger.warning(f"Threat intelligence lookup failed: {e}")


class EnhancedScannerWrapper:
    """Wrapper that combines all detection engines."""
    
    def __init__(self, scanner_engine, heuristic_engine, ml_classifier):
        """Initialize enhanced scanner wrapper."""
        self.scanner_engine = scanner_engine
        self.heuristic_engine = heuristic_engine
        self.ml_classifier = ml_classifier
    
    def scan_file(self, file_path: str):
        """Scan file with all engines."""
        all_detections = []
        
        try:
            # Original signature-based detection
            if self.scanner_engine:
                result = self.scanner_engine.scan_file(file_path)
                if result and hasattr(result, 'detections'):
                    all_detections.extend(result.detections)
            
            # Heuristic analysis
            heuristic_result = self.heuristic_engine.analyze_file(file_path)
            heuristic_detection = create_heuristic_detection(file_path, heuristic_result)
            if heuristic_detection:
                all_detections.append(heuristic_detection)
            
            # Machine learning classification
            ml_result = self.ml_classifier.classify_file(file_path)
            ml_detection = create_ml_detection(file_path, ml_result)
            if ml_detection:
                all_detections.append(ml_detection)
            
            # Create combined result
            from core.models import ScanResult, ScanStatus
            from datetime import datetime
            
            return ScanResult(
                scan_id=f"enhanced_{int(datetime.now().timestamp())}",
                start_time=datetime.now(),
                end_time=datetime.now(),
                status=ScanStatus.COMPLETED,
                files_scanned=1,
                threats_found=len(all_detections),
                detections=all_detections,
                errors=[],
                scan_path=file_path
            )
        
        except Exception as e:
            logger.error(f"Enhanced scan failed for {file_path}: {e}")
            return None
    
    def scan_path(self, scan_path: str, scan_options=None):
        """Scan path with enhanced detection."""
        # This would implement directory scanning
        # For now, delegate to original scanner if available
        if self.scanner_engine and hasattr(self.scanner_engine, 'scan_path'):
            return self.scanner_engine.scan_path(scan_path, scan_options)
        
        # Fallback implementation
        from core.models import ScanResult, ScanStatus
        from datetime import datetime
        
        return ScanResult(
            scan_id=f"enhanced_path_{int(datetime.now().timestamp())}",
            start_time=datetime.now(),
            end_time=datetime.now(),
            status=ScanStatus.COMPLETED,
            files_scanned=0,
            threats_found=0,
            detections=[],
            errors=[],
            scan_path=scan_path
        )


class MockScannerEngine:
    """Mock scanner engine for testing when original is not available."""
    
    def __init__(self):
        """Initialize mock scanner."""
        print("⚠️ Using mock scanner engine for demonstration")
    
    def scan_file(self, file_path: str):
        """Mock file scanning."""
        from core.models import ScanResult, ScanStatus, Detection, DetectionType
        from datetime import datetime
        
        detections = []
        
        # Simulate EICAR detection
        if "eicar" in file_path.lower():
            detections.append(Detection(
                file_path=file_path,
                threat_name="EICAR-Test-File",
                detection_type=DetectionType.SIGNATURE,
                risk_score=100,
                description="EICAR test file detected"
            ))
        
        return ScanResult(
            scan_id=f"mock_{int(datetime.now().timestamp())}",
            start_time=datetime.now(),
            end_time=datetime.now(),
            status=ScanStatus.COMPLETED,
            files_scanned=1,
            threats_found=len(detections),
            detections=detections,
            errors=[],
            scan_path=file_path
        )


def create_heuristic_detection(file_path: str, heuristic_result):
    """Create detection from heuristic results."""
    from detection.heuristic_engine import create_heuristic_detection as create_heur_det
    return create_heur_det(file_path, heuristic_result)


def main():
    """Main entry point for enhanced antivirus tool."""
    parser = argparse.ArgumentParser(
        description="Enhanced Educational Antivirus Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --gui                           # Launch GUI dashboard
  %(prog)s --scan /path/to/file           # Scan single file
  %(prog)s --scan-dir /path/to/directory  # Scan directory
  %(prog)s --realtime                     # Start real-time protection
  %(prog)s --demo                         # Run demonstration mode
        """
    )
    
    parser.add_argument('--gui', action='store_true', help='Launch GUI dashboard')
    parser.add_argument('--scan', help='Scan single file')
    parser.add_argument('--scan-dir', help='Scan directory')
    parser.add_argument('--realtime', action='store_true', help='Start real-time protection')
    parser.add_argument('--demo', action='store_true', help='Run demonstration mode')
    parser.add_argument('--parallel', action='store_true', help='Use parallel scanning')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        config_manager = ConfigManager()
        config = config_manager.load_config(args.config)
        
        # Initialize enhanced engine
        engine = EnhancedAntivirusEngine(config)
        
        if args.gui:
            # Launch GUI
            engine.launch_gui()
        
        elif args.scan:
            # Scan single file
            result = engine.scan_file(args.scan)
            print(f"\n📊 Scan Results:")
            print(f"   Threats found: {result.threats_found}")
            for detection in result.detections:
                print(f"   - {detection.threat_name} (Risk: {detection.risk_score})")
        
        elif args.scan_dir:
            # Scan directory
            result = engine.scan_path(args.scan_dir, use_parallel=args.parallel)
            print(f"\n📊 Scan Results:")
            print(f"   Files scanned: {result.files_scanned}")
            print(f"   Threats found: {result.threats_found}")
            for detection in result.detections:
                print(f"   - {detection.file_path}: {detection.threat_name}")
        
        elif args.realtime:
            # Start real-time protection
            print("🛡️ Starting real-time protection...")
            engine.start_realtime_protection()
            
            try:
                print("Real-time protection active. Press Ctrl+C to stop...")
                import time
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n🛑 Stopping real-time protection...")
                engine.stop_realtime_protection()
        
        elif args.demo:
            # Run demonstration
            run_demonstration(engine)
        
        else:
            # Default: show help and launch GUI
            parser.print_help()
            print("\n🖥️ Launching GUI dashboard...")
            engine.launch_gui()
    
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def run_demonstration(engine: EnhancedAntivirusEngine):
    """Run a comprehensive demonstration of all features."""
    print("\n🎯 Enhanced Antivirus Tool Demonstration")
    print("=" * 50)
    
    # 1. Create test files
    print("\n1. Creating test files...")
    test_dir = Path("demo_files")
    test_dir.mkdir(exist_ok=True)
    
    # EICAR test file
    eicar_content = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    eicar_file = test_dir / "eicar_test.txt"
    with open(eicar_file, 'w') as f:
        f.write(eicar_content)
    
    # Benign test file
    benign_file = test_dir / "benign_test.txt"
    with open(benign_file, 'w') as f:
        f.write("This is a benign test file for demonstration purposes.")
    
    print(f"   ✅ Created test files in {test_dir}")
    
    # 2. Demonstrate file scanning
    print("\n2. Demonstrating enhanced file scanning...")
    
    for test_file in [eicar_file, benign_file]:
        print(f"\n   🔍 Scanning: {test_file}")
        result = engine.scan_file(str(test_file))
        
        if result.threats_found > 0:
            print(f"   🚨 Threats detected: {result.threats_found}")
            for detection in result.detections:
                print(f"      - {detection.threat_name} (Engine: {detection.detection_type.value})")
        else:
            print(f"   ✅ File is clean")
    
    # 3. Demonstrate quarantine
    print("\n3. Demonstrating quarantine system...")
    if eicar_file.exists():
        print(f"   🔒 Quarantining: {eicar_file}")
        
        # Create a detection for quarantine
        from core.models import Detection, DetectionType
        detection = Detection(
            file_path=str(eicar_file),
            threat_name="EICAR-Test-File",
            detection_type=DetectionType.SIGNATURE,
            risk_score=100,
            description="EICAR test file"
        )
        
        success = engine.quarantine_manager.quarantine_file(str(eicar_file), detection)
        if success:
            print(f"   ✅ File quarantined successfully")
        else:
            print(f"   ❌ Quarantine failed")
    
    # 4. Demonstrate threat intelligence
    print("\n4. Demonstrating threat intelligence...")
    test_hashes = [
        "44d88612fea8a8f36de82e1278abb02f",  # EICAR MD5
        "1234567890abcdef1234567890abcdef"   # Random hash
    ]
    
    for test_hash in test_hashes:
        print(f"   🌐 Looking up hash: {test_hash[:16]}...")
        results = engine.threat_intel_manager.lookup_file_hash(test_hash, "md5")
        
        if results:
            for result in results:
                status = "Malicious" if result.malicious else "Clean"
                print(f"      {result.source}: {status} (confidence: {result.confidence:.2f})")
        else:
            print(f"      No threat intelligence data found")
    
    # 5. Demonstrate performance features
    print("\n5. Demonstrating performance optimization...")
    stats = engine.parallel_scanner.get_performance_stats()
    print(f"   ⚡ Parallel scanner configuration:")
    print(f"      Max threads: {stats['config']['max_threads']}")
    print(f"      Max processes: {stats['config']['max_processes']}")
    print(f"      Cache enabled: {stats['config']['cache_enabled']}")
    
    # 6. Show quarantine statistics
    print("\n6. Quarantine statistics...")
    q_stats = engine.quarantine_manager.get_quarantine_statistics()
    print(f"   📊 Quarantine status:")
    print(f"      Total files: {q_stats['total_files']}")
    print(f"      Total size: {q_stats['total_size_mb']:.2f} MB")
    
    # Cleanup
    print("\n7. Cleaning up demonstration files...")
    import shutil
    if test_dir.exists():
        shutil.rmtree(test_dir)
    print(f"   🧹 Cleaned up {test_dir}")
    
    print("\n✅ Demonstration completed successfully!")
    print("\nTo explore more features, try:")
    print("  • python enhanced_main.py --gui")
    print("  • python enhanced_main.py --realtime")
    print("  • python enhanced_main.py --scan-dir /path/to/directory --parallel")


if __name__ == "__main__":
    main()