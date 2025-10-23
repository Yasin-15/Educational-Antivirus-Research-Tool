#!/usr/bin/env python3
"""
Real-Time File System Monitor for Educational Antivirus Tool.

This module provides cross-platform real-time file system monitoring
with automatic threat detection and quarantine capabilities.
"""
import os
import sys
import time
import threading
import queue
from pathlib import Path
from typing import Dict, List, Set, Optional, Callable, Any
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json

# Cross-platform file monitoring
try:
    # Windows
    import win32file
    import win32con
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

try:
    # Linux/macOS - using polling as fallback
    import select
    UNIX_AVAILABLE = True
except ImportError:
    UNIX_AVAILABLE = False

from core.models import Detection, DetectionType, ScanResult, ScanStatus


@dataclass
class FileEvent:
    """Represents a file system event."""
    event_type: str  # created, modified, deleted, moved
    file_path: str
    timestamp: datetime
    file_size: int = 0
    file_hash: str = ""
    old_path: str = ""  # For move events


@dataclass
class MonitorConfig:
    """Configuration for file monitoring."""
    watch_paths: List[str]
    exclude_paths: List[str]
    exclude_extensions: List[str]
    max_file_size_mb: int
    scan_on_create: bool
    scan_on_modify: bool
    auto_quarantine: bool
    notification_callback: Optional[Callable] = None


class FileSystemMonitor:
    """Cross-platform real-time file system monitor."""
    
    def __init__(self, config: MonitorConfig, scanner_engine=None):
        """Initialize file system monitor."""
        self.config = config
        self.scanner_engine = scanner_engine
        self.is_monitoring = False
        self.monitor_threads = []
        self.event_queue = queue.Queue()
        self.processed_files = {}  # Cache to avoid duplicate processing
        self.quarantine_manager = None
        
        # Statistics
        self.stats = {
            'files_monitored': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'events_processed': 0,
            'start_time': None
        }
        
        # Initialize platform-specific monitor
        self.platform_monitor = self._create_platform_monitor()
    
    def start_monitoring(self):
        """Start real-time file monitoring."""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.stats['start_time'] = datetime.now()
        
        print("🔍 Starting real-time file system monitoring...")
        
        # Start event processing thread
        processing_thread = threading.Thread(target=self._process_events, daemon=True)
        processing_thread.start()
        self.monitor_threads.append(processing_thread)
        
        # Start platform-specific monitoring
        for watch_path in self.config.watch_paths:
            if os.path.exists(watch_path):
                monitor_thread = threading.Thread(
                    target=self._monitor_directory,
                    args=(watch_path,),
                    daemon=True
                )
                monitor_thread.start()
                self.monitor_threads.append(monitor_thread)
                print(f"  📁 Monitoring: {watch_path}")
        
        print("✅ Real-time monitoring active")
    
    def stop_monitoring(self):
        """Stop real-time file monitoring."""
        if not self.is_monitoring:
            return
        
        print("🛑 Stopping real-time file monitoring...")
        self.is_monitoring = False
        
        # Wait for threads to finish (with timeout)
        for thread in self.monitor_threads:
            thread.join(timeout=2.0)
        
        self.monitor_threads.clear()
        print("✅ Real-time monitoring stopped")
        
        # Print statistics
        self._print_statistics()
    
    def add_watch_path(self, path: str):
        """Add a new path to monitor."""
        if path not in self.config.watch_paths:
            self.config.watch_paths.append(path)
            
            if self.is_monitoring and os.path.exists(path):
                monitor_thread = threading.Thread(
                    target=self._monitor_directory,
                    args=(path,),
                    daemon=True
                )
                monitor_thread.start()
                self.monitor_threads.append(monitor_thread)
                print(f"📁 Added monitoring: {path}")
    
    def remove_watch_path(self, path: str):
        """Remove a path from monitoring."""
        if path in self.config.watch_paths:
            self.config.watch_paths.remove(path)
            print(f"📁 Removed monitoring: {path}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        stats = self.stats.copy()
        if stats['start_time']:
            stats['uptime_seconds'] = (datetime.now() - stats['start_time']).total_seconds()
        return stats
    
    def _create_platform_monitor(self):
        """Create platform-specific file monitor."""
        if sys.platform.startswith('win') and WINDOWS_AVAILABLE:
            return WindowsFileMonitor(self)
        else:
            return PollingFileMonitor(self)
    
    def _monitor_directory(self, directory_path: str):
        """Monitor a specific directory."""
        try:
            self.platform_monitor.monitor_directory(directory_path)
        except Exception as e:
            print(f"❌ Error monitoring {directory_path}: {e}")
    
    def _process_events(self):
        """Process file system events from the queue."""
        while self.is_monitoring:
            try:
                # Get event with timeout
                event = self.event_queue.get(timeout=1.0)
                self._handle_file_event(event)
                self.stats['events_processed'] += 1
                self.event_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"❌ Error processing event: {e}")
    
    def _handle_file_event(self, event: FileEvent):
        """Handle a single file system event."""
        try:
            # Check if we should process this file
            if not self._should_process_file(event.file_path, event.event_type):
                return
            
            # Avoid duplicate processing
            file_key = f"{event.file_path}:{event.file_hash}"
            if file_key in self.processed_files:
                return
            
            print(f"🔍 Processing: {event.event_type} - {event.file_path}")
            
            # Scan the file if configured
            if ((event.event_type == "created" and self.config.scan_on_create) or
                (event.event_type == "modified" and self.config.scan_on_modify)):
                
                self._scan_file(event)
            
            # Mark as processed
            self.processed_files[file_key] = datetime.now()
            self.stats['files_monitored'] += 1
            
            # Clean old entries from processed files cache
            self._cleanup_processed_cache()
            
        except Exception as e:
            print(f"❌ Error handling file event: {e}")
    
    def _should_process_file(self, file_path: str, event_type: str) -> bool:
        """Check if a file should be processed."""
        path_obj = Path(file_path)
        
        # Check if file exists (for create/modify events)
        if event_type in ["created", "modified"] and not path_obj.exists():
            return False
        
        # Check exclude paths
        for exclude_path in self.config.exclude_paths:
            if exclude_path in file_path:
                return False
        
        # Check exclude extensions
        if path_obj.suffix.lower() in self.config.exclude_extensions:
            return False
        
        # Check file size
        if event_type in ["created", "modified"]:
            try:
                file_size = path_obj.stat().st_size
                max_size = self.config.max_file_size_mb * 1024 * 1024
                if file_size > max_size:
                    return False
            except OSError:
                return False
        
        return True
    
    def _scan_file(self, event: FileEvent):
        """Scan a file for threats."""
        if not self.scanner_engine:
            return
        
        try:
            # Perform scan
            scan_result = self.scanner_engine.scan_file(event.file_path)
            
            if scan_result and scan_result.threats_found > 0:
                print(f"🚨 THREAT DETECTED: {event.file_path}")
                self.stats['threats_detected'] += 1
                
                # Handle threat
                self._handle_threat_detection(event, scan_result)
                
                # Notify if callback is set
                if self.config.notification_callback:
                    self.config.notification_callback(event, scan_result)
        
        except Exception as e:
            print(f"❌ Error scanning file {event.file_path}: {e}")
    
    def _handle_threat_detection(self, event: FileEvent, scan_result: ScanResult):
        """Handle detected threat."""
        if self.config.auto_quarantine and self.quarantine_manager:
            try:
                # Quarantine the file
                quarantine_result = self.quarantine_manager.quarantine_file(
                    event.file_path,
                    scan_result.detections[0] if scan_result.detections else None
                )
                
                if quarantine_result:
                    print(f"🔒 File quarantined: {event.file_path}")
                    self.stats['files_quarantined'] += 1
                else:
                    print(f"❌ Failed to quarantine: {event.file_path}")
            
            except Exception as e:
                print(f"❌ Error quarantining file: {e}")
    
    def _cleanup_processed_cache(self):
        """Clean old entries from processed files cache."""
        if len(self.processed_files) > 1000:  # Limit cache size
            cutoff_time = datetime.now() - timedelta(hours=1)
            self.processed_files = {
                k: v for k, v in self.processed_files.items()
                if v > cutoff_time
            }
    
    def _print_statistics(self):
        """Print monitoring statistics."""
        stats = self.get_statistics()
        print("\n📊 Monitoring Statistics:")
        print(f"  Files monitored: {stats['files_monitored']}")
        print(f"  Threats detected: {stats['threats_detected']}")
        print(f"  Files quarantined: {stats['files_quarantined']}")
        print(f"  Events processed: {stats['events_processed']}")
        if 'uptime_seconds' in stats:
            print(f"  Uptime: {stats['uptime_seconds']:.1f} seconds")


class WindowsFileMonitor:
    """Windows-specific file monitor using ReadDirectoryChangesW."""
    
    def __init__(self, parent_monitor):
        """Initialize Windows file monitor."""
        self.parent = parent_monitor
    
    def monitor_directory(self, directory_path: str):
        """Monitor directory using Windows API."""
        if not WINDOWS_AVAILABLE:
            raise RuntimeError("Windows API not available")
        
        try:
            # Open directory handle
            handle = win32file.CreateFile(
                directory_path,
                win32file.GENERIC_READ,
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
                None,
                win32file.OPEN_EXISTING,
                win32file.FILE_FLAG_BACKUP_SEMANTICS,
                None
            )
            
            # Monitor for changes
            while self.parent.is_monitoring:
                try:
                    results = win32file.ReadDirectoryChangesW(
                        handle,
                        8192,  # Buffer size
                        True,  # Watch subdirectories
                        win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                        win32con.FILE_NOTIFY_CHANGE_SIZE |
                        win32con.FILE_NOTIFY_CHANGE_LAST_WRITE,
                        None,
                        None
                    )
                    
                    for action, filename in results:
                        file_path = os.path.join(directory_path, filename)
                        event_type = self._map_windows_action(action)
                        
                        if event_type:
                            event = self._create_file_event(file_path, event_type)
                            self.parent.event_queue.put(event)
                
                except Exception as e:
                    if self.parent.is_monitoring:
                        print(f"❌ Windows monitor error: {e}")
                    break
        
        except Exception as e:
            print(f"❌ Failed to start Windows monitoring for {directory_path}: {e}")
    
    def _map_windows_action(self, action: int) -> Optional[str]:
        """Map Windows file action to event type."""
        action_map = {
            win32con.FILE_ACTION_ADDED: "created",
            win32con.FILE_ACTION_REMOVED: "deleted",
            win32con.FILE_ACTION_MODIFIED: "modified",
            win32con.FILE_ACTION_RENAMED_OLD_NAME: "moved",
            win32con.FILE_ACTION_RENAMED_NEW_NAME: "moved"
        }
        return action_map.get(action)
    
    def _create_file_event(self, file_path: str, event_type: str) -> FileEvent:
        """Create file event with metadata."""
        file_size = 0
        file_hash = ""
        
        try:
            if os.path.exists(file_path) and event_type != "deleted":
                stat_info = os.stat(file_path)
                file_size = stat_info.st_size
                
                # Calculate hash for small files
                if file_size < 1024 * 1024:  # 1MB limit
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.md5(f.read()).hexdigest()
        except Exception:
            pass
        
        return FileEvent(
            event_type=event_type,
            file_path=file_path,
            timestamp=datetime.now(),
            file_size=file_size,
            file_hash=file_hash
        )


class PollingFileMonitor:
    """Cross-platform file monitor using polling."""
    
    def __init__(self, parent_monitor):
        """Initialize polling file monitor."""
        self.parent = parent_monitor
        self.file_states = {}  # Track file states
    
    def monitor_directory(self, directory_path: str):
        """Monitor directory using polling."""
        print(f"📊 Using polling monitor for: {directory_path}")
        
        # Initial scan
        self._scan_directory(directory_path, initial=True)
        
        # Polling loop
        while self.parent.is_monitoring:
            try:
                self._scan_directory(directory_path)
                time.sleep(2.0)  # Poll every 2 seconds
            except Exception as e:
                if self.parent.is_monitoring:
                    print(f"❌ Polling monitor error: {e}")
                break
    
    def _scan_directory(self, directory_path: str, initial: bool = False):
        """Scan directory for changes."""
        try:
            current_files = {}
            
            # Walk directory tree
            for root, dirs, files in os.walk(directory_path):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    
                    try:
                        stat_info = os.stat(file_path)
                        file_state = {
                            'size': stat_info.st_size,
                            'mtime': stat_info.st_mtime,
                            'exists': True
                        }
                        current_files[file_path] = file_state
                        
                        # Check for changes
                        if not initial:
                            old_state = self.file_states.get(file_path)
                            
                            if old_state is None:
                                # New file
                                event = self._create_file_event(file_path, "created")
                                self.parent.event_queue.put(event)
                            
                            elif (old_state['size'] != file_state['size'] or
                                  old_state['mtime'] != file_state['mtime']):
                                # Modified file
                                event = self._create_file_event(file_path, "modified")
                                self.parent.event_queue.put(event)
                    
                    except OSError:
                        continue
            
            # Check for deleted files
            if not initial:
                for file_path in self.file_states:
                    if file_path not in current_files:
                        event = FileEvent(
                            event_type="deleted",
                            file_path=file_path,
                            timestamp=datetime.now()
                        )
                        self.parent.event_queue.put(event)
            
            # Update file states
            self.file_states = current_files
        
        except Exception as e:
            print(f"❌ Error scanning directory {directory_path}: {e}")
    
    def _create_file_event(self, file_path: str, event_type: str) -> FileEvent:
        """Create file event with metadata."""
        file_size = 0
        file_hash = ""
        
        try:
            if os.path.exists(file_path):
                stat_info = os.stat(file_path)
                file_size = stat_info.st_size
                
                # Calculate hash for small files
                if file_size < 1024 * 1024:  # 1MB limit
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.md5(f.read()).hexdigest()
        except Exception:
            pass
        
        return FileEvent(
            event_type=event_type,
            file_path=file_path,
            timestamp=datetime.now(),
            file_size=file_size,
            file_hash=file_hash
        )


class RealTimeProtectionManager:
    """Manager for real-time protection services."""
    
    def __init__(self, config, scanner_engine=None, quarantine_manager=None):
        """Initialize real-time protection manager."""
        self.config = config
        self.scanner_engine = scanner_engine
        self.quarantine_manager = quarantine_manager
        self.file_monitor = None
        self.is_active = False
        
        # Default monitoring configuration
        self.monitor_config = MonitorConfig(
            watch_paths=self._get_default_watch_paths(),
            exclude_paths=self._get_default_exclude_paths(),
            exclude_extensions=['.tmp', '.log', '.bak', '.swp'],
            max_file_size_mb=config.max_file_size_mb if config else 50,
            scan_on_create=True,
            scan_on_modify=True,
            auto_quarantine=True,
            notification_callback=self._threat_notification
        )
    
    def start_protection(self):
        """Start real-time protection."""
        if self.is_active:
            return
        
        print("🛡️ Starting Real-Time Protection...")
        
        # Create file monitor
        self.file_monitor = FileSystemMonitor(
            self.monitor_config,
            self.scanner_engine
        )
        self.file_monitor.quarantine_manager = self.quarantine_manager
        
        # Start monitoring
        self.file_monitor.start_monitoring()
        self.is_active = True
        
        print("✅ Real-Time Protection is now active")
    
    def stop_protection(self):
        """Stop real-time protection."""
        if not self.is_active:
            return
        
        print("🛑 Stopping Real-Time Protection...")
        
        if self.file_monitor:
            self.file_monitor.stop_monitoring()
            self.file_monitor = None
        
        self.is_active = False
        print("✅ Real-Time Protection stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get real-time protection status."""
        status = {
            'active': self.is_active,
            'monitored_paths': len(self.monitor_config.watch_paths),
            'statistics': {}
        }
        
        if self.file_monitor:
            status['statistics'] = self.file_monitor.get_statistics()
        
        return status
    
    def add_exclusion(self, path: str):
        """Add path to exclusion list."""
        if path not in self.monitor_config.exclude_paths:
            self.monitor_config.exclude_paths.append(path)
            print(f"➕ Added exclusion: {path}")
    
    def remove_exclusion(self, path: str):
        """Remove path from exclusion list."""
        if path in self.monitor_config.exclude_paths:
            self.monitor_config.exclude_paths.remove(path)
            print(f"➖ Removed exclusion: {path}")
    
    def _get_default_watch_paths(self) -> List[str]:
        """Get default paths to monitor."""
        paths = []
        
        # User directories
        home_dir = Path.home()
        paths.extend([
            str(home_dir / "Downloads"),
            str(home_dir / "Documents"),
            str(home_dir / "Desktop")
        ])
        
        # System directories (if accessible)
        if sys.platform.startswith('win'):
            paths.extend([
                "C:\\Windows\\Temp",
                "C:\\Users\\Public"
            ])
        else:
            paths.extend([
                "/tmp",
                "/var/tmp"
            ])
        
        # Filter existing paths
        return [path for path in paths if os.path.exists(path)]
    
    def _get_default_exclude_paths(self) -> List[str]:
        """Get default paths to exclude from monitoring."""
        exclude_paths = []
        
        if sys.platform.startswith('win'):
            exclude_paths.extend([
                "C:\\Windows\\System32",
                "C:\\Program Files",
                "C:\\Program Files (x86)"
            ])
        else:
            exclude_paths.extend([
                "/proc",
                "/sys",
                "/dev"
            ])
        
        return exclude_paths
    
    def _threat_notification(self, event: FileEvent, scan_result: ScanResult):
        """Handle threat detection notification."""
        print(f"\n🚨 REAL-TIME THREAT ALERT 🚨")
        print(f"File: {event.file_path}")
        print(f"Event: {event.event_type}")
        print(f"Threats: {scan_result.threats_found}")
        
        if scan_result.detections:
            for detection in scan_result.detections[:3]:  # Show first 3
                print(f"  - {detection.threat_name} (Risk: {detection.risk_score})")
        
        print(f"Time: {event.timestamp}")
        print("=" * 50)


# Example usage and testing
def create_test_monitor():
    """Create a test file monitor for demonstration."""
    config = MonitorConfig(
        watch_paths=["./test_monitor"],
        exclude_paths=[],
        exclude_extensions=['.log'],
        max_file_size_mb=10,
        scan_on_create=True,
        scan_on_modify=True,
        auto_quarantine=False
    )
    
    return FileSystemMonitor(config)


if __name__ == "__main__":
    # Test the file monitor
    print("🧪 Testing Real-Time File Monitor")
    
    # Create test directory
    test_dir = Path("./test_monitor")
    test_dir.mkdir(exist_ok=True)
    
    # Create and start monitor
    monitor = create_test_monitor()
    
    try:
        monitor.start_monitoring()
        
        print("Monitor is running. Create/modify files in ./test_monitor to see events.")
        print("Press Ctrl+C to stop...")
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop_monitoring()
    
    finally:
        # Cleanup
        import shutil
        if test_dir.exists():
            shutil.rmtree(test_dir)