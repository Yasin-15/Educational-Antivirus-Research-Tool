#!/usr/bin/env python3
"""
Parallel Scanner for Educational Antivirus Tool.

This module provides high-performance scanning capabilities using
multithreading, multiprocessing, and optimized algorithms.
"""
import os
import time
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Iterator, Tuple
from dataclasses import dataclass
from datetime import datetime
import queue
import hashlib
import psutil

from core.models import ScanResult, Detection, ScanStatus, ScanOptions


@dataclass
class ScanTask:
    """Represents a single file scan task."""
    file_path: str
    file_size: int
    priority: int = 0
    task_id: str = ""


@dataclass
class ScanProgress:
    """Tracks scanning progress."""
    total_files: int
    scanned_files: int
    current_file: str
    threats_found: int
    elapsed_time: float
    estimated_remaining: float
    scan_rate: float  # files per second


@dataclass
class PerformanceConfig:
    """Configuration for performance optimization."""
    max_threads: int = 0  # 0 = auto-detect
    max_processes: int = 0  # 0 = auto-detect
    use_multiprocessing: bool = True
    use_multithreading: bool = True
    chunk_size: int = 100
    priority_scanning: bool = True
    memory_limit_mb: int = 1024
    cpu_limit_percent: int = 80
    io_optimization: bool = True
    cache_enabled: bool = True
    progress_callback: Optional[Callable] = None


class FileCache:
    """Cache for file hashes and scan results."""
    
    def __init__(self, max_size: int = 10000):
        """Initialize file cache."""
        self.max_size = max_size
        self.cache = {}
        self.access_times = {}
        self.lock = threading.Lock()
    
    def get(self, file_path: str, file_mtime: float) -> Optional[Any]:
        """Get cached result if file hasn't changed."""
        with self.lock:
            cache_key = f"{file_path}:{file_mtime}"
            
            if cache_key in self.cache:
                self.access_times[cache_key] = time.time()
                return self.cache[cache_key]
            
            return None
    
    def put(self, file_path: str, file_mtime: float, result: Any):
        """Cache scan result."""
        with self.lock:
            cache_key = f"{file_path}:{file_mtime}"
            
            # Evict old entries if cache is full
            if len(self.cache) >= self.max_size:
                self._evict_oldest()
            
            self.cache[cache_key] = result
            self.access_times[cache_key] = time.time()
    
    def _evict_oldest(self):
        """Evict oldest cache entry."""
        if not self.access_times:
            return
        
        oldest_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        del self.cache[oldest_key]
        del self.access_times[oldest_key]
    
    def clear(self):
        """Clear cache."""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
    
    def get_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        with self.lock:
            return {
                'entries': len(self.cache),
                'max_size': self.max_size
            }


class ResourceMonitor:
    """Monitors system resources during scanning."""
    
    def __init__(self, config: PerformanceConfig):
        """Initialize resource monitor."""
        self.config = config
        self.monitoring = False
        self.stats = {
            'cpu_usage': [],
            'memory_usage': [],
            'disk_io': [],
            'peak_memory': 0,
            'peak_cpu': 0
        }
        self.monitor_thread = None
    
    def start_monitoring(self):
        """Start resource monitoring."""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
    
    def _monitor_loop(self):
        """Resource monitoring loop."""
        while self.monitoring:
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                self.stats['cpu_usage'].append(cpu_percent)
                self.stats['peak_cpu'] = max(self.stats['peak_cpu'], cpu_percent)
                
                # Memory usage
                memory = psutil.virtual_memory()
                memory_mb = memory.used / (1024 * 1024)
                self.stats['memory_usage'].append(memory_mb)
                self.stats['peak_memory'] = max(self.stats['peak_memory'], memory_mb)
                
                # Disk I/O
                disk_io = psutil.disk_io_counters()
                if disk_io:
                    self.stats['disk_io'].append({
                        'read_bytes': disk_io.read_bytes,
                        'write_bytes': disk_io.write_bytes
                    })
                
                # Keep only last 100 measurements
                for key in ['cpu_usage', 'memory_usage', 'disk_io']:
                    if len(self.stats[key]) > 100:
                        self.stats[key] = self.stats[key][-100:]
                
                # Check resource limits
                if cpu_percent > self.config.cpu_limit_percent:
                    time.sleep(0.1)  # Throttle if CPU usage is high
                
                if memory_mb > self.config.memory_limit_mb:
                    # Force garbage collection if memory usage is high
                    import gc
                    gc.collect()
                
            except Exception as e:
                print(f"❌ Resource monitoring error: {e}")
            
            time.sleep(1)
    
    def get_current_stats(self) -> Dict[str, Any]:
        """Get current resource statistics."""
        try:
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_mb': memory.used / (1024 * 1024),
                'available_memory_mb': memory.available / (1024 * 1024),
                'peak_cpu': self.stats['peak_cpu'],
                'peak_memory': self.stats['peak_memory']
            }
        except Exception:
            return {}


class ParallelScanner:
    """High-performance parallel file scanner."""
    
    def __init__(self, scanner_engine, config: Optional[PerformanceConfig] = None):
        """Initialize parallel scanner."""
        self.scanner_engine = scanner_engine
        self.config = config or PerformanceConfig()
        
        # Auto-detect optimal thread/process counts
        if self.config.max_threads == 0:
            self.config.max_threads = min(32, (os.cpu_count() or 1) * 2)
        
        if self.config.max_processes == 0:
            self.config.max_processes = min(8, os.cpu_count() or 1)
        
        # Initialize components
        self.file_cache = FileCache() if self.config.cache_enabled else None
        self.resource_monitor = ResourceMonitor(self.config)
        
        # Scanning state
        self.is_scanning = False
        self.scan_cancelled = False
        self.progress = ScanProgress(0, 0, "", 0, 0.0, 0.0, 0.0)
        self.progress_lock = threading.Lock()
        
        print(f"⚡ Parallel Scanner initialized:")
        print(f"   Max threads: {self.config.max_threads}")
        print(f"   Max processes: {self.config.max_processes}")
        print(f"   Multiprocessing: {self.config.use_multiprocessing}")
        print(f"   Caching: {self.config.cache_enabled}")
    
    def scan_path(self, scan_path: str, scan_options: Optional[ScanOptions] = None) -> ScanResult:
        """Scan a path using parallel processing."""
        start_time = time.time()
        
        try:
            self.is_scanning = True
            self.scan_cancelled = False
            
            print(f"🚀 Starting parallel scan: {scan_path}")
            
            # Start resource monitoring
            self.resource_monitor.start_monitoring()
            
            # Discover files to scan
            print("📁 Discovering files...")
            scan_tasks = list(self._discover_files(scan_path, scan_options))
            
            if not scan_tasks:
                return self._create_empty_result(scan_path, start_time)
            
            # Initialize progress
            with self.progress_lock:
                self.progress = ScanProgress(
                    total_files=len(scan_tasks),
                    scanned_files=0,
                    current_file="",
                    threats_found=0,
                    elapsed_time=0.0,
                    estimated_remaining=0.0,
                    scan_rate=0.0
                )
            
            print(f"📊 Found {len(scan_tasks)} files to scan")
            
            # Sort tasks by priority if enabled
            if self.config.priority_scanning:
                scan_tasks = self._prioritize_tasks(scan_tasks)
            
            # Perform parallel scanning
            detections = self._scan_files_parallel(scan_tasks)
            
            # Create scan result
            end_time = time.time()
            elapsed_time = end_time - start_time
            
            scan_result = ScanResult(
                scan_id=f"parallel_{int(start_time)}",
                start_time=datetime.fromtimestamp(start_time),
                end_time=datetime.fromtimestamp(end_time),
                status=ScanStatus.CANCELLED if self.scan_cancelled else ScanStatus.COMPLETED,
                files_scanned=self.progress.scanned_files,
                threats_found=len(detections),
                detections=detections,
                errors=[],
                scan_path=scan_path
            )
            
            # Print performance summary
            self._print_performance_summary(elapsed_time, len(scan_tasks), len(detections))
            
            return scan_result
            
        except Exception as e:
            print(f"❌ Parallel scan failed: {e}")
            return self._create_error_result(scan_path, start_time, str(e))
        
        finally:
            self.is_scanning = False
            self.resource_monitor.stop_monitoring()
    
    def cancel_scan(self):
        """Cancel the current scan."""
        self.scan_cancelled = True
        print("🛑 Scan cancellation requested")
    
    def get_progress(self) -> ScanProgress:
        """Get current scan progress."""
        with self.progress_lock:
            return self.progress
    
    def _discover_files(self, scan_path: str, scan_options: Optional[ScanOptions]) -> Iterator[ScanTask]:
        """Discover files to scan."""
        path_obj = Path(scan_path)
        
        if path_obj.is_file():
            # Single file
            try:
                file_size = path_obj.stat().st_size
                yield ScanTask(
                    file_path=str(path_obj),
                    file_size=file_size,
                    task_id=f"file_{hash(str(path_obj))}"
                )
            except OSError:
                pass
            return
        
        # Directory scanning
        if not path_obj.is_dir():
            return
        
        try:
            # Use os.walk for better performance than Path.rglob
            for root, dirs, files in os.walk(path_obj):
                # Check for cancellation
                if self.scan_cancelled:
                    break
                
                # Filter directories if needed
                if scan_options and not scan_options.recursive:
                    dirs.clear()  # Don't recurse
                
                for filename in files:
                    if self.scan_cancelled:
                        break
                    
                    file_path = Path(root) / filename
                    
                    # Apply filters
                    if not self._should_scan_file(file_path, scan_options):
                        continue
                    
                    try:
                        file_size = file_path.stat().st_size
                        
                        # Calculate priority
                        priority = self._calculate_file_priority(file_path, file_size)
                        
                        yield ScanTask(
                            file_path=str(file_path),
                            file_size=file_size,
                            priority=priority,
                            task_id=f"file_{hash(str(file_path))}"
                        )
                        
                    except OSError:
                        continue
        
        except Exception as e:
            print(f"❌ File discovery error: {e}")
    
    def _should_scan_file(self, file_path: Path, scan_options: Optional[ScanOptions]) -> bool:
        """Check if a file should be scanned."""
        if not scan_options:
            return True
        
        # Check file size limit
        try:
            file_size = file_path.stat().st_size
            max_size = scan_options.max_file_size_mb * 1024 * 1024
            if file_size > max_size:
                return False
        except OSError:
            return False
        
        # Check skip extensions
        if file_path.suffix.lower() in scan_options.skip_extensions:
            return False
        
        # Check include patterns
        if scan_options.include_patterns:
            if not any(pattern in str(file_path) for pattern in scan_options.include_patterns):
                return False
        
        # Check exclude patterns
        if scan_options.exclude_patterns:
            if any(pattern in str(file_path) for pattern in scan_options.exclude_patterns):
                return False
        
        return True
    
    def _calculate_file_priority(self, file_path: Path, file_size: int) -> int:
        """Calculate scanning priority for a file."""
        priority = 0
        
        # Higher priority for executable files
        if file_path.suffix.lower() in ['.exe', '.dll', '.scr', '.bat', '.cmd']:
            priority += 100
        
        # Higher priority for recently modified files
        try:
            mtime = file_path.stat().st_mtime
            age_days = (time.time() - mtime) / (24 * 3600)
            if age_days < 7:
                priority += 50
            elif age_days < 30:
                priority += 25
        except OSError:
            pass
        
        # Higher priority for smaller files (scan faster)
        if file_size < 1024 * 1024:  # < 1MB
            priority += 30
        elif file_size < 10 * 1024 * 1024:  # < 10MB
            priority += 10
        
        # Higher priority for suspicious locations
        suspicious_paths = ['temp', 'tmp', 'downloads', 'desktop']
        if any(sus_path in str(file_path).lower() for sus_path in suspicious_paths):
            priority += 20
        
        return priority
    
    def _prioritize_tasks(self, tasks: List[ScanTask]) -> List[ScanTask]:
        """Sort tasks by priority."""
        return sorted(tasks, key=lambda t: t.priority, reverse=True)
    
    def _scan_files_parallel(self, tasks: List[ScanTask]) -> List[Detection]:
        """Scan files using parallel processing."""
        all_detections = []
        
        if self.config.use_multiprocessing and len(tasks) > 100:
            # Use multiprocessing for large scans
            detections = self._scan_with_multiprocessing(tasks)
        else:
            # Use multithreading for smaller scans
            detections = self._scan_with_multithreading(tasks)
        
        all_detections.extend(detections)
        return all_detections
    
    def _scan_with_multithreading(self, tasks: List[ScanTask]) -> List[Detection]:
        """Scan files using multithreading."""
        detections = []
        
        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            # Submit tasks in chunks
            chunk_size = self.config.chunk_size
            
            for i in range(0, len(tasks), chunk_size):
                if self.scan_cancelled:
                    break
                
                chunk = tasks[i:i + chunk_size]
                
                # Submit chunk tasks
                future_to_task = {
                    executor.submit(self._scan_single_file, task): task
                    for task in chunk
                }
                
                # Collect results
                for future in as_completed(future_to_task):
                    if self.scan_cancelled:
                        break
                    
                    task = future_to_task[future]
                    
                    try:
                        result = future.result(timeout=30)  # 30 second timeout per file
                        
                        if result:
                            detections.extend(result)
                        
                        # Update progress
                        self._update_progress(task.file_path)
                        
                    except Exception as e:
                        print(f"❌ Scan error for {task.file_path}: {e}")
                        self._update_progress(task.file_path)
        
        return detections
    
    def _scan_with_multiprocessing(self, tasks: List[ScanTask]) -> List[Detection]:
        """Scan files using multiprocessing."""
        detections = []
        
        # Split tasks into chunks for processes
        chunk_size = max(1, len(tasks) // self.config.max_processes)
        task_chunks = [tasks[i:i + chunk_size] for i in range(0, len(tasks), chunk_size)]
        
        with ProcessPoolExecutor(max_workers=self.config.max_processes) as executor:
            # Submit chunk tasks
            future_to_chunk = {
                executor.submit(self._scan_task_chunk, chunk): chunk
                for chunk in task_chunks
            }
            
            # Collect results
            for future in as_completed(future_to_chunk):
                if self.scan_cancelled:
                    break
                
                try:
                    chunk_detections = future.result(timeout=300)  # 5 minute timeout per chunk
                    detections.extend(chunk_detections)
                    
                except Exception as e:
                    print(f"❌ Process chunk error: {e}")
        
        return detections
    
    def _scan_single_file(self, task: ScanTask) -> List[Detection]:
        """Scan a single file."""
        if self.scan_cancelled:
            return []
        
        file_path = task.file_path
        
        try:
            # Check cache first
            if self.file_cache:
                try:
                    file_mtime = os.path.getmtime(file_path)
                    cached_result = self.file_cache.get(file_path, file_mtime)
                    if cached_result is not None:
                        return cached_result
                except OSError:
                    pass
            
            # Perform actual scan
            detections = []
            
            if self.scanner_engine:
                scan_result = self.scanner_engine.scan_file(file_path)
                if scan_result and scan_result.detections:
                    detections = scan_result.detections
            
            # Cache result
            if self.file_cache:
                try:
                    file_mtime = os.path.getmtime(file_path)
                    self.file_cache.put(file_path, file_mtime, detections)
                except OSError:
                    pass
            
            return detections
            
        except Exception as e:
            print(f"❌ Error scanning {file_path}: {e}")
            return []
    
    def _scan_task_chunk(self, tasks: List[ScanTask]) -> List[Detection]:
        """Scan a chunk of tasks (for multiprocessing)."""
        all_detections = []
        
        for task in tasks:
            detections = self._scan_single_file(task)
            all_detections.extend(detections)
            
            # Update progress (approximate for multiprocessing)
            self._update_progress(task.file_path)
        
        return all_detections
    
    def _update_progress(self, current_file: str):
        """Update scan progress."""
        with self.progress_lock:
            self.progress.scanned_files += 1
            self.progress.current_file = current_file
            
            # Calculate timing
            elapsed = time.time() - (self.progress.elapsed_time or time.time())
            self.progress.elapsed_time = elapsed
            
            if self.progress.scanned_files > 0:
                self.progress.scan_rate = self.progress.scanned_files / elapsed
                
                remaining_files = self.progress.total_files - self.progress.scanned_files
                if self.progress.scan_rate > 0:
                    self.progress.estimated_remaining = remaining_files / self.progress.scan_rate
            
            # Call progress callback if set
            if self.config.progress_callback:
                try:
                    self.config.progress_callback(self.progress)
                except Exception:
                    pass
    
    def _create_empty_result(self, scan_path: str, start_time: float) -> ScanResult:
        """Create empty scan result."""
        return ScanResult(
            scan_id=f"empty_{int(start_time)}",
            start_time=datetime.fromtimestamp(start_time),
            end_time=datetime.now(),
            status=ScanStatus.COMPLETED,
            files_scanned=0,
            threats_found=0,
            detections=[],
            errors=[],
            scan_path=scan_path
        )
    
    def _create_error_result(self, scan_path: str, start_time: float, error: str) -> ScanResult:
        """Create error scan result."""
        return ScanResult(
            scan_id=f"error_{int(start_time)}",
            start_time=datetime.fromtimestamp(start_time),
            end_time=datetime.now(),
            status=ScanStatus.FAILED,
            files_scanned=0,
            threats_found=0,
            detections=[],
            errors=[error],
            scan_path=scan_path
        )
    
    def _print_performance_summary(self, elapsed_time: float, total_files: int, threats_found: int):
        """Print performance summary."""
        print(f"\n📊 Scan Performance Summary:")
        print(f"   Total files: {total_files}")
        print(f"   Threats found: {threats_found}")
        print(f"   Elapsed time: {elapsed_time:.2f} seconds")
        
        if elapsed_time > 0:
            scan_rate = total_files / elapsed_time
            print(f"   Scan rate: {scan_rate:.1f} files/second")
        
        # Resource usage
        resource_stats = self.resource_monitor.get_current_stats()
        if resource_stats:
            print(f"   Peak CPU: {resource_stats.get('peak_cpu', 0):.1f}%")
            print(f"   Peak Memory: {resource_stats.get('peak_memory', 0):.1f} MB")
        
        # Cache statistics
        if self.file_cache:
            cache_stats = self.file_cache.get_stats()
            print(f"   Cache entries: {cache_stats['entries']}")
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get detailed performance statistics."""
        stats = {
            'config': {
                'max_threads': self.config.max_threads,
                'max_processes': self.config.max_processes,
                'use_multiprocessing': self.config.use_multiprocessing,
                'cache_enabled': self.config.cache_enabled
            },
            'progress': {
                'total_files': self.progress.total_files,
                'scanned_files': self.progress.scanned_files,
                'scan_rate': self.progress.scan_rate,
                'elapsed_time': self.progress.elapsed_time
            },
            'resources': self.resource_monitor.get_current_stats()
        }
        
        if self.file_cache:
            stats['cache'] = self.file_cache.get_stats()
        
        return stats


def create_parallel_scanner(scanner_engine, config: Optional[PerformanceConfig] = None) -> ParallelScanner:
    """Create a parallel scanner with optimal configuration."""
    if config is None:
        # Auto-configure based on system capabilities
        cpu_count = os.cpu_count() or 1
        memory_gb = psutil.virtual_memory().total / (1024**3)
        
        config = PerformanceConfig(
            max_threads=min(32, cpu_count * 2),
            max_processes=min(8, cpu_count),
            use_multiprocessing=cpu_count > 2,
            use_multithreading=True,
            chunk_size=max(50, cpu_count * 10),
            memory_limit_mb=int(memory_gb * 1024 * 0.5),  # Use 50% of available memory
            cpu_limit_percent=80,
            cache_enabled=True
        )
    
    return ParallelScanner(scanner_engine, config)


# Example usage and testing
if __name__ == "__main__":
    print("🧪 Testing Parallel Scanner")
    
    # Create mock scanner engine for testing
    class MockScannerEngine:
        def scan_file(self, file_path: str):
            # Simulate scanning delay
            time.sleep(0.01)
            
            # Simulate occasional detection
            if "test" in file_path.lower():
                from core.models import Detection, DetectionType
                return type('ScanResult', (), {
                    'detections': [Detection(
                        file_path=file_path,
                        threat_name="Test.Threat",
                        detection_type=DetectionType.SIGNATURE,
                        risk_score=50,
                        description="Test detection"
                    )]
                })()
            
            return type('ScanResult', (), {'detections': []})()
    
    # Test configuration
    config = PerformanceConfig(
        max_threads=4,
        max_processes=2,
        use_multiprocessing=False,  # Disable for testing
        cache_enabled=True
    )
    
    # Create scanner
    mock_engine = MockScannerEngine()
    scanner = create_parallel_scanner(mock_engine, config)
    
    # Test scan (use current directory)
    print(f"\n🔍 Testing scan of current directory...")
    
    scan_options = ScanOptions(
        recursive=False,
        max_file_size_mb=10,
        skip_extensions=['.pyc', '.log']
    )
    
    result = scanner.scan_path(".", scan_options)
    
    print(f"\n✅ Scan completed:")
    print(f"   Files scanned: {result.files_scanned}")
    print(f"   Threats found: {result.threats_found}")
    print(f"   Status: {result.status.value}")
    
    # Performance stats
    stats = scanner.get_performance_stats()
    print(f"\n📊 Performance Stats:")
    for category, data in stats.items():
        print(f"   {category}: {data}")