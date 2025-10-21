"""
Main scanning engine for the Educational Antivirus Research Tool.

This module provides the central ScanEngine class that coordinates all scanning
operations, manages detection engines, and provides progress tracking.
"""
import os
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Generator
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from enum import Enum

from core.models import (
    ScanResult, ScanOptions, Detection, ScanStatus, 
    DetectionType, Config
)
from core.exceptions import ScanError, ConfigurationError, QuarantineError
from core.logging_config import get_logger
from core.file_utils import get_file_info
from detection.signature_engine import SignatureEngine
from detection.behavioral_engine import BehavioralAnalysisEngine
from quarantine.quarantine_manager import QuarantineManager

logger = get_logger(__name__)


class ThreatAction(Enum):
    """Actions that can be taken for detected threats."""
    QUARANTINE = "quarantine"
    IGNORE = "ignore"
    DELETE = "delete"
    SKIP = "skip"


class ThreatDecision:
    """Represents a user decision for handling a detected threat."""
    
    def __init__(self, detection: Detection, action: ThreatAction, 
                 reason: str = "", auto_applied: bool = False):
        """Initialize threat decision.
        
        Args:
            detection: The detection that triggered this decision
            action: Action to take for this threat
            reason: Reason for the decision
            auto_applied: Whether this was an automatic decision
        """
        self.detection = detection
        self.action = action
        self.reason = reason
        self.auto_applied = auto_applied
        self.timestamp = datetime.now()
        self.quarantine_id: Optional[str] = None


class ScanProgress:
    """Tracks scanning progress and provides cancellation support."""
    
    def __init__(self, total_files: int = 0):
        """Initialize scan progress tracker.
        
        Args:
            total_files: Total number of files to scan
        """
        self.total_files = total_files
        self.files_scanned = 0
        self.detections_found = 0
        self.errors_encountered = 0
        self.current_file = ""
        self.start_time = datetime.now()
        self.is_cancelled = False
        self._lock = threading.Lock()
    
    def update_file(self, file_path: str) -> None:
        """Update currently scanning file."""
        with self._lock:
            self.current_file = file_path
    
    def increment_scanned(self) -> None:
        """Increment scanned file count."""
        with self._lock:
            self.files_scanned += 1
    
    def increment_detections(self, count: int = 1) -> None:
        """Increment detection count."""
        with self._lock:
            self.detections_found += count
    
    def increment_errors(self) -> None:
        """Increment error count."""
        with self._lock:
            self.errors_encountered += 1
    
    def cancel(self) -> None:
        """Cancel the scanning operation."""
        with self._lock:
            self.is_cancelled = True
    
    def get_progress_info(self) -> Dict[str, Any]:
        """Get current progress information."""
        with self._lock:
            elapsed_time = (datetime.now() - self.start_time).total_seconds()
            
            progress_info = {
                'total_files': self.total_files,
                'files_scanned': self.files_scanned,
                'detections_found': self.detections_found,
                'errors_encountered': self.errors_encountered,
                'current_file': self.current_file,
                'elapsed_time': elapsed_time,
                'is_cancelled': self.is_cancelled
            }
            
            # Calculate progress percentage
            if self.total_files > 0:
                progress_info['progress_percent'] = (self.files_scanned / self.total_files) * 100
            else:
                progress_info['progress_percent'] = 0.0
            
            # Calculate estimated time remaining
            if self.files_scanned > 0 and elapsed_time > 0:
                avg_time_per_file = elapsed_time / self.files_scanned
                remaining_files = self.total_files - self.files_scanned
                progress_info['estimated_remaining'] = avg_time_per_file * remaining_files
            else:
                progress_info['estimated_remaining'] = 0.0
            
            return progress_info


class ScanEngine:
    """
    Main scanning engine that coordinates detection engines and manages scan operations.
    
    This class provides the primary interface for scanning files and directories,
    coordinating signature-based and behavioral detection engines, and managing
    scan progress and results.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize the scan engine.
        
        Args:
            config: Configuration object for the scan engine
        """
        self.config = config or Config()
        self.signature_engine: Optional[SignatureEngine] = None
        self.behavioral_engine: Optional[BehavioralAnalysisEngine] = None
        self.quarantine_manager: Optional[QuarantineManager] = None
        self._initialized = False
        self._scan_history: List[ScanResult] = []
        self._current_scan: Optional[ScanResult] = None
        self._progress: Optional[ScanProgress] = None
        self._progress_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        
        # User interaction callbacks
        self._threat_decision_callback: Optional[Callable[[Detection], ThreatAction]] = None
        
        # Decision history
        self._decision_history: List[ThreatDecision] = []
        
        # Auto-decision rules
        self._auto_quarantine_threshold = 8  # Auto-quarantine high-risk threats
        self._auto_ignore_threshold = 3      # Auto-ignore low-risk threats
        
        logger.info("ScanEngine initialized")
    
    def initialize(self) -> bool:
        """Initialize the scan engine and detection engines.
        
        Returns:
            True if initialization successful
            
        Raises:
            ConfigurationError: If configuration is invalid
            ScanError: If engine initialization fails
        """
        try:
            # Validate configuration
            config_errors = self.config.validate()
            if config_errors:
                raise ConfigurationError(f"Invalid configuration: {', '.join(config_errors)}")
            
            # Initialize signature engine
            logger.info("Initializing signature detection engine...")
            self.signature_engine = SignatureEngine(
                db_path=self.config.signature_db_path,
                sensitivity=self.config.signature_sensitivity
            )
            self.signature_engine.initialize()
            
            # Initialize behavioral analysis engine
            logger.info("Initializing behavioral analysis engine...")
            self.behavioral_engine = BehavioralAnalysisEngine(self.config)
            
            # Initialize quarantine manager
            logger.info("Initializing quarantine manager...")
            self.quarantine_manager = QuarantineManager(self.config.quarantine_path)
            
            self._initialized = True
            logger.info("ScanEngine initialization completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize ScanEngine: {e}")
            raise ScanError(f"Engine initialization failed: {e}")
    
    def scan_path(self, path: str, options: Optional[ScanOptions] = None) -> ScanResult:
        """Scan a file or directory path.
        
        Args:
            path: Path to scan (file or directory)
            options: Scan options, uses defaults if None
            
        Returns:
            ScanResult with scan results and statistics
            
        Raises:
            ScanError: If scanning fails
        """
        if not self._initialized:
            raise ScanError("ScanEngine not initialized - call initialize() first")
        
        if options is None:
            options = ScanOptions()
        
        # Create scan result
        scan_id = str(uuid.uuid4())
        scan_result = ScanResult(
            scan_id=scan_id,
            start_time=datetime.now(),
            scanned_paths=[path],
            scan_options=options,
            status=ScanStatus.RUNNING
        )
        
        self._current_scan = scan_result
        
        try:
            logger.info(f"Starting scan of path: {path}")
            
            # Determine if path is file or directory
            if os.path.isfile(path):
                files_to_scan = [path]
            elif os.path.isdir(path):
                files_to_scan = self._get_files_to_scan(path, options)
            else:
                raise ScanError(f"Path does not exist or is not accessible: {path}")
            
            # Initialize progress tracking
            self._progress = ScanProgress(len(files_to_scan))
            
            # Scan files
            all_detections = []
            all_errors = []
            
            if len(files_to_scan) <= 10:  # Use single-threaded for small scans
                for file_path in files_to_scan:
                    if self._progress.is_cancelled:
                        break
                    
                    try:
                        detections = self._scan_single_file(file_path)
                        all_detections.extend(detections)
                    except Exception as e:
                        error_msg = f"Error scanning {file_path}: {e}"
                        all_errors.append(error_msg)
                        logger.warning(error_msg)
                        self._progress.increment_errors()
                    
                    self._progress.increment_scanned()
                    self._notify_progress()
            else:
                # Use multi-threaded scanning for larger scans
                all_detections, all_errors = self._scan_files_threaded(files_to_scan)
            
            # Complete scan result
            scan_result.end_time = datetime.now()
            scan_result.total_files = len(files_to_scan)
            scan_result.detections = all_detections
            scan_result.errors = all_errors
            scan_result.status = ScanStatus.COMPLETED if not self._progress.is_cancelled else ScanStatus.FAILED
            
            # Add to scan history
            self._scan_history.append(scan_result)
            
            logger.info(f"Scan completed: {len(all_detections)} detections in {len(files_to_scan)} files")
            
            return scan_result
            
        except Exception as e:
            scan_result.end_time = datetime.now()
            scan_result.status = ScanStatus.FAILED
            scan_result.errors.append(str(e))
            self._scan_history.append(scan_result)
            
            logger.error(f"Scan failed: {e}")
            raise ScanError(f"Scan operation failed: {e}")
        
        finally:
            self._current_scan = None
            self._progress = None
    
    def scan_with_quarantine(self, path: str, options: Optional[ScanOptions] = None,
                           interactive: bool = True) -> ScanResult:
        """Scan a path with integrated threat handling and quarantine management.
        
        Args:
            path: Path to scan (file or directory)
            options: Scan options, uses defaults if None
            interactive: Whether to prompt user for threat decisions
            
        Returns:
            ScanResult with threat handling information
            
        Raises:
            ScanError: If scanning fails
        """
        if not self._initialized:
            raise ScanError("ScanEngine not initialized - call initialize() first")
        
        # Perform initial scan
        scan_result = self.scan_path(path, options)
        
        # Process detections with threat handling
        if scan_result.detections:
            processed_decisions = self._process_detections_with_interaction(
                scan_result.detections, interactive
            )
            
            # Update scan result with processing information
            if not hasattr(scan_result, 'details'):
                scan_result.details = {}
            
            scan_result.details.update({
                'threat_decisions': [
                    {
                        'detection_id': decision.detection.file_path,
                        'action': decision.action.value,
                        'reason': decision.reason,
                        'auto_applied': decision.auto_applied,
                        'timestamp': decision.timestamp.isoformat(),
                        'quarantine_id': decision.quarantine_id
                    }
                    for decision in processed_decisions
                ],
                'quarantine_actions': sum(1 for d in processed_decisions 
                                        if d.action == ThreatAction.QUARANTINE),
                'ignored_threats': sum(1 for d in processed_decisions 
                                     if d.action == ThreatAction.IGNORE),
                'deleted_threats': sum(1 for d in processed_decisions 
                                     if d.action == ThreatAction.DELETE)
            })
        
        logger.info(f"Integrated scan completed: {len(scan_result.detections)} threats processed")
        return scan_result
    
    def scan_file(self, file_path: str) -> List[Detection]:
        """Scan a single file using all available detection engines.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            List of Detection objects found
            
        Raises:
            ScanError: If file scanning fails
        """
        if not self._initialized:
            raise ScanError("ScanEngine not initialized - call initialize() first")
        
        return self._scan_single_file(file_path)
    
    def _scan_single_file(self, file_path: str) -> List[Detection]:
        """Internal method to scan a single file with both engines.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            List of Detection objects found
        """
        detections = []
        
        # Update progress
        if self._progress:
            self._progress.update_file(file_path)
        
        try:
            # Check file size limits
            file_info = get_file_info(file_path)
            max_size_bytes = self.config.max_file_size_mb * 1024 * 1024
            
            if file_info.size > max_size_bytes:
                logger.debug(f"Skipping large file: {file_path} ({file_info.size} bytes)")
                return detections
            
            # Signature-based detection
            try:
                signature_detections = self.signature_engine.scan_file(file_path)
                detections.extend(signature_detections)
                logger.debug(f"Signature scan of {file_path}: {len(signature_detections)} detections")
            except Exception as e:
                logger.warning(f"Signature scanning failed for {file_path}: {e}")
            
            # Behavioral analysis (only if no signature detections or if configured to always run)
            try:
                behavioral_result = self.behavioral_engine.analyze_file(file_path)
                
                # Create detection if risk score exceeds threshold
                if behavioral_result.risk_score >= self.config.behavioral_threshold:
                    behavioral_detection = Detection(
                        file_path=file_path,
                        detection_type=DetectionType.BEHAVIORAL,
                        threat_name=f"Suspicious behavior (risk: {behavioral_result.risk_score})",
                        risk_score=behavioral_result.risk_score,
                        timestamp=datetime.now(),
                        details={
                            'entropy': behavioral_result.entropy,
                            'suspicious_patterns': behavioral_result.suspicious_patterns,
                            'analysis_details': behavioral_result.analysis_details,
                            'behavioral_threshold': self.config.behavioral_threshold
                        }
                    )
                    detections.append(behavioral_detection)
                    logger.debug(f"Behavioral detection in {file_path}: risk score {behavioral_result.risk_score}")
                
            except Exception as e:
                logger.warning(f"Behavioral analysis failed for {file_path}: {e}")
            
            # Update progress
            if self._progress and detections:
                self._progress.increment_detections(len(detections))
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            raise
        
        return detections
    
    def _get_files_to_scan(self, directory_path: str, options: ScanOptions) -> List[str]:
        """Get list of files to scan in a directory.
        
        Args:
            directory_path: Path to the directory
            options: Scan options
            
        Returns:
            List of file paths to scan
        """
        files_to_scan = []
        directory = Path(directory_path)
        
        try:
            if options.recursive:
                pattern = "**/*"
            else:
                pattern = "*"
            
            for file_path in directory.glob(pattern):
                if file_path.is_file():
                    # Check if we should skip this file
                    if self._should_skip_file(str(file_path), options):
                        continue
                    
                    # Handle symlinks
                    if file_path.is_symlink() and not options.follow_symlinks:
                        logger.debug(f"Skipping symlink: {file_path}")
                        continue
                    
                    files_to_scan.append(str(file_path))
            
            logger.info(f"Found {len(files_to_scan)} files to scan in {directory_path}")
            
        except Exception as e:
            logger.error(f"Error listing files in {directory_path}: {e}")
            raise ScanError(f"Failed to list files in directory: {e}")
        
        return files_to_scan
    
    def _should_skip_file(self, file_path: str, options: ScanOptions) -> bool:
        """Check if a file should be skipped based on scan options.
        
        Args:
            file_path: Path to the file
            options: Scan options
            
        Returns:
            True if file should be skipped
        """
        file_path_lower = file_path.lower()
        
        # Check skip extensions
        for ext in options.skip_extensions:
            if file_path_lower.endswith(ext.lower()):
                return True
        
        # Check global skip extensions from config
        for ext in self.config.skip_extensions:
            if file_path_lower.endswith(ext.lower()):
                return True
        
        return False
    
    def _scan_files_threaded(self, files_to_scan: List[str]) -> tuple[List[Detection], List[str]]:
        """Scan files using multiple threads for better performance.
        
        Args:
            files_to_scan: List of file paths to scan
            
        Returns:
            Tuple of (all_detections, all_errors)
        """
        all_detections = []
        all_errors = []
        max_workers = min(4, len(files_to_scan))  # Limit concurrent threads
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit scan tasks
            future_to_file = {
                executor.submit(self._scan_single_file, file_path): file_path
                for file_path in files_to_scan
            }
            
            # Process completed scans
            for future in as_completed(future_to_file):
                if self._progress and self._progress.is_cancelled:
                    # Cancel remaining tasks
                    for f in future_to_file:
                        f.cancel()
                    break
                
                file_path = future_to_file[future]
                
                try:
                    detections = future.result()
                    all_detections.extend(detections)
                except Exception as e:
                    error_msg = f"Error scanning {file_path}: {e}"
                    all_errors.append(error_msg)
                    logger.warning(error_msg)
                    if self._progress:
                        self._progress.increment_errors()
                
                if self._progress:
                    self._progress.increment_scanned()
                    self._notify_progress()
        
        return all_detections, all_errors
    
    def _process_detections_with_interaction(self, detections: List[Detection], 
                                           interactive: bool) -> List[ThreatDecision]:
        """Process detections with user interaction for threat handling.
        
        Args:
            detections: List of detections to process
            interactive: Whether to use interactive mode
            
        Returns:
            List of ThreatDecision objects
        """
        decisions = []
        
        for detection in detections:
            try:
                # Determine action for this threat
                if interactive and self._threat_decision_callback:
                    # Use interactive callback
                    action = self._threat_decision_callback(detection)
                    decision = ThreatDecision(
                        detection=detection,
                        action=action,
                        reason="User decision",
                        auto_applied=False
                    )
                else:
                    # Use automatic decision rules
                    decision = self._make_automatic_decision(detection)
                
                # Execute the decision
                self._execute_threat_decision(decision)
                
                decisions.append(decision)
                self._decision_history.append(decision)
                
            except Exception as e:
                logger.error(f"Failed to process detection {detection.file_path}: {e}")
                # Create a skip decision for failed processing
                skip_decision = ThreatDecision(
                    detection=detection,
                    action=ThreatAction.SKIP,
                    reason=f"Processing failed: {e}",
                    auto_applied=True
                )
                decisions.append(skip_decision)
        
        return decisions
    
    def _make_automatic_decision(self, detection: Detection) -> ThreatDecision:
        """Make an automatic decision for a threat based on rules.
        
        Args:
            detection: Detection to make decision for
            
        Returns:
            ThreatDecision with automatic action
        """
        risk_score = detection.risk_score
        
        # High-risk threats: auto-quarantine
        if risk_score >= self._auto_quarantine_threshold:
            return ThreatDecision(
                detection=detection,
                action=ThreatAction.QUARANTINE,
                reason=f"High risk score ({risk_score}) - auto-quarantine",
                auto_applied=True
            )
        
        # Low-risk threats: auto-ignore
        elif risk_score <= self._auto_ignore_threshold:
            return ThreatDecision(
                detection=detection,
                action=ThreatAction.IGNORE,
                reason=f"Low risk score ({risk_score}) - auto-ignore",
                auto_applied=True
            )
        
        # Medium-risk threats: default to quarantine for safety
        else:
            return ThreatDecision(
                detection=detection,
                action=ThreatAction.QUARANTINE,
                reason=f"Medium risk score ({risk_score}) - quarantine for safety",
                auto_applied=True
            )
    
    def _execute_threat_decision(self, decision: ThreatDecision) -> None:
        """Execute a threat decision by performing the specified action.
        
        Args:
            decision: ThreatDecision to execute
            
        Raises:
            QuarantineError: If quarantine action fails
            ScanError: If other actions fail
        """
        detection = decision.detection
        action = decision.action
        
        try:
            if action == ThreatAction.QUARANTINE:
                # Move file to quarantine
                quarantine_id = self.quarantine_manager.quarantine_file(
                    detection.file_path, detection
                )
                logger.info(f"File quarantined: {detection.file_path} -> {quarantine_id}")
                
                # Update decision with quarantine ID
                decision.quarantine_id = quarantine_id
            
            elif action == ThreatAction.DELETE:
                # Permanently delete the file
                if os.path.exists(detection.file_path):
                    os.remove(detection.file_path)
                    logger.info(f"File deleted: {detection.file_path}")
                else:
                    logger.warning(f"File not found for deletion: {detection.file_path}")
            
            elif action == ThreatAction.IGNORE:
                # Log the ignore decision
                logger.info(f"Threat ignored: {detection.file_path}")
            
            elif action == ThreatAction.SKIP:
                # Log the skip decision
                logger.info(f"Threat processing skipped: {detection.file_path}")
            
        except Exception as e:
            logger.error(f"Failed to execute {action.value} for {detection.file_path}: {e}")
            raise
    
    def cancel_scan(self) -> bool:
        """Cancel the currently running scan.
        
        Returns:
            True if scan was cancelled, False if no scan running
        """
        if self._progress:
            self._progress.cancel()
            logger.info("Scan cancellation requested")
            return True
        return False
    
    def get_scan_progress(self) -> Optional[Dict[str, Any]]:
        """Get current scan progress information.
        
        Returns:
            Progress information dictionary, or None if no scan running
        """
        if self._progress:
            return self._progress.get_progress_info()
        return None
    
    def add_progress_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Add a callback function to receive progress updates.
        
        Args:
            callback: Function that takes progress info dictionary
        """
        self._progress_callbacks.append(callback)
    
    def remove_progress_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Remove a progress callback function.
        
        Args:
            callback: Function to remove
        """
        if callback in self._progress_callbacks:
            self._progress_callbacks.remove(callback)
    
    def _notify_progress(self) -> None:
        """Notify all progress callbacks with current progress."""
        if self._progress:
            progress_info = self._progress.get_progress_info()
            for callback in self._progress_callbacks:
                try:
                    callback(progress_info)
                except Exception as e:
                    logger.warning(f"Progress callback failed: {e}")
    
    def get_scan_history(self) -> List[ScanResult]:
        """Get history of all scan operations.
        
        Returns:
            List of ScanResult objects
        """
        return self._scan_history.copy()
    
    def get_current_scan(self) -> Optional[ScanResult]:
        """Get currently running scan result.
        
        Returns:
            Current ScanResult or None if no scan running
        """
        return self._current_scan
    
    def clear_scan_history(self) -> None:
        """Clear the scan history."""
        self._scan_history.clear()
        logger.info("Scan history cleared")
    
    def update_config(self, config: Config) -> None:
        """Update engine configuration.
        
        Args:
            config: New configuration object
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Validate new configuration
        config_errors = config.validate()
        if config_errors:
            raise ConfigurationError(f"Invalid configuration: {', '.join(config_errors)}")
        
        self.config = config
        
        # Update detection engines if initialized
        if self._initialized:
            if self.signature_engine:
                self.signature_engine.update_sensitivity(config.signature_sensitivity)
            
            if self.behavioral_engine:
                self.behavioral_engine.update_config(config)
        
        logger.info("ScanEngine configuration updated")
    
    def set_threat_decision_callback(self, callback: Callable[[Detection], ThreatAction]) -> None:
        """Set callback function for interactive threat decisions.
        
        Args:
            callback: Function that takes Detection and returns ThreatAction
        """
        self._threat_decision_callback = callback
        logger.info("Threat decision callback set")
    
    def update_auto_decision_thresholds(self, quarantine_threshold: int, 
                                      ignore_threshold: int) -> None:
        """Update automatic decision thresholds.
        
        Args:
            quarantine_threshold: Risk score threshold for auto-quarantine
            ignore_threshold: Risk score threshold for auto-ignore
            
        Raises:
            ValueError: If thresholds are invalid
        """
        if not 1 <= quarantine_threshold <= 10:
            raise ValueError("Quarantine threshold must be between 1 and 10")
        
        if not 1 <= ignore_threshold <= 10:
            raise ValueError("Ignore threshold must be between 1 and 10")
        
        if ignore_threshold >= quarantine_threshold:
            raise ValueError("Ignore threshold must be less than quarantine threshold")
        
        self._auto_quarantine_threshold = quarantine_threshold
        self._auto_ignore_threshold = ignore_threshold
        
        logger.info(f"Updated auto-decision thresholds: quarantine={quarantine_threshold}, ignore={ignore_threshold}")
    
    def get_decision_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get history of threat decisions.
        
        Args:
            limit: Maximum number of decisions to return
            
        Returns:
            List of decision information dictionaries
        """
        decisions = self._decision_history
        
        if limit:
            decisions = decisions[-limit:]
        
        return [
            {
                'file_path': decision.detection.file_path,
                'threat_name': decision.detection.threat_name,
                'risk_score': decision.detection.risk_score,
                'detection_type': decision.detection.detection_type.value,
                'action': decision.action.value,
                'reason': decision.reason,
                'auto_applied': decision.auto_applied,
                'timestamp': decision.timestamp.isoformat(),
                'quarantine_id': decision.quarantine_id
            }
            for decision in decisions
        ]
    
    def get_quarantine_summary(self) -> Dict[str, Any]:
        """Get summary of quarantine operations.
        
        Returns:
            Dictionary with quarantine statistics and recent activity
        """
        try:
            # Get quarantine statistics
            stats = self.quarantine_manager.get_quarantine_stats()
            
            # Get recent decisions
            recent_decisions = [
                {
                    'file_path': decision.detection.file_path,
                    'action': decision.action.value,
                    'reason': decision.reason,
                    'timestamp': decision.timestamp.isoformat(),
                    'auto_applied': decision.auto_applied
                }
                for decision in self._decision_history[-10:]  # Last 10 decisions
            ]
            
            return {
                'quarantine_stats': stats,
                'recent_decisions': recent_decisions,
                'total_decisions': len(self._decision_history),
                'auto_quarantine_threshold': self._auto_quarantine_threshold,
                'auto_ignore_threshold': self._auto_ignore_threshold
            }
            
        except Exception as e:
            logger.error(f"Failed to get quarantine summary: {e}")
            return {'error': str(e)}
    
    def restore_quarantined_file(self, quarantine_id: str, force: bool = False) -> bool:
        """Restore a file from quarantine.
        
        Args:
            quarantine_id: ID of quarantined file to restore
            force: Whether to overwrite existing files
            
        Returns:
            True if restoration successful
            
        Raises:
            QuarantineError: If restoration fails
        """
        try:
            result = self.quarantine_manager.restore_file(quarantine_id, force)
            
            if result:
                logger.info(f"File restored from quarantine: {quarantine_id}")
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to restore file {quarantine_id}: {e}")
            raise
    
    def delete_quarantined_file(self, quarantine_id: str, confirm: bool = False) -> bool:
        """Permanently delete a quarantined file.
        
        Args:
            quarantine_id: ID of quarantined file to delete
            confirm: Confirmation flag
            
        Returns:
            True if deletion successful
            
        Raises:
            QuarantineError: If deletion fails
        """
        try:
            result = self.quarantine_manager.delete_quarantined_file(quarantine_id, confirm)
            
            if result:
                logger.info(f"Quarantined file deleted: {quarantine_id}")
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to delete quarantined file {quarantine_id}: {e}")
            raise
    
    def list_quarantined_files(self) -> List[Dict[str, Any]]:
        """Get list of all quarantined files with details.
        
        Returns:
            List of quarantined file information
        """
        try:
            entries = self.quarantine_manager.list_quarantined_files()
            
            return [
                {
                    'quarantine_id': entry.quarantine_id,
                    'original_path': entry.original_path,
                    'quarantine_date': entry.quarantine_date.isoformat(),
                    'restored': entry.restored,
                    'threat_name': entry.detection_info.threat_name,
                    'detection_type': entry.detection_info.detection_type.value,
                    'risk_score': entry.detection_info.risk_score,
                    'signature_id': entry.detection_info.signature_id
                }
                for entry in entries
            ]
            
        except Exception as e:
            logger.error(f"Failed to list quarantined files: {e}")
            return []
    
    def get_engine_statistics(self) -> Dict[str, Any]:
        """Get statistics from all detection engines.
        
        Returns:
            Dictionary with engine statistics
        """
        stats = {
            'scan_history_count': len(self._scan_history),
            'total_scans': len(self._scan_history),
            'signature_engine': {},
            'behavioral_engine': {}
        }
        
        if self.signature_engine:
            stats['signature_engine'] = self.signature_engine.get_scan_statistics()
        
        # Get quarantine statistics
        if self.quarantine_manager:
            stats['quarantine_stats'] = self.quarantine_manager.get_quarantine_stats()
        
        # Calculate decision statistics
        decision_stats = {
            'total_decisions': len(self._decision_history),
            'auto_decisions': sum(1 for d in self._decision_history if d.auto_applied),
            'manual_decisions': sum(1 for d in self._decision_history if not d.auto_applied),
            'quarantine_actions': sum(1 for d in self._decision_history 
                                    if d.action == ThreatAction.QUARANTINE),
            'ignore_actions': sum(1 for d in self._decision_history 
                                if d.action == ThreatAction.IGNORE),
            'delete_actions': sum(1 for d in self._decision_history 
                                if d.action == ThreatAction.DELETE)
        }
        stats['decision_stats'] = decision_stats
        
        # Calculate aggregate statistics from scan history
        if self._scan_history:
            total_files = sum(scan.total_files for scan in self._scan_history)
            total_detections = sum(len(scan.detections) for scan in self._scan_history)
            total_errors = sum(len(scan.errors) for scan in self._scan_history)
            
            stats.update({
                'total_files_scanned': total_files,
                'total_detections': total_detections,
                'total_errors': total_errors,
                'detection_rate': total_detections / total_files if total_files > 0 else 0.0
            })
        
        return stats
    
    def close(self) -> None:
        """Close the scan engine and cleanup resources."""
        if self.signature_engine:
            self.signature_engine.close()
            self.signature_engine = None
        
        self.behavioral_engine = None
        self.quarantine_manager = None
        self._initialized = False
        self._progress_callbacks.clear()
        self._threat_decision_callback = None
        self._decision_history.clear()
        
        logger.info("ScanEngine closed")
    
    def __enter__(self):
        """Context manager entry."""
        self.initialize()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()