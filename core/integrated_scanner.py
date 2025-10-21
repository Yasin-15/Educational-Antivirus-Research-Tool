"""
Integrated Scanner for the Educational Antivirus Research Tool.

This module provides an enhanced scanning engine that integrates detection engines
with quarantine management and user interaction for handling detected threats.
"""
import os
from typing import List, Dict, Any, Optional, Callable, Tuple
from enum import Enum
from datetime import datetime

from core.models import Detection, ScanResult, ScanOptions, Config
from core.exceptions import ScanError, QuarantineError
from core.logging_config import get_logger
from core.scan_engine import ScanEngine
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


class IntegratedScanner:
    """
    Enhanced scanner that integrates detection engines with quarantine management
    and provides user interaction for threat handling decisions.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize the integrated scanner.
        
        Args:
            config: Configuration object for the scanner
        """
        self.config = config or Config()
        self.scan_engine = ScanEngine(self.config)
        self.quarantine_manager = QuarantineManager(self.config.quarantine_path)
        
        # User interaction callbacks
        self._threat_decision_callback: Optional[Callable[[Detection], ThreatAction]] = None
        self._progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
        
        # Decision history
        self._decision_history: List[ThreatDecision] = []
        
        # Auto-decision rules
        self._auto_quarantine_threshold = 8  # Auto-quarantine high-risk threats
        self._auto_ignore_threshold = 3      # Auto-ignore low-risk threats
        
        logger.info("IntegratedScanner initialized")
    
    def initialize(self) -> bool:
        """Initialize the integrated scanner and all components.
        
        Returns:
            True if initialization successful
            
        Raises:
            ScanError: If initialization fails
        """
        try:
            # Initialize scan engine
            self.scan_engine.initialize()
            
            # Quarantine manager is already initialized in constructor
            
            logger.info("IntegratedScanner initialization completed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize IntegratedScanner: {e}")
            raise ScanError(f"Integrated scanner initialization failed: {e}")
    
    def scan_with_interaction(self, path: str, options: Optional[ScanOptions] = None,
                            interactive: bool = True) -> ScanResult:
        """Scan a path with integrated threat handling and user interaction.
        
        Args:
            path: Path to scan (file or directory)
            options: Scan options
            interactive: Whether to prompt user for threat decisions
            
        Returns:
            Enhanced ScanResult with threat handling information
            
        Raises:
            ScanError: If scanning fails
        """
        if options is None:
            options = ScanOptions()
        
        logger.info(f"Starting integrated scan of: {path}")
        
        try:
            # Perform initial scan
            scan_result = self.scan_engine.scan_path(path, options)
            
            # Process detections with user interaction
            if scan_result.detections:
                processed_detections = self._process_detections_with_interaction(
                    scan_result.detections, interactive
                )
                
                # Update scan result with processing information
                scan_result.details = getattr(scan_result, 'details', {})
                scan_result.details.update({
                    'threat_decisions': [
                        {
                            'detection_id': decision.detection.file_path,
                            'action': decision.action.value,
                            'reason': decision.reason,
                            'auto_applied': decision.auto_applied,
                            'timestamp': decision.timestamp.isoformat()
                        }
                        for decision in processed_detections
                    ],
                    'quarantine_actions': sum(1 for d in processed_detections 
                                            if d.action == ThreatAction.QUARANTINE),
                    'ignored_threats': sum(1 for d in processed_detections 
                                         if d.action == ThreatAction.IGNORE),
                    'deleted_threats': sum(1 for d in processed_detections 
                                         if d.action == ThreatAction.DELETE)
                })
            
            logger.info(f"Integrated scan completed: {len(scan_result.detections)} threats processed")
            return scan_result
            
        except Exception as e:
            logger.error(f"Integrated scan failed: {e}")
            raise ScanError(f"Integrated scan operation failed: {e}")
    
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
    
    def set_threat_decision_callback(self, callback: Callable[[Detection], ThreatAction]) -> None:
        """Set callback function for interactive threat decisions.
        
        Args:
            callback: Function that takes Detection and returns ThreatAction
        """
        self._threat_decision_callback = callback
        logger.info("Threat decision callback set")
    
    def set_progress_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Set callback function for progress updates.
        
        Args:
            callback: Function that takes progress info dictionary
        """
        self._progress_callback = callback
        self.scan_engine.add_progress_callback(callback)
        logger.info("Progress callback set")
    
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
                'quarantine_id': getattr(decision, 'quarantine_id', None)
            }
            for decision in decisions
        ]
    
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
    
    def export_scan_report(self, scan_result: ScanResult, 
                          include_quarantine_info: bool = True) -> Dict[str, Any]:
        """Export comprehensive scan report with quarantine information.
        
        Args:
            scan_result: Scan result to export
            include_quarantine_info: Whether to include quarantine details
            
        Returns:
            Comprehensive report dictionary
        """
        try:
            report = {
                'scan_info': {
                    'scan_id': scan_result.scan_id,
                    'start_time': scan_result.start_time.isoformat(),
                    'end_time': scan_result.end_time.isoformat() if scan_result.end_time else None,
                    'scanned_paths': scan_result.scanned_paths,
                    'total_files': scan_result.total_files,
                    'status': scan_result.status.value
                },
                'detections': [
                    {
                        'file_path': detection.file_path,
                        'threat_name': detection.threat_name,
                        'detection_type': detection.detection_type.value,
                        'risk_score': detection.risk_score,
                        'signature_id': detection.signature_id,
                        'timestamp': detection.timestamp.isoformat(),
                        'details': detection.details
                    }
                    for detection in scan_result.detections
                ],
                'errors': scan_result.errors,
                'scan_options': scan_result.scan_options.to_dict() if scan_result.scan_options else None
            }
            
            # Add threat decision information if available
            if hasattr(scan_result, 'details') and scan_result.details:
                report['threat_handling'] = scan_result.details
            
            # Add quarantine information if requested
            if include_quarantine_info:
                report['quarantine_summary'] = self.get_quarantine_summary()
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to export scan report: {e}")
            return {'error': str(e)}
    
    def get_scanner_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scanner statistics.
        
        Returns:
            Dictionary with scanner statistics
        """
        try:
            # Get base engine statistics
            engine_stats = self.scan_engine.get_engine_statistics()
            
            # Get quarantine statistics
            quarantine_stats = self.quarantine_manager.get_quarantine_stats()
            
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
            
            return {
                'engine_statistics': engine_stats,
                'quarantine_statistics': quarantine_stats,
                'decision_statistics': decision_stats,
                'configuration': {
                    'auto_quarantine_threshold': self._auto_quarantine_threshold,
                    'auto_ignore_threshold': self._auto_ignore_threshold
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get scanner statistics: {e}")
            return {'error': str(e)}
    
    def close(self) -> None:
        """Close the integrated scanner and cleanup resources."""
        if self.scan_engine:
            self.scan_engine.close()
        
        # Clear callbacks and history
        self._threat_decision_callback = None
        self._progress_callback = None
        self._decision_history.clear()
        
        logger.info("IntegratedScanner closed")
    
    def __enter__(self):
        """Context manager entry."""
        self.initialize()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()