"""
Threat Handler for the Educational Antivirus Research Tool.

This module provides user interaction interfaces for handling detected threats,
including CLI prompts and programmatic decision making.
"""
import sys
from typing import Dict, Any, Optional, Callable, List
from enum import Enum

from core.models import Detection, DetectionType
from core.integrated_scanner import ThreatAction
from core.logging_config import get_logger

logger = get_logger(__name__)


class InteractionMode(Enum):
    """Modes for user interaction."""
    INTERACTIVE = "interactive"
    AUTOMATIC = "automatic"
    BATCH = "batch"


class ThreatHandler:
    """
    Handles user interaction for threat decisions with multiple interface options.
    """
    
    def __init__(self, mode: InteractionMode = InteractionMode.INTERACTIVE):
        """Initialize the threat handler.
        
        Args:
            mode: Interaction mode for handling threats
        """
        self.mode = mode
        self._batch_decisions: Dict[str, ThreatAction] = {}
        self._default_action = ThreatAction.QUARANTINE
        
        logger.info(f"ThreatHandler initialized in {mode.value} mode")
    
    def handle_threat_decision(self, detection: Detection) -> ThreatAction:
        """Handle a threat detection and get user decision.
        
        Args:
            detection: Detection object requiring a decision
            
        Returns:
            ThreatAction to take for this threat
        """
        if self.mode == InteractionMode.INTERACTIVE:
            return self._interactive_decision(detection)
        elif self.mode == InteractionMode.BATCH:
            return self._batch_decision(detection)
        else:  # AUTOMATIC
            return self._automatic_decision(detection)
    
    def _interactive_decision(self, detection: Detection) -> ThreatAction:
        """Get interactive user decision for a threat.
        
        Args:
            detection: Detection requiring decision
            
        Returns:
            User-selected ThreatAction
        """
        print("\n" + "="*80)
        print("THREAT DETECTED")
        print("="*80)
        
        # Display threat information
        self._display_threat_info(detection)
        
        # Display educational information if available
        self._display_educational_info(detection)
        
        # Get user choice
        while True:
            print("\nWhat would you like to do with this file?")
            print("  [Q] Quarantine - Move to secure quarantine folder")
            print("  [I] Ignore - Leave file in place (not recommended for real threats)")
            print("  [D] Delete - Permanently delete the file")
            print("  [S] Skip - Skip this file for now")
            print("  [H] Help - Show more information about options")
            
            choice = input("\nEnter your choice [Q/I/D/S/H]: ").strip().upper()
            
            if choice == 'Q':
                return ThreatAction.QUARANTINE
            elif choice == 'I':
                # Confirm ignore action
                confirm = input("Are you sure you want to ignore this threat? [y/N]: ").strip().lower()
                if confirm in ['y', 'yes']:
                    return ThreatAction.IGNORE
                else:
                    continue
            elif choice == 'D':
                # Confirm delete action
                confirm = input("Are you sure you want to permanently delete this file? [y/N]: ").strip().lower()
                if confirm in ['y', 'yes']:
                    return ThreatAction.DELETE
                else:
                    continue
            elif choice == 'S':
                return ThreatAction.SKIP
            elif choice == 'H':
                self._display_help()
                continue
            else:
                print("Invalid choice. Please enter Q, I, D, S, or H.")
                continue
    
    def _batch_decision(self, detection: Detection) -> ThreatAction:
        """Get batch decision for a threat based on pre-configured rules.
        
        Args:
            detection: Detection requiring decision
            
        Returns:
            Pre-configured ThreatAction
        """
        # Check for specific file patterns
        file_path = detection.file_path.lower()
        
        for pattern, action in self._batch_decisions.items():
            if pattern in file_path:
                logger.info(f"Batch decision for {detection.file_path}: {action.value} (pattern: {pattern})")
                return action
        
        # Use default action if no pattern matches
        logger.info(f"Batch decision for {detection.file_path}: {self._default_action.value} (default)")
        return self._default_action
    
    def _automatic_decision(self, detection: Detection) -> ThreatAction:
        """Make automatic decision based on threat characteristics.
        
        Args:
            detection: Detection requiring decision
            
        Returns:
            Automatically determined ThreatAction
        """
        risk_score = detection.risk_score
        
        # High-risk threats: quarantine
        if risk_score >= 8:
            return ThreatAction.QUARANTINE
        
        # Medium-risk threats: quarantine for safety
        elif risk_score >= 5:
            return ThreatAction.QUARANTINE
        
        # Low-risk threats: ignore
        else:
            return ThreatAction.IGNORE
    
    def _display_threat_info(self, detection: Detection) -> None:
        """Display detailed threat information.
        
        Args:
            detection: Detection to display information for
        """
        print(f"File: {detection.file_path}")
        print(f"Threat: {detection.threat_name}")
        print(f"Detection Type: {detection.detection_type.value.title()}")
        print(f"Risk Score: {detection.risk_score}/10")
        
        if detection.signature_id:
            print(f"Signature ID: {detection.signature_id}")
        
        print(f"Detected: {detection.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Display additional details if available
        if detection.details:
            self._display_detection_details(detection.details)
    
    def _display_detection_details(self, details: Dict[str, Any]) -> None:
        """Display additional detection details.
        
        Args:
            details: Detection details dictionary
        """
        print("\nDetection Details:")
        
        # File information
        if 'file_size' in details:
            size_mb = details['file_size'] / (1024 * 1024)
            print(f"  File Size: {size_mb:.2f} MB")
        
        if 'file_hash_md5' in details:
            print(f"  MD5 Hash: {details['file_hash_md5']}")
        
        # Signature-specific details
        if 'signature_type' in details:
            print(f"  Signature Type: {details['signature_type']}")
        
        if 'confidence' in details:
            print(f"  Match Confidence: {details['confidence']:.2f}")
        
        # Behavioral analysis details
        if 'entropy' in details:
            print(f"  File Entropy: {details['entropy']:.2f}")
        
        if 'suspicious_patterns' in details and details['suspicious_patterns']:
            print("  Suspicious Patterns:")
            for pattern in details['suspicious_patterns']:
                print(f"    - {pattern}")
        
        # Educational information
        if 'educational_info' in details and details['educational_info']:
            print(f"\nEducational Info: {details['educational_info']}")
        
        if 'harmless' in details and details['harmless']:
            print("\n⚠️  NOTE: This is a harmless test file for educational purposes.")
    
    def _display_educational_info(self, detection: Detection) -> None:
        """Display educational information about the threat.
        
        Args:
            detection: Detection to display educational info for
        """
        print("\n" + "-"*60)
        print("EDUCATIONAL INFORMATION")
        print("-"*60)
        
        if detection.detection_type == DetectionType.SIGNATURE:
            print("This threat was detected using SIGNATURE-BASED DETECTION:")
            print("• The file contains a known malware signature pattern")
            print("• Signature detection is fast and accurate for known threats")
            print("• However, it cannot detect new or modified malware variants")
            
        elif detection.detection_type == DetectionType.BEHAVIORAL:
            print("This threat was detected using BEHAVIORAL ANALYSIS:")
            print("• The file exhibits suspicious characteristics or patterns")
            print("• Behavioral analysis can detect unknown threats")
            print("• It may occasionally flag legitimate files (false positives)")
        
        # Risk level explanation
        risk_score = detection.risk_score
        if risk_score >= 8:
            print(f"\n🔴 HIGH RISK ({risk_score}/10): This file poses a significant threat")
        elif risk_score >= 5:
            print(f"\n🟡 MEDIUM RISK ({risk_score}/10): This file shows suspicious characteristics")
        else:
            print(f"\n🟢 LOW RISK ({risk_score}/10): This file shows minor suspicious indicators")
        
        # Action recommendations
        print("\nRECOMMENDED ACTIONS:")
        if risk_score >= 8:
            print("• QUARANTINE: Isolate the file for further analysis")
            print("• DO NOT ignore high-risk threats in real environments")
        elif risk_score >= 5:
            print("• QUARANTINE: Safe option for suspicious files")
            print("• Consider the file's source and purpose before ignoring")
        else:
            print("• IGNORE: May be safe if you trust the file source")
            print("• QUARANTINE: Safer option if uncertain")
    
    def _display_help(self) -> None:
        """Display help information about threat handling options."""
        print("\n" + "="*60)
        print("THREAT HANDLING OPTIONS - HELP")
        print("="*60)
        
        print("\n🔒 QUARANTINE:")
        print("  • Moves the file to a secure quarantine folder")
        print("  • File is isolated and cannot cause harm")
        print("  • You can restore the file later if it's a false positive")
        print("  • Recommended for most threats")
        
        print("\n👁️ IGNORE:")
        print("  • Leaves the file in its current location")
        print("  • File remains active and potentially dangerous")
        print("  • Only use if you're certain the file is safe")
        print("  • NOT recommended for real malware")
        
        print("\n🗑️ DELETE:")
        print("  • Permanently removes the file from your system")
        print("  • Cannot be undone - file is lost forever")
        print("  • Use only if you're certain you don't need the file")
        print("  • More aggressive than quarantine")
        
        print("\n⏭️ SKIP:")
        print("  • Temporarily skips this file without taking action")
        print("  • File remains in place and unprocessed")
        print("  • Use if you need to handle this file manually later")
        
        print("\n💡 EDUCATIONAL NOTE:")
        print("  In this educational tool, all threats are harmless test files.")
        print("  In a real antivirus system, ignoring threats could be dangerous!")
        
        input("\nPress Enter to continue...")
    
    def set_batch_decisions(self, decisions: Dict[str, str]) -> None:
        """Set batch decision rules for automatic processing.
        
        Args:
            decisions: Dictionary mapping file patterns to action names
        """
        self._batch_decisions.clear()
        
        for pattern, action_name in decisions.items():
            try:
                action = ThreatAction(action_name.lower())
                self._batch_decisions[pattern.lower()] = action
            except ValueError:
                logger.warning(f"Invalid action '{action_name}' for pattern '{pattern}'")
        
        logger.info(f"Set {len(self._batch_decisions)} batch decision rules")
    
    def set_default_action(self, action: ThreatAction) -> None:
        """Set default action for batch and automatic modes.
        
        Args:
            action: Default ThreatAction to use
        """
        self._default_action = action
        logger.info(f"Set default action to {action.value}")
    
    def get_threat_summary(self, detection: Detection) -> str:
        """Get a brief summary of a threat for logging or display.
        
        Args:
            detection: Detection to summarize
            
        Returns:
            Brief threat summary string
        """
        return (f"{detection.threat_name} in {detection.file_path} "
                f"(Risk: {detection.risk_score}/10, Type: {detection.detection_type.value})")


class CLIThreatInterface:
    """
    Command-line interface for threat handling with enhanced user experience.
    """
    
    def __init__(self):
        """Initialize the CLI threat interface."""
        self.handler = ThreatHandler(InteractionMode.INTERACTIVE)
        self._threat_count = 0
        self._session_decisions: List[Dict[str, Any]] = []
    
    def handle_scan_threats(self, detections: List[Detection]) -> List[Dict[str, Any]]:
        """Handle multiple threats from a scan with CLI interface.
        
        Args:
            detections: List of detections to handle
            
        Returns:
            List of decision dictionaries
        """
        if not detections:
            print("\n✅ No threats detected!")
            return []
        
        print(f"\n⚠️  {len(detections)} threat(s) detected!")
        print("You will be prompted to handle each threat individually.")
        
        decisions = []
        
        for i, detection in enumerate(detections, 1):
            self._threat_count = i
            print(f"\n--- Threat {i} of {len(detections)} ---")
            
            action = self.handler.handle_threat_decision(detection)
            
            decision = {
                'detection': detection,
                'action': action,
                'threat_number': i,
                'total_threats': len(detections)
            }
            
            decisions.append(decision)
            self._session_decisions.append(decision)
            
            # Show action confirmation
            self._show_action_confirmation(detection, action)
        
        # Show session summary
        self._show_session_summary(decisions)
        
        return decisions
    
    def _show_action_confirmation(self, detection: Detection, action: ThreatAction) -> None:
        """Show confirmation of the action taken.
        
        Args:
            detection: Detection that was handled
            action: Action that was taken
        """
        action_messages = {
            ThreatAction.QUARANTINE: "🔒 File will be moved to quarantine",
            ThreatAction.IGNORE: "👁️ File will be left in place",
            ThreatAction.DELETE: "🗑️ File will be permanently deleted",
            ThreatAction.SKIP: "⏭️ File will be skipped for now"
        }
        
        message = action_messages.get(action, f"Action: {action.value}")
        print(f"\n✓ {message}")
    
    def _show_session_summary(self, decisions: List[Dict[str, Any]]) -> None:
        """Show summary of all decisions made in this session.
        
        Args:
            decisions: List of decision dictionaries
        """
        if not decisions:
            return
        
        print("\n" + "="*80)
        print("SESSION SUMMARY")
        print("="*80)
        
        # Count actions
        action_counts = {}
        for decision in decisions:
            action = decision['action']
            action_counts[action] = action_counts.get(action, 0) + 1
        
        print(f"Total threats handled: {len(decisions)}")
        
        for action, count in action_counts.items():
            action_names = {
                ThreatAction.QUARANTINE: "Quarantined",
                ThreatAction.IGNORE: "Ignored",
                ThreatAction.DELETE: "Deleted",
                ThreatAction.SKIP: "Skipped"
            }
            name = action_names.get(action, action.value)
            print(f"  {name}: {count}")
        
        # Show individual decisions
        print("\nDetailed decisions:")
        for decision in decisions:
            detection = decision['detection']
            action = decision['action']
            print(f"  {action.value.upper()}: {detection.file_path}")
        
        print("\n" + "="*80)
    
    def set_batch_mode(self, decisions: Dict[str, str], default_action: str = "quarantine") -> None:
        """Switch to batch mode with predefined decisions.
        
        Args:
            decisions: Dictionary mapping file patterns to actions
            default_action: Default action for unmatched files
        """
        self.handler = ThreatHandler(InteractionMode.BATCH)
        self.handler.set_batch_decisions(decisions)
        self.handler.set_default_action(ThreatAction(default_action.lower()))
        
        print(f"Switched to batch mode with {len(decisions)} rules")
    
    def set_automatic_mode(self) -> None:
        """Switch to automatic mode with risk-based decisions."""
        self.handler = ThreatHandler(InteractionMode.AUTOMATIC)
        print("Switched to automatic mode (risk-based decisions)")
    
    def set_interactive_mode(self) -> None:
        """Switch to interactive mode with user prompts."""
        self.handler = ThreatHandler(InteractionMode.INTERACTIVE)
        print("Switched to interactive mode (user prompts)")
    
    def get_session_statistics(self) -> Dict[str, Any]:
        """Get statistics for the current session.
        
        Returns:
            Dictionary with session statistics
        """
        if not self._session_decisions:
            return {'total_decisions': 0}
        
        action_counts = {}
        for decision in self._session_decisions:
            action = decision['action']
            action_counts[action.value] = action_counts.get(action.value, 0) + 1
        
        return {
            'total_decisions': len(self._session_decisions),
            'action_counts': action_counts,
            'mode': self.handler.mode.value
        }