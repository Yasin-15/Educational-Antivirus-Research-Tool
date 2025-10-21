"""
Utility functions and classes for the CLI interface.

This module provides enhanced progress indicators, formatting utilities,
and interactive components for the command-line interface.
"""
import sys
import time
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import os


class ProgressIndicator:
    """Enhanced progress indicator with real-time updates."""
    
    def __init__(self, total_items: int = 0, show_eta: bool = True, 
                 show_rate: bool = True, width: int = 40):
        """Initialize progress indicator.
        
        Args:
            total_items: Total number of items to process
            show_eta: Whether to show estimated time remaining
            show_rate: Whether to show processing rate
            width: Width of the progress bar
        """
        self.total_items = total_items
        self.show_eta = show_eta
        self.show_rate = show_rate
        self.width = width
        
        self.current_item = 0
        self.start_time = time.time()
        self.last_update = 0
        self.current_file = ""
        self.detections_found = 0
        self.errors_encountered = 0
        
        self._lock = threading.Lock()
        self._running = False
        self._update_thread: Optional[threading.Thread] = None
    
    def start(self) -> None:
        """Start the progress indicator."""
        self._running = True
        self.start_time = time.time()
        self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self._update_thread.start()
    
    def stop(self) -> None:
        """Stop the progress indicator."""
        self._running = False
        if self._update_thread:
            self._update_thread.join(timeout=1.0)
        self._clear_line()
        print()  # Move to next line
    
    def update(self, current_item: int, current_file: str = "", 
               detections: int = 0, errors: int = 0) -> None:
        """Update progress information.
        
        Args:
            current_item: Current item number
            current_file: Currently processing file
            detections: Number of detections found
            errors: Number of errors encountered
        """
        with self._lock:
            self.current_item = current_item
            self.current_file = current_file
            self.detections_found = detections
            self.errors_encountered = errors
    
    def _update_loop(self) -> None:
        """Main update loop running in separate thread."""
        while self._running:
            self._display_progress()
            time.sleep(0.1)  # Update 10 times per second
    
    def _display_progress(self) -> None:
        """Display current progress."""
        with self._lock:
            current_time = time.time()
            
            # Calculate progress percentage
            if self.total_items > 0:
                progress = min(self.current_item / self.total_items, 1.0)
            else:
                progress = 0.0
            
            # Create progress bar
            filled_length = int(self.width * progress)
            bar = '█' * filled_length + '░' * (self.width - filled_length)
            
            # Calculate statistics
            elapsed_time = current_time - self.start_time
            
            # Build progress line
            progress_line = f'\r|{bar}| {progress*100:.1f}%'
            
            if self.total_items > 0:
                progress_line += f' ({self.current_item}/{self.total_items})'
            
            # Add rate information
            if self.show_rate and elapsed_time > 0 and self.current_item > 0:
                rate = self.current_item / elapsed_time
                progress_line += f' {rate:.1f} files/sec'
            
            # Add ETA
            if self.show_eta and self.total_items > 0 and self.current_item > 0 and elapsed_time > 0:
                remaining_items = self.total_items - self.current_item
                rate = self.current_item / elapsed_time
                if rate > 0:
                    eta_seconds = remaining_items / rate
                    eta = str(timedelta(seconds=int(eta_seconds)))
                    progress_line += f' ETA: {eta}'
            
            # Add current file (truncated if too long)
            if self.current_file:
                filename = os.path.basename(self.current_file)
                max_filename_length = 30
                if len(filename) > max_filename_length:
                    filename = filename[:max_filename_length-3] + '...'
                progress_line += f' - {filename}'
            
            # Add detection/error counts
            if self.detections_found > 0 or self.errors_encountered > 0:
                progress_line += f' [D:{self.detections_found} E:{self.errors_encountered}]'
            
            # Ensure line doesn't exceed terminal width
            terminal_width = os.get_terminal_size().columns if hasattr(os, 'get_terminal_size') else 80
            if len(progress_line) > terminal_width - 1:
                progress_line = progress_line[:terminal_width-4] + '...'
            
            # Display the line
            sys.stdout.write(progress_line)
            sys.stdout.flush()
    
    def _clear_line(self) -> None:
        """Clear the current line."""
        terminal_width = os.get_terminal_size().columns if hasattr(os, 'get_terminal_size') else 80
        sys.stdout.write('\r' + ' ' * terminal_width + '\r')
        sys.stdout.flush()


class ThreatDisplayFormatter:
    """Formatter for displaying threat information in a user-friendly way."""
    
    @staticmethod
    def format_threat_summary(detection) -> str:
        """Format a threat detection for summary display."""
        risk_level = ThreatDisplayFormatter._get_risk_level(detection.risk_score)
        risk_color = ThreatDisplayFormatter._get_risk_color(detection.risk_score)
        
        summary = f"🚨 {detection.threat_name}\n"
        summary += f"   File: {detection.file_path}\n"
        summary += f"   Type: {detection.detection_type.value.title()}\n"
        summary += f"   Risk: {risk_color}{risk_level}{ThreatDisplayFormatter._reset_color()} ({detection.risk_score}/10)\n"
        
        if detection.signature_id:
            summary += f"   Signature: {detection.signature_id}\n"
        
        return summary
    
    @staticmethod
    def format_threat_details(detection) -> str:
        """Format detailed threat information."""
        details = ThreatDisplayFormatter.format_threat_summary(detection)
        details += f"   Detected: {detection.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        if detection.details:
            details += "   Additional Details:\n"
            for key, value in detection.details.items():
                if isinstance(value, dict):
                    details += f"     {key}:\n"
                    for sub_key, sub_value in value.items():
                        details += f"       {sub_key}: {sub_value}\n"
                elif isinstance(value, list):
                    details += f"     {key}: {', '.join(map(str, value))}\n"
                else:
                    details += f"     {key}: {value}\n"
        
        return details
    
    @staticmethod
    def _get_risk_level(risk_score: int) -> str:
        """Get risk level description."""
        if risk_score >= 8:
            return "HIGH"
        elif risk_score >= 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    @staticmethod
    def _get_risk_color(risk_score: int) -> str:
        """Get ANSI color code for risk level."""
        if not sys.stdout.isatty():
            return ""  # No colors for non-terminal output
        
        if risk_score >= 8:
            return "\033[91m"  # Red
        elif risk_score >= 5:
            return "\033[93m"  # Yellow
        else:
            return "\033[92m"  # Green
    
    @staticmethod
    def _reset_color() -> str:
        """Get ANSI reset color code."""
        if not sys.stdout.isatty():
            return ""
        return "\033[0m"


class InteractivePrompt:
    """Enhanced interactive prompt system with better user experience."""
    
    @staticmethod
    def confirm(message: str, default: bool = False) -> bool:
        """Show confirmation prompt.
        
        Args:
            message: Message to display
            default: Default value if user just presses Enter
            
        Returns:
            True if confirmed, False otherwise
        """
        default_text = "[Y/n]" if default else "[y/N]"
        
        try:
            response = input(f"{message} {default_text}: ").strip().lower()
            
            if not response:
                return default
            
            return response in ('y', 'yes', 'true', '1')
            
        except (KeyboardInterrupt, EOFError):
            print("\nOperation cancelled.")
            return False
    
    @staticmethod
    def select_option(message: str, options: List[str], default: int = 0) -> int:
        """Show option selection prompt.
        
        Args:
            message: Message to display
            options: List of options to choose from
            default: Default option index
            
        Returns:
            Selected option index
        """
        print(f"\n{message}")
        for i, option in enumerate(options):
            marker = "*" if i == default else " "
            print(f"  {marker} {i+1}. {option}")
        
        while True:
            try:
                response = input(f"\nSelect option [1-{len(options)}] (default: {default+1}): ").strip()
                
                if not response:
                    return default
                
                choice = int(response) - 1
                if 0 <= choice < len(options):
                    return choice
                else:
                    print(f"Please enter a number between 1 and {len(options)}")
                    
            except ValueError:
                print("Please enter a valid number")
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")
                return default
    
    @staticmethod
    def input_with_validation(message: str, validator=None, default: str = "") -> str:
        """Get input with optional validation.
        
        Args:
            message: Message to display
            validator: Optional validation function
            default: Default value
            
        Returns:
            Validated input string
        """
        while True:
            try:
                if default:
                    response = input(f"{message} (default: {default}): ").strip()
                    if not response:
                        response = default
                else:
                    response = input(f"{message}: ").strip()
                
                if validator:
                    if validator(response):
                        return response
                    else:
                        print("Invalid input. Please try again.")
                        continue
                
                return response
                
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")
                return default


class ScanResultsFormatter:
    """Formatter for scan results with enhanced display options."""
    
    @staticmethod
    def format_summary(scan_result) -> str:
        """Format scan results summary."""
        duration = ""
        if scan_result.end_time:
            delta = scan_result.end_time - scan_result.start_time
            duration = f" in {delta.total_seconds():.2f} seconds"
        
        summary = f"\n{'='*60}\n"
        summary += f"SCAN COMPLETED{duration}\n"
        summary += f"{'='*60}\n"
        summary += f"Status: {scan_result.status.value.upper()}\n"
        summary += f"Files Scanned: {scan_result.total_files}\n"
        summary += f"Threats Found: {len(scan_result.detections)}\n"
        summary += f"Errors: {len(scan_result.errors)}\n"
        
        if scan_result.detections:
            # Group by risk level
            high_risk = [d for d in scan_result.detections if d.risk_score >= 8]
            medium_risk = [d for d in scan_result.detections if 5 <= d.risk_score < 8]
            low_risk = [d for d in scan_result.detections if d.risk_score < 5]
            
            summary += f"\nThreat Breakdown:\n"
            if high_risk:
                summary += f"  🔴 High Risk: {len(high_risk)}\n"
            if medium_risk:
                summary += f"  🟡 Medium Risk: {len(medium_risk)}\n"
            if low_risk:
                summary += f"  🟢 Low Risk: {len(low_risk)}\n"
        
        return summary
    
    @staticmethod
    def format_detailed_results(scan_result) -> str:
        """Format detailed scan results."""
        output = ScanResultsFormatter.format_summary(scan_result)
        
        if scan_result.detections:
            output += f"\n{'='*60}\n"
            output += f"THREAT DETAILS\n"
            output += f"{'='*60}\n"
            
            # Sort by risk score (highest first)
            sorted_detections = sorted(scan_result.detections, 
                                     key=lambda d: d.risk_score, reverse=True)
            
            for i, detection in enumerate(sorted_detections, 1):
                output += f"\n{i}. {ThreatDisplayFormatter.format_threat_details(detection)}"
        
        if scan_result.errors:
            output += f"\n{'='*60}\n"
            output += f"ERRORS ENCOUNTERED\n"
            output += f"{'='*60}\n"
            for error in scan_result.errors:
                output += f"  ❌ {error}\n"
        
        # Show threat handling summary if available
        if hasattr(scan_result, 'details') and scan_result.details:
            details = scan_result.details
            if 'threat_decisions' in details:
                output += f"\n{'='*60}\n"
                output += f"THREAT HANDLING SUMMARY\n"
                output += f"{'='*60}\n"
                output += f"Quarantined: {details.get('quarantine_actions', 0)}\n"
                output += f"Ignored: {details.get('ignored_threats', 0)}\n"
                output += f"Deleted: {details.get('deleted_threats', 0)}\n"
        
        return output
    
    @staticmethod
    def format_csv_output(scan_result) -> str:
        """Format scan results as CSV."""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'File Path', 'Threat Name', 'Detection Type', 'Risk Score', 
            'Signature ID', 'Timestamp', 'Details'
        ])
        
        # Write detection data
        for detection in scan_result.detections:
            details_str = str(detection.details) if detection.details else ""
            writer.writerow([
                detection.file_path,
                detection.threat_name,
                detection.detection_type.value,
                detection.risk_score,
                detection.signature_id or "",
                detection.timestamp.isoformat(),
                details_str
            ])
        
        return output.getvalue()
    
    @staticmethod
    def format_json_output(scan_result) -> Dict[str, Any]:
        """Format scan results as JSON-serializable dictionary."""
        return {
            'scan_info': {
                'scan_id': scan_result.scan_id,
                'start_time': scan_result.start_time.isoformat(),
                'end_time': scan_result.end_time.isoformat() if scan_result.end_time else None,
                'status': scan_result.status.value,
                'scanned_paths': scan_result.scanned_paths,
                'total_files': scan_result.total_files
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
            'summary': {
                'total_threats': len(scan_result.detections),
                'high_risk_threats': len([d for d in scan_result.detections if d.risk_score >= 8]),
                'medium_risk_threats': len([d for d in scan_result.detections if 5 <= d.risk_score < 8]),
                'low_risk_threats': len([d for d in scan_result.detections if d.risk_score < 5]),
                'total_errors': len(scan_result.errors)
            }
        }