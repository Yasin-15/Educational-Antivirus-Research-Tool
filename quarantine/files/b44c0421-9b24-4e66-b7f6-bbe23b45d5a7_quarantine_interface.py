"""
Quarantine Management Interface for the Educational Antivirus Research Tool.

This module provides a high-level interface for quarantine operations,
including listing, viewing details, restoration, and deletion of quarantined files.
It serves as the main interface layer between the CLI/GUI and the quarantine manager.
"""
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path

from quarantine.quarantine_manager import QuarantineManager
from core.models import QuarantineEntry, Detection
from core.exceptions import QuarantineError, FileAccessError


class QuarantineInterface:
    """
    High-level interface for quarantine management operations.
    
    This class provides a simplified interface for common quarantine operations
    and handles error management, user confirmations, and formatting.
    """
    
    def __init__(self, quarantine_path: str = "quarantine"):
        """
        Initialize the quarantine interface.
        
        Args:
            quarantine_path: Path to the quarantine directory
        """
        self.manager = QuarantineManager(quarantine_path)
        self.logger = logging.getLogger(__name__)
    
    def list_quarantined_files(self, 
                             status_filter: Optional[str] = None,
                             detection_type_filter: Optional[str] = None,
                             limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get a formatted list of quarantined files with optional filtering.
        
        Args:
            status_filter: Filter by status ('active', 'restored', or None for all)
            detection_type_filter: Filter by detection type ('signature', 'behavioral', or None)
            limit: Maximum number of entries to return (None for all)
            
        Returns:
            List of dictionaries containing formatted quarantine information
        """
        try:
            entries = self.manager.list_quarantined_files()
            
            # Apply filters
            if status_filter:
                if status_filter == 'active':
                    entries = [e for e in entries if not e.restored]
                elif status_filter == 'restored':
                    entries = [e for e in entries if e.restored]
            
            if detection_type_filter:
                entries = [e for e in entries 
                          if e.detection_info.detection_type.value == detection_type_filter]
            
            # Apply limit
            if limit and limit > 0:
                entries = entries[:limit]
            
            # Format entries for display
            formatted_entries = []
            for entry in entries:
                formatted_entry = {
                    'quarantine_id': entry.quarantine_id,
                    'original_path': entry.original_path,
                    'filename': Path(entry.original_path).name,
                    'quarantine_date': entry.quarantine_date.strftime('%Y-%m-%d %H:%M:%S'),
                    'status': 'Restored' if entry.restored else 'Active',
                    'threat_name': entry.detection_info.threat_name,
                    'detection_type': entry.detection_info.detection_type.value,
                    'risk_score': entry.detection_info.risk_score,
                    'signature_id': entry.detection_info.signature_id,
                    'days_quarantined': (datetime.now() - entry.quarantine_date).days
                }
                formatted_entries.append(formatted_entry)
            
            return formatted_entries
            
        except Exception as e:
            self.logger.error(f"Failed to list quarantined files: {str(e)}")
            return []
    
    def get_quarantine_details(self, quarantine_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific quarantined file.
        
        Args:
            quarantine_id: Unique quarantine identifier
            
        Returns:
            Dictionary with detailed quarantine information or None if not found
        """
        try:
            entry = self.manager.get_quarantine_entry(quarantine_id)
            
            if not entry:
                return None
            
            # Check if quarantined file exists
            quarantine_path = Path(entry.quarantine_path)
            file_exists = quarantine_path.exists()
            file_size = quarantine_path.stat().st_size if file_exists else 0
            
            # Format detailed information
            details = {
                'quarantine_id': entry.quarantine_id,
                'original_path': entry.original_path,
                'quarantine_path': entry.quarantine_path,
                'filename': Path(entry.original_path).name,
                'quarantine_date': entry.quarantine_date.strftime('%Y-%m-%d %H:%M:%S'),
                'quarantine_timestamp': entry.quarantine_date.isoformat(),
                'status': 'Restored' if entry.restored else 'Active',
                'days_quarantined': (datetime.now() - entry.quarantine_date).days,
                'file_exists': file_exists,
                'file_size': file_size,
                'file_size_mb': round(file_size / (1024 * 1024), 2) if file_size > 0 else 0,
                
                # Detection information
                'detection_info': {
                    'threat_name': entry.detection_info.threat_name,
                    'detection_type': entry.detection_info.detection_type.value,
                    'risk_score': entry.detection_info.risk_score,
                    'signature_id': entry.detection_info.signature_id,
                    'detection_timestamp': entry.detection_info.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'details': entry.detection_info.details
                }
            }
            
            return details
            
        except Exception as e:
            self.logger.error(f"Failed to get quarantine details for {quarantine_id}: {str(e)}")
            return None
    
    def restore_quarantined_file(self, 
                               quarantine_id: str, 
                               force_overwrite: bool = False,
                               confirm_callback: Optional[callable] = None) -> Tuple[bool, str]:
        """
        Restore a quarantined file with user confirmation handling.
        
        Args:
            quarantine_id: Unique quarantine identifier
            force_overwrite: If True, overwrite existing files without confirmation
            confirm_callback: Optional callback function for user confirmation
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            entry = self.manager.get_quarantine_entry(quarantine_id)
            
            if not entry:
                return False, "Quarantine entry not found"
            
            if entry.restored:
                return False, "File has already been restored"
            
            # Check if original location exists
            original_path = Path(entry.original_path)
            if original_path.exists() and not force_overwrite:
                if confirm_callback:
                    confirmed = confirm_callback(
                        f"File already exists at {entry.original_path}. Overwrite?",
                        "overwrite_confirmation"
                    )
                    if not confirmed:
                        return False, "Restoration cancelled by user"
                else:
                    return False, f"File already exists at {entry.original_path}. Use force_overwrite=True to overwrite."
            
            # Perform restoration
            success = self.manager.restore_file(quarantine_id, force=force_overwrite or original_path.exists())
            
            if success:
                message = f"File restored successfully to {entry.original_path}"
                self.logger.info(f"Restored quarantined file: {quarantine_id}")
                return True, message
            else:
                return False, "Restoration failed"
                
        except (QuarantineError, FileAccessError) as e:
            error_msg = f"Restoration error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error during restoration: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def delete_quarantined_file(self, 
                              quarantine_id: str,
                              confirm_callback: Optional[callable] = None) -> Tuple[bool, str]:
        """
        Delete a quarantined file with user confirmation handling.
        
        Args:
            quarantine_id: Unique quarantine identifier
            confirm_callback: Optional callback function for user confirmation
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            entry = self.manager.get_quarantine_entry(quarantine_id)
            
            if not entry:
                return False, "Quarantine entry not found"
            
            # Get confirmation if callback provided
            if confirm_callback:
                confirmed = confirm_callback(
                    f"Permanently delete quarantined file '{Path(entry.original_path).name}'?\n"
                    f"Threat: {entry.detection_info.threat_name}\n"
                    f"This action cannot be undone!",
                    "delete_confirmation"
                )
                if not confirmed:
                    return False, "Deletion cancelled by user"
            
            # Perform deletion
            success = self.manager.delete_quarantined_file(quarantine_id, confirm=True)
            
            if success:
                message = f"Quarantined file deleted permanently"
                self.logger.info(f"Deleted quarantined file: {quarantine_id}")
                return True, message
            else:
                return False, "Deletion failed"
                
        except QuarantineError as e:
            error_msg = f"Deletion error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error during deletion: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def get_quarantine_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive quarantine statistics with additional analysis.
        
        Returns:
            Dictionary containing quarantine statistics and analysis
        """
        try:
            stats = self.manager.get_quarantine_stats()
            entries = self.manager.list_quarantined_files()
            
            # Calculate additional statistics
            if entries:
                # Age analysis
                now = datetime.now()
                ages = [(now - entry.quarantine_date).days for entry in entries]
                avg_age = sum(ages) / len(ages)
                oldest_age = max(ages)
                newest_age = min(ages)
                
                # Risk score analysis
                risk_scores = [entry.detection_info.risk_score for entry in entries]
                avg_risk_score = sum(risk_scores) / len(risk_scores)
                high_risk_count = sum(1 for score in risk_scores if score >= 8)
                
                # Threat analysis
                threat_names = [entry.detection_info.threat_name for entry in entries]
                unique_threats = len(set(threat_names))
                
                stats.update({
                    'age_analysis': {
                        'average_days': round(avg_age, 1),
                        'oldest_days': oldest_age,
                        'newest_days': newest_age
                    },
                    'risk_analysis': {
                        'average_risk_score': round(avg_risk_score, 1),
                        'high_risk_count': high_risk_count,
                        'high_risk_percentage': round((high_risk_count / len(entries)) * 100, 1)
                    },
                    'threat_analysis': {
                        'unique_threats': unique_threats,
                        'total_detections': len(entries)
                    }
                })
            else:
                stats.update({
                    'age_analysis': {'average_days': 0, 'oldest_days': 0, 'newest_days': 0},
                    'risk_analysis': {'average_risk_score': 0, 'high_risk_count': 0, 'high_risk_percentage': 0},
                    'threat_analysis': {'unique_threats': 0, 'total_detections': 0}
                })
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get quarantine statistics: {str(e)}")
            return {
                'total_quarantined': 0,
                'active_quarantined': 0,
                'restored_files': 0,
                'error': str(e)
            }
    
    def export_quarantine_report(self, 
                               output_path: Optional[str] = None,
                               include_statistics: bool = True) -> Tuple[bool, str]:
        """
        Export a comprehensive quarantine report.
        
        Args:
            output_path: Path to save the report (optional)
            include_statistics: Whether to include statistics in the report
            
        Returns:
            Tuple of (success: bool, file_path_or_error: str)
        """
        try:
            report_path = self.manager.export_quarantine_report(output_path)
            
            if include_statistics:
                # Add statistics to the report
                stats = self.get_quarantine_statistics()
                
                # Read existing report and add statistics
                import json
                with open(report_path, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
                
                report_data['enhanced_statistics'] = stats
                
                # Save updated report
                with open(report_path, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=2)
            
            self.logger.info(f"Quarantine report exported: {report_path}")
            return True, report_path
            
        except Exception as e:
            error_msg = f"Failed to export quarantine report: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def cleanup_old_quarantine_files(self, 
                                   days_old: int = 30,
                                   confirm_callback: Optional[callable] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Clean up old quarantined files with user confirmation.
        
        Args:
            days_old: Remove files quarantined more than this many days ago
            confirm_callback: Optional callback function for user confirmation
            
        Returns:
            Tuple of (success: bool, cleanup_result: dict)
        """
        try:
            # Get files that would be affected
            entries = self.manager.list_quarantined_files()
            cutoff_date = datetime.now() - timedelta(days=days_old)
            affected_files = [e for e in entries if e.quarantine_date < cutoff_date]
            
            if not affected_files:
                return True, {
                    'removed_count': 0,
                    'message': 'No files found older than specified age',
                    'cutoff_date': cutoff_date.isoformat()
                }
            
            # Get confirmation if callback provided
            if confirm_callback:
                confirmed = confirm_callback(
                    f"This will permanently delete {len(affected_files)} quarantined files "
                    f"older than {days_old} days.\nThis action cannot be undone!",
                    "cleanup_confirmation"
                )
                if not confirmed:
                    return False, {
                        'removed_count': 0,
                        'message': 'Cleanup cancelled by user',
                        'cutoff_date': cutoff_date.isoformat()
                    }
            
            # Perform cleanup
            result = self.manager.cleanup_quarantine(days_old=days_old, confirm=True)
            
            self.logger.info(f"Quarantine cleanup completed: {result['removed_count']} files removed")
            return True, result
            
        except Exception as e:
            error_msg = f"Cleanup failed: {str(e)}"
            self.logger.error(error_msg)
            return False, {'error': error_msg}
    
    def validate_quarantine_integrity(self) -> Dict[str, Any]:
        """
        Validate the integrity of the quarantine system.
        
        Returns:
            Dictionary with validation results
        """
        try:
            entries = self.manager.list_quarantined_files()
            
            validation_result = {
                'total_entries': len(entries),
                'valid_entries': 0,
                'missing_files': [],
                'corrupted_entries': [],
                'orphaned_files': [],
                'issues_found': False
            }
            
            # Check each quarantine entry
            for entry in entries:
                try:
                    quarantine_path = Path(entry.quarantine_path)
                    
                    if quarantine_path.exists():
                        validation_result['valid_entries'] += 1
                    else:
                        validation_result['missing_files'].append({
                            'quarantine_id': entry.quarantine_id,
                            'original_path': entry.original_path,
                            'expected_path': str(quarantine_path)
                        })
                        validation_result['issues_found'] = True
                        
                except Exception as e:
                    validation_result['corrupted_entries'].append({
                        'quarantine_id': entry.quarantine_id,
                        'error': str(e)
                    })
                    validation_result['issues_found'] = True
            
            # Check for orphaned files in quarantine directory
            quarantine_files_dir = Path(self.manager.quarantine_path) / "files"
            if quarantine_files_dir.exists():
                expected_files = {Path(entry.quarantine_path).name for entry in entries}
                actual_files = {f.name for f in quarantine_files_dir.iterdir() if f.is_file()}
                
                orphaned = actual_files - expected_files
                if orphaned:
                    validation_result['orphaned_files'] = list(orphaned)
                    validation_result['issues_found'] = True
            
            return validation_result
            
        except Exception as e:
            return {
                'error': str(e),
                'issues_found': True
            }


def create_simple_confirmation_callback():
    """
    Create a simple console-based confirmation callback for CLI usage.
    
    Returns:
        Confirmation callback function
    """
    def confirm(message: str, confirmation_type: str) -> bool:
        """Simple console confirmation."""
        print(f"\n{message}")
        response = input("Continue? (y/N): ").strip().lower()
        return response == 'y'
    
    return confirm