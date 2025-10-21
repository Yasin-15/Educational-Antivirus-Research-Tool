"""
Quarantine Manager for the Educational Antivirus Research Tool.

This module handles secure isolation of detected files, including:
- Creating secure quarantine directories with restricted permissions
- Moving files to quarantine with metadata tracking
- Managing quarantined file operations (list, restore, delete)
"""
import os
import shutil
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import stat
import logging

from core.models import Detection, QuarantineEntry
from core.exceptions import QuarantineError, FileAccessError


class QuarantineManager:
    """Manages quarantine operations for detected files."""
    
    def __init__(self, quarantine_path: str = "quarantine"):
        """
        Initialize the QuarantineManager.
        
        Args:
            quarantine_path: Base directory for quarantine operations
        """
        self.quarantine_path = Path(quarantine_path)
        self.metadata_file = self.quarantine_path / "metadata.json"
        self.logger = logging.getLogger(__name__)
        
        # Initialize quarantine directory
        self._initialize_quarantine_directory()
    
    def _initialize_quarantine_directory(self) -> None:
        """
        Create and secure the quarantine directory structure.
        
        Creates:
        - Main quarantine directory with restricted permissions
        - Files subdirectory for quarantined files
        - Metadata file for tracking quarantined items
        """
        try:
            # Create main quarantine directory
            self.quarantine_path.mkdir(parents=True, exist_ok=True)
            
            # Create files subdirectory
            files_dir = self.quarantine_path / "files"
            files_dir.mkdir(exist_ok=True)
            
            # Set restrictive permissions (owner read/write/execute only)
            if os.name != 'nt':  # Unix-like systems
                os.chmod(self.quarantine_path, stat.S_IRWXU)
                os.chmod(files_dir, stat.S_IRWXU)
            else:  # Windows - use basic permission restriction
                # On Windows, we'll rely on the directory being in the application folder
                pass
            
            # Initialize metadata file if it doesn't exist
            if not self.metadata_file.exists():
                self._save_metadata({})
                
            self.logger.info(f"Quarantine directory initialized at: {self.quarantine_path}")
            
        except Exception as e:
            raise QuarantineError(f"Failed to initialize quarantine directory: {str(e)}")
    
    def _load_metadata(self) -> Dict[str, Dict[str, Any]]:
        """
        Load quarantine metadata from file.
        
        Returns:
            Dictionary mapping quarantine IDs to metadata
        """
        try:
            if self.metadata_file.exists():
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            self.logger.error(f"Failed to load quarantine metadata: {str(e)}")
            return {}
    
    def _save_metadata(self, metadata: Dict[str, Dict[str, Any]]) -> None:
        """
        Save quarantine metadata to file.
        
        Args:
            metadata: Dictionary mapping quarantine IDs to metadata
        """
        try:
            with open(self.metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, default=str)
        except Exception as e:
            raise QuarantineError(f"Failed to save quarantine metadata: {str(e)}")
    
    def _generate_quarantine_id(self) -> str:
        """
        Generate a unique quarantine ID.
        
        Returns:
            Unique quarantine identifier
        """
        return str(uuid.uuid4())
    
    def _get_quarantine_file_path(self, quarantine_id: str, original_filename: str) -> Path:
        """
        Get the quarantine file path for a given ID and filename.
        
        Args:
            quarantine_id: Unique quarantine identifier
            original_filename: Original filename
            
        Returns:
            Path where the quarantined file should be stored
        """
        # Use quarantine ID as prefix to avoid filename conflicts
        safe_filename = f"{quarantine_id}_{Path(original_filename).name}"
        return self.quarantine_path / "files" / safe_filename
    
    def quarantine_file(self, file_path: str, detection_info: Detection) -> str:
        """
        Move a file to quarantine with secure isolation.
        
        Args:
            file_path: Path to the file to quarantine
            detection_info: Detection information for the file
            
        Returns:
            Quarantine ID for the quarantined file
            
        Raises:
            QuarantineError: If quarantine operation fails
            FileAccessError: If file cannot be accessed
        """
        try:
            source_path = Path(file_path)
            
            # Validate source file exists
            if not source_path.exists():
                raise FileAccessError(f"Source file does not exist: {file_path}")
            
            if not source_path.is_file():
                raise FileAccessError(f"Source is not a file: {file_path}")
            
            # Generate quarantine ID and destination path
            quarantine_id = self._generate_quarantine_id()
            quarantine_file_path = self._get_quarantine_file_path(quarantine_id, source_path.name)
            
            # Copy file to quarantine (preserve original until confirmed)
            shutil.copy2(source_path, quarantine_file_path)
            
            # Set restrictive permissions on quarantined file
            if os.name != 'nt':  # Unix-like systems
                os.chmod(quarantine_file_path, stat.S_IRUSR | stat.S_IWUSR)
            
            # Create quarantine entry
            quarantine_entry = QuarantineEntry(
                quarantine_id=quarantine_id,
                original_path=str(source_path.absolute()),
                quarantine_path=str(quarantine_file_path),
                detection_info=detection_info,
                quarantine_date=datetime.now(),
                restored=False
            )
            
            # Update metadata
            metadata = self._load_metadata()
            metadata[quarantine_id] = {
                'quarantine_id': quarantine_id,
                'original_path': quarantine_entry.original_path,
                'quarantine_path': quarantine_entry.quarantine_path,
                'detection_info': detection_info.to_dict(),
                'quarantine_date': quarantine_entry.quarantine_date.isoformat(),
                'restored': False
            }
            self._save_metadata(metadata)
            
            # Remove original file after successful quarantine
            try:
                source_path.unlink()
                self.logger.info(f"File quarantined successfully: {file_path} -> {quarantine_id}")
            except Exception as e:
                # If we can't remove the original, log warning but don't fail
                self.logger.warning(f"Could not remove original file after quarantine: {str(e)}")
            
            return quarantine_id
            
        except Exception as e:
            if isinstance(e, (QuarantineError, FileAccessError)):
                raise
            raise QuarantineError(f"Failed to quarantine file {file_path}: {str(e)}")
    
    def list_quarantined_files(self) -> List[QuarantineEntry]:
        """
        Get a list of all quarantined files.
        
        Returns:
            List of QuarantineEntry objects for all quarantined files
        """
        try:
            metadata = self._load_metadata()
            entries = []
            
            for quarantine_id, data in metadata.items():
                # Reconstruct Detection object
                detection_data = data['detection_info']
                detection = Detection.from_dict(detection_data)
                
                # Create QuarantineEntry
                entry = QuarantineEntry(
                    quarantine_id=data['quarantine_id'],
                    original_path=data['original_path'],
                    quarantine_path=data['quarantine_path'],
                    detection_info=detection,
                    quarantine_date=datetime.fromisoformat(data['quarantine_date']),
                    restored=data.get('restored', False)
                )
                entries.append(entry)
            
            # Sort by quarantine date (newest first)
            entries.sort(key=lambda x: x.quarantine_date, reverse=True)
            return entries
            
        except Exception as e:
            self.logger.error(f"Failed to list quarantined files: {str(e)}")
            return []
    
    def get_quarantine_entry(self, quarantine_id: str) -> Optional[QuarantineEntry]:
        """
        Get details for a specific quarantined file.
        
        Args:
            quarantine_id: Unique quarantine identifier
            
        Returns:
            QuarantineEntry object or None if not found
        """
        try:
            metadata = self._load_metadata()
            
            if quarantine_id not in metadata:
                return None
            
            data = metadata[quarantine_id]
            detection_data = data['detection_info']
            detection = Detection.from_dict(detection_data)
            
            return QuarantineEntry(
                quarantine_id=data['quarantine_id'],
                original_path=data['original_path'],
                quarantine_path=data['quarantine_path'],
                detection_info=detection,
                quarantine_date=datetime.fromisoformat(data['quarantine_date']),
                restored=data.get('restored', False)
            )
            
        except Exception as e:
            self.logger.error(f"Failed to get quarantine entry {quarantine_id}: {str(e)}")
            return None
    
    def get_quarantine_stats(self) -> Dict[str, Any]:
        """
        Get statistics about quarantined files.
        
        Returns:
            Dictionary with quarantine statistics
        """
        try:
            entries = self.list_quarantined_files()
            
            total_files = len(entries)
            restored_files = sum(1 for entry in entries if entry.restored)
            active_files = total_files - restored_files
            
            # Count by detection type
            signature_detections = sum(1 for entry in entries 
                                    if entry.detection_info.detection_type.value == 'signature')
            behavioral_detections = sum(1 for entry in entries 
                                     if entry.detection_info.detection_type.value == 'behavioral')
            
            return {
                'total_quarantined': total_files,
                'active_quarantined': active_files,
                'restored_files': restored_files,
                'signature_detections': signature_detections,
                'behavioral_detections': behavioral_detections,
                'quarantine_path': str(self.quarantine_path),
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get quarantine stats: {str(e)}")
            return {
                'total_quarantined': 0,
                'active_quarantined': 0,
                'restored_files': 0,
                'signature_detections': 0,
                'behavioral_detections': 0,
                'quarantine_path': str(self.quarantine_path),
                'last_updated': datetime.now().isoformat(),
                'error': str(e)
            }    

    def restore_file(self, quarantine_id: str, force: bool = False) -> bool:
        """
        Restore a quarantined file to its original location.
        
        Args:
            quarantine_id: Unique quarantine identifier
            force: If True, overwrite existing file at original location
            
        Returns:
            True if restoration was successful, False otherwise
            
        Raises:
            QuarantineError: If restoration fails
        """
        try:
            # Get quarantine entry
            entry = self.get_quarantine_entry(quarantine_id)
            if not entry:
                raise QuarantineError(f"Quarantine entry not found: {quarantine_id}")
            
            if entry.restored:
                self.logger.warning(f"File already restored: {quarantine_id}")
                return True
            
            # Check if quarantined file exists
            quarantine_file_path = Path(entry.quarantine_path)
            if not quarantine_file_path.exists():
                raise QuarantineError(f"Quarantined file not found: {entry.quarantine_path}")
            
            # Check original location
            original_path = Path(entry.original_path)
            
            # Create parent directories if they don't exist
            original_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Check if file already exists at original location
            if original_path.exists() and not force:
                raise QuarantineError(
                    f"File already exists at original location: {entry.original_path}. "
                    "Use force=True to overwrite."
                )
            
            # Copy file back to original location
            shutil.copy2(quarantine_file_path, original_path)
            
            # Restore original permissions (best effort)
            if os.name != 'nt':  # Unix-like systems
                try:
                    os.chmod(original_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
                except Exception as e:
                    self.logger.warning(f"Could not restore file permissions: {str(e)}")
            
            # Update metadata to mark as restored
            metadata = self._load_metadata()
            if quarantine_id in metadata:
                metadata[quarantine_id]['restored'] = True
                metadata[quarantine_id]['restore_date'] = datetime.now().isoformat()
                self._save_metadata(metadata)
            
            self.logger.info(f"File restored successfully: {quarantine_id} -> {entry.original_path}")
            return True
            
        except Exception as e:
            if isinstance(e, QuarantineError):
                raise
            raise QuarantineError(f"Failed to restore file {quarantine_id}: {str(e)}")
    
    def delete_quarantined_file(self, quarantine_id: str, confirm: bool = False) -> bool:
        """
        Permanently delete a quarantined file.
        
        Args:
            quarantine_id: Unique quarantine identifier
            confirm: Confirmation flag to prevent accidental deletion
            
        Returns:
            True if deletion was successful, False otherwise
            
        Raises:
            QuarantineError: If deletion fails or confirmation not provided
        """
        try:
            if not confirm:
                raise QuarantineError(
                    "Deletion requires explicit confirmation. Set confirm=True to proceed."
                )
            
            # Get quarantine entry
            entry = self.get_quarantine_entry(quarantine_id)
            if not entry:
                raise QuarantineError(f"Quarantine entry not found: {quarantine_id}")
            
            # Remove quarantined file
            quarantine_file_path = Path(entry.quarantine_path)
            if quarantine_file_path.exists():
                quarantine_file_path.unlink()
                self.logger.info(f"Quarantined file deleted: {entry.quarantine_path}")
            
            # Remove from metadata
            metadata = self._load_metadata()
            if quarantine_id in metadata:
                del metadata[quarantine_id]
                self._save_metadata(metadata)
            
            self.logger.info(f"Quarantine entry removed: {quarantine_id}")
            return True
            
        except Exception as e:
            if isinstance(e, QuarantineError):
                raise
            raise QuarantineError(f"Failed to delete quarantined file {quarantine_id}: {str(e)}")
    
    def cleanup_quarantine(self, days_old: int = 30, confirm: bool = False) -> Dict[str, Any]:
        """
        Clean up old quarantined files.
        
        Args:
            days_old: Remove files quarantined more than this many days ago
            confirm: Confirmation flag to prevent accidental cleanup
            
        Returns:
            Dictionary with cleanup statistics
            
        Raises:
            QuarantineError: If cleanup fails or confirmation not provided
        """
        try:
            if not confirm:
                raise QuarantineError(
                    "Cleanup requires explicit confirmation. Set confirm=True to proceed."
                )
            
            cutoff_date = datetime.now() - timedelta(days=days_old)
            entries = self.list_quarantined_files()
            
            removed_count = 0
            errors = []
            
            for entry in entries:
                if entry.quarantine_date < cutoff_date:
                    try:
                        self.delete_quarantined_file(entry.quarantine_id, confirm=True)
                        removed_count += 1
                    except Exception as e:
                        errors.append(f"Failed to remove {entry.quarantine_id}: {str(e)}")
            
            result = {
                'removed_count': removed_count,
                'cutoff_date': cutoff_date.isoformat(),
                'errors': errors
            }
            
            self.logger.info(f"Quarantine cleanup completed: {removed_count} files removed")
            return result
            
        except Exception as e:
            if isinstance(e, QuarantineError):
                raise
            raise QuarantineError(f"Failed to cleanup quarantine: {str(e)}")
    
    def export_quarantine_report(self, output_path: str = None) -> str:
        """
        Export a detailed report of all quarantined files.
        
        Args:
            output_path: Path to save the report (optional)
            
        Returns:
            Path to the generated report file
        """
        try:
            entries = self.list_quarantined_files()
            stats = self.get_quarantine_stats()
            
            # Generate report data
            report_data = {
                'report_generated': datetime.now().isoformat(),
                'statistics': stats,
                'quarantined_files': []
            }
            
            for entry in entries:
                file_data = {
                    'quarantine_id': entry.quarantine_id,
                    'original_path': entry.original_path,
                    'quarantine_date': entry.quarantine_date.isoformat(),
                    'restored': entry.restored,
                    'detection_info': {
                        'threat_name': entry.detection_info.threat_name,
                        'detection_type': entry.detection_info.detection_type.value,
                        'risk_score': entry.detection_info.risk_score,
                        'signature_id': entry.detection_info.signature_id,
                        'timestamp': entry.detection_info.timestamp.isoformat()
                    }
                }
                report_data['quarantined_files'].append(file_data)
            
            # Determine output path
            if output_path is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = self.quarantine_path / f"quarantine_report_{timestamp}.json"
            else:
                output_path = Path(output_path)
            
            # Save report
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
            
            self.logger.info(f"Quarantine report exported: {output_path}")
            return str(output_path)
            
        except Exception as e:
            raise QuarantineError(f"Failed to export quarantine report: {str(e)}")


# Import required for cleanup method
from datetime import timedelta