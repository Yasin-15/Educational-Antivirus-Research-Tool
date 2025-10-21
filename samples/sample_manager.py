"""
Sample manager for creating and managing harmless test malware samples.
"""
import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

from core.models import SampleInfo
from core.exceptions import AntivirusError
from samples.sample_generator import SampleGenerator, SampleGeneratorError


class SampleManagerError(AntivirusError):
    """Raised when sample management operations fail."""
    pass


class SampleManager:
    """Manages creation, storage, and metadata of test samples."""
    
    def __init__(self, samples_path: str = "samples/", metadata_file: str = "sample_metadata.json"):
        """Initialize the sample manager.
        
        Args:
            samples_path: Directory to store samples
            metadata_file: File to store sample metadata
        """
        self.samples_path = Path(samples_path)
        self.samples_path.mkdir(parents=True, exist_ok=True)
        
        self.metadata_file = self.samples_path / metadata_file
        self.generator = SampleGenerator(str(self.samples_path))
        self._metadata_cache: Dict[str, SampleInfo] = {}
        
        # Load existing metadata
        self._load_metadata()
    
    def create_test_sample(self, sample_type: str, name: Optional[str] = None, **kwargs) -> SampleInfo:
        """Create a new test sample.
        
        Args:
            sample_type: Type of sample ('eicar', 'custom_signature', 'behavioral_trigger')
            name: Optional custom name for the sample
            **kwargs: Additional arguments specific to sample type
            
        Returns:
            SampleInfo object with sample metadata
            
        Raises:
            SampleManagerError: If sample creation fails
        """
        try:
            # Check if sample with same name already exists
            if name and self._sample_name_exists(name):
                raise SampleManagerError(f"Sample with name '{name}' already exists")
            
            # Create sample based on type
            if sample_type == 'eicar':
                filename = name or "eicar.txt"
                sample_info = self.generator.create_eicar_sample(filename)
                
            elif sample_type == 'custom_signature':
                signature_name = kwargs.get('signature_name')
                if not signature_name:
                    raise SampleManagerError("signature_name required for custom_signature type")
                sample_info = self.generator.create_custom_signature_sample(signature_name, name)
                
            elif sample_type == 'behavioral_trigger':
                trigger_type = kwargs.get('trigger_type')
                if not trigger_type:
                    raise SampleManagerError("trigger_type required for behavioral_trigger type")
                sample_info = self.generator.create_behavioral_trigger_sample(trigger_type, name)
                
            else:
                valid_types = ['eicar', 'custom_signature', 'behavioral_trigger']
                raise SampleManagerError(f"Unknown sample type '{sample_type}'. Valid types: {', '.join(valid_types)}")
            
            # Store metadata
            self._add_sample_metadata(sample_info)
            
            return sample_info
            
        except SampleGeneratorError as e:
            raise SampleManagerError(f"Sample generation failed: {e}")
        except Exception as e:
            raise SampleManagerError(f"Failed to create test sample: {e}")
    
    def list_available_samples(self) -> List[SampleInfo]:
        """Get list of all available test samples.
        
        Returns:
            List of SampleInfo objects
        """
        return list(self._metadata_cache.values())
    
    def get_sample_metadata(self, sample_id: str) -> Optional[SampleInfo]:
        """Get metadata for a specific sample.
        
        Args:
            sample_id: ID of the sample
            
        Returns:
            SampleInfo object or None if not found
        """
        return self._metadata_cache.get(sample_id)
    
    def get_sample_by_name(self, name: str) -> Optional[SampleInfo]:
        """Get sample by name.
        
        Args:
            name: Name of the sample
            
        Returns:
            SampleInfo object or None if not found
        """
        for sample in self._metadata_cache.values():
            if sample.name == name:
                return sample
        return None
    
    def delete_sample(self, sample_id: str, confirm: bool = False) -> bool:
        """Delete a test sample and its metadata.
        
        Args:
            sample_id: ID of the sample to delete
            confirm: Whether deletion is confirmed
            
        Returns:
            True if deleted successfully, False otherwise
            
        Raises:
            SampleManagerError: If sample not found or deletion fails
        """
        if not confirm:
            raise SampleManagerError("Deletion must be confirmed with confirm=True")
        
        sample_info = self._metadata_cache.get(sample_id)
        if not sample_info:
            raise SampleManagerError(f"Sample with ID '{sample_id}' not found")
        
        try:
            # Delete the file
            file_path = Path(sample_info.file_path)
            if file_path.exists():
                file_path.unlink()
            
            # Remove from metadata
            del self._metadata_cache[sample_id]
            self._save_metadata()
            
            return True
            
        except Exception as e:
            raise SampleManagerError(f"Failed to delete sample: {e}")
    
    def cleanup_orphaned_files(self) -> List[str]:
        """Remove files that exist but have no metadata entries.
        
        Only removes files that appear to be sample files (not Python source files).
        
        Returns:
            List of cleaned up file paths
        """
        cleaned_files = []
        
        # Extensions that should NOT be cleaned up (source code, etc.)
        protected_extensions = {'.py', '.pyc', '.pyo', '.pyd', '.so', '.dll'}
        protected_names = {'__pycache__', '__init__.py'}
        
        try:
            # Get all files in samples directory
            for file_path in self.samples_path.iterdir():
                if file_path.is_file() and file_path.name != self.metadata_file.name:
                    # Skip protected files (Python source, etc.)
                    if (file_path.suffix.lower() in protected_extensions or 
                        file_path.name in protected_names or
                        file_path.name.startswith('__')):
                        continue
                    
                    # Check if file has corresponding metadata
                    file_has_metadata = False
                    for sample in self._metadata_cache.values():
                        if Path(sample.file_path) == file_path:
                            file_has_metadata = True
                            break
                    
                    # If no metadata found, it's orphaned
                    if not file_has_metadata:
                        file_path.unlink()
                        cleaned_files.append(str(file_path))
            
            return cleaned_files
            
        except Exception as e:
            raise SampleManagerError(f"Failed to cleanup orphaned files: {e}")
    
    def validate_samples(self) -> Dict[str, List[str]]:
        """Validate all samples and their metadata.
        
        Returns:
            Dictionary with 'valid', 'missing_files', and 'corrupted_metadata' lists
        """
        result = {
            'valid': [],
            'missing_files': [],
            'corrupted_metadata': []
        }
        
        for sample_id, sample_info in self._metadata_cache.items():
            try:
                file_path = Path(sample_info.file_path)
                
                # Check if file exists
                if not file_path.exists():
                    result['missing_files'].append(sample_id)
                    continue
                
                # Basic validation of sample info
                if not all([sample_info.name, sample_info.sample_type, sample_info.description]):
                    result['corrupted_metadata'].append(sample_id)
                    continue
                
                result['valid'].append(sample_id)
                
            except Exception:
                result['corrupted_metadata'].append(sample_id)
        
        return result
    
    def get_samples_by_type(self, sample_type: str) -> List[SampleInfo]:
        """Get all samples of a specific type.
        
        Args:
            sample_type: Type of samples to retrieve
            
        Returns:
            List of SampleInfo objects
        """
        return [sample for sample in self._metadata_cache.values() 
                if sample.sample_type == sample_type]
    
    def get_sample_statistics(self) -> Dict[str, int]:
        """Get statistics about stored samples.
        
        Returns:
            Dictionary with sample counts by type
        """
        stats = {}
        for sample in self._metadata_cache.values():
            sample_type = sample.sample_type
            stats[sample_type] = stats.get(sample_type, 0) + 1
        
        stats['total'] = len(self._metadata_cache)
        return stats
    
    def export_sample_list(self, output_file: str, format: str = 'json') -> bool:
        """Export sample list to file.
        
        Args:
            output_file: Path to output file
            format: Export format ('json' or 'csv')
            
        Returns:
            True if export successful
            
        Raises:
            SampleManagerError: If export fails
        """
        try:
            if format == 'json':
                data = [sample.to_dict() for sample in self._metadata_cache.values()]
                with open(output_file, 'w') as f:
                    json.dump(data, f, indent=2)
                    
            elif format == 'csv':
                import csv
                with open(output_file, 'w', newline='') as f:
                    if not self._metadata_cache:
                        return True
                    
                    # Get field names from first sample
                    first_sample = next(iter(self._metadata_cache.values()))
                    fieldnames = first_sample.to_dict().keys()
                    
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for sample in self._metadata_cache.values():
                        writer.writerow(sample.to_dict())
            else:
                raise SampleManagerError(f"Unsupported export format: {format}")
            
            return True
            
        except Exception as e:
            raise SampleManagerError(f"Failed to export sample list: {e}")
    
    def get_available_signature_types(self) -> List[str]:
        """Get list of available custom signature types.
        
        Returns:
            List of signature names
        """
        return self.generator.get_available_signatures()
    
    def get_available_behavioral_triggers(self) -> List[str]:
        """Get list of available behavioral trigger types.
        
        Returns:
            List of trigger type names
        """
        return self.generator.get_available_behavioral_triggers()
    
    def _sample_name_exists(self, name: str) -> bool:
        """Check if a sample with the given name already exists."""
        return any(sample.name == name for sample in self._metadata_cache.values())
    
    def _add_sample_metadata(self, sample_info: SampleInfo) -> None:
        """Add sample metadata to cache and save to file."""
        self._metadata_cache[sample_info.sample_id] = sample_info
        self._save_metadata()
    
    def _load_metadata(self) -> None:
        """Load sample metadata from file."""
        try:
            if self.metadata_file.exists():
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    
                for item in data:
                    sample_info = SampleInfo.from_dict(item)
                    self._metadata_cache[sample_info.sample_id] = sample_info
                    
        except Exception as e:
            # If metadata file is corrupted, start fresh but log the error
            print(f"Warning: Could not load sample metadata: {e}")
            self._metadata_cache = {}
    
    def _save_metadata(self) -> None:
        """Save sample metadata to file."""
        try:
            data = [sample.to_dict() for sample in self._metadata_cache.values()]
            with open(self.metadata_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            raise SampleManagerError(f"Failed to save sample metadata: {e}")