"""
Signature detection engine for the Educational Antivirus Research Tool.
"""
import os
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from core.exceptions import SignatureError, ScanError, FileAccessError
from core.logging_config import get_logger
from core.models import Detection, DetectionType, FileInfo
from core.file_utils import calculate_file_hash, get_file_info
from .signature_database import SignatureDatabaseManager
from .pattern_matcher import MultiPatternMatcher
from .signature_models import Signature, SignatureMatch
from .default_signatures import get_default_signatures

logger = get_logger(__name__)


class SignatureEngine:
    """Main signature detection engine that coordinates signature scanning operations."""
    
    def __init__(self, db_path: str, sensitivity: int = 5):
        """Initialize the signature detection engine.
        
        Args:
            db_path: Path to the signature database
            sensitivity: Detection sensitivity (1-10, higher = more sensitive)
        """
        self.db_path = db_path
        self.sensitivity = sensitivity
        self.db_manager: Optional[SignatureDatabaseManager] = None
        self.pattern_matcher: Optional[MultiPatternMatcher] = None
        self._signatures_loaded = False
        
        # Statistics
        self.scan_stats = {
            'files_scanned': 0,
            'signatures_matched': 0,
            'total_matches': 0,
            'scan_time': 0.0
        }
    
    def initialize(self) -> bool:
        """Initialize the signature engine and load signatures.
        
        Returns:
            True if initialization successful
            
        Raises:
            SignatureError: If initialization fails
        """
        try:
            # Initialize database manager
            self.db_manager = SignatureDatabaseManager(self.db_path)
            
            # Load default signatures if database is empty
            metadata = self.db_manager.get_metadata()
            if metadata.signature_count == 0:
                logger.info("Loading default educational signatures...")
                self._load_default_signatures()
            
            # Load signatures for pattern matching
            self._load_signatures()
            
            logger.info(f"Signature engine initialized with {len(self.pattern_matcher.signatures)} signatures")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize signature engine: {e}")
            raise SignatureError(f"Engine initialization failed: {e}")
    
    def _load_default_signatures(self) -> None:
        """Load default educational signatures into the database."""
        default_signatures = get_default_signatures()
        
        for signature in default_signatures:
            try:
                self.db_manager.add_signature(signature)
                logger.debug(f"Added default signature: {signature.name}")
            except SignatureError as e:
                logger.warning(f"Failed to add default signature {signature.signature_id}: {e}")
    
    def _load_signatures(self) -> None:
        """Load signatures from database for pattern matching."""
        try:
            signatures = self.db_manager.get_all_signatures(enabled_only=True)
            self.pattern_matcher = MultiPatternMatcher(signatures, self.sensitivity)
            self._signatures_loaded = True
            
            logger.info(f"Loaded {len(signatures)} signatures for pattern matching")
            
        except Exception as e:
            logger.error(f"Failed to load signatures: {e}")
            raise SignatureError(f"Signature loading failed: {e}")
    
    def scan_file(self, file_path: str) -> List[Detection]:
        """Scan a single file for signature matches.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            List of Detection objects for any matches found
            
        Raises:
            ScanError: If file scanning fails
        """
        if not self._signatures_loaded:
            raise ScanError("Signatures not loaded - call initialize() first")
        
        detections = []
        scan_start = datetime.now()
        
        try:
            # Check if file exists and is accessible
            if not os.path.exists(file_path):
                raise FileAccessError(f"File not found: {file_path}")
            
            if not os.path.isfile(file_path):
                raise FileAccessError(f"Path is not a file: {file_path}")
            
            # Get file info for size checking
            file_info = get_file_info(file_path)
            
            # Skip large files based on configuration
            max_size_bytes = 100 * 1024 * 1024  # 100MB default
            if file_info.size > max_size_bytes:
                logger.info(f"Skipping large file: {file_path} ({file_info.size} bytes)")
                return detections
            
            # Read file content
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
            except (IOError, OSError, PermissionError) as e:
                raise FileAccessError(f"Cannot read file {file_path}: {e}")
            
            # Perform signature matching
            matches = self.pattern_matcher.match_all(file_data, file_path)
            
            # Convert matches to Detection objects
            for match in matches:
                detection = self._create_detection_from_match(match, file_info)
                detections.append(detection)
                
                logger.info(f"Detection: {match.signature.name} in {file_path}")
            
            # Update statistics
            self.scan_stats['files_scanned'] += 1
            self.scan_stats['total_matches'] += len(matches)
            if matches:
                self.scan_stats['signatures_matched'] += len(set(m.signature.signature_id for m in matches))
            
            scan_time = (datetime.now() - scan_start).total_seconds()
            self.scan_stats['scan_time'] += scan_time
            
            logger.debug(f"Scanned {file_path}: {len(detections)} detections in {scan_time:.3f}s")
            
        except FileAccessError:
            raise
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            raise ScanError(f"File scan failed: {e}")
        
        return detections
    
    def scan_directory(self, directory_path: str, recursive: bool = True, 
                      skip_extensions: Optional[List[str]] = None) -> List[Detection]:
        """Scan all files in a directory for signature matches.
        
        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories
            skip_extensions: List of file extensions to skip
            
        Returns:
            List of all Detection objects found
            
        Raises:
            ScanError: If directory scanning fails
        """
        if not self._signatures_loaded:
            raise ScanError("Signatures not loaded - call initialize() first")
        
        if skip_extensions is None:
            skip_extensions = ['.tmp', '.log', '.bak']
        
        all_detections = []
        scan_start = datetime.now()
        
        try:
            directory = Path(directory_path)
            if not directory.exists():
                raise FileAccessError(f"Directory not found: {directory_path}")
            
            if not directory.is_dir():
                raise FileAccessError(f"Path is not a directory: {directory_path}")
            
            # Get file list
            if recursive:
                file_pattern = "**/*"
            else:
                file_pattern = "*"
            
            files_to_scan = []
            for file_path in directory.glob(file_pattern):
                if file_path.is_file():
                    # Check if we should skip this file
                    if any(str(file_path).lower().endswith(ext.lower()) for ext in skip_extensions):
                        logger.debug(f"Skipping file with excluded extension: {file_path}")
                        continue
                    
                    files_to_scan.append(str(file_path))
            
            logger.info(f"Scanning {len(files_to_scan)} files in {directory_path}")
            
            # Scan each file
            for file_path in files_to_scan:
                try:
                    file_detections = self.scan_file(file_path)
                    all_detections.extend(file_detections)
                except (FileAccessError, ScanError) as e:
                    logger.warning(f"Failed to scan {file_path}: {e}")
                    continue
            
            scan_time = (datetime.now() - scan_start).total_seconds()
            logger.info(f"Directory scan completed: {len(all_detections)} detections in {scan_time:.3f}s")
            
        except FileAccessError:
            raise
        except Exception as e:
            logger.error(f"Error scanning directory {directory_path}: {e}")
            raise ScanError(f"Directory scan failed: {e}")
        
        return all_detections
    
    def _create_detection_from_match(self, match: SignatureMatch, file_info: FileInfo) -> Detection:
        """Create a Detection object from a SignatureMatch.
        
        Args:
            match: SignatureMatch object
            file_info: FileInfo object for the scanned file
            
        Returns:
            Detection object
        """
        # Calculate risk score based on signature severity and confidence
        base_risk = match.signature.severity
        confidence_multiplier = match.confidence
        risk_score = min(10, int(base_risk * confidence_multiplier))
        
        # Create detailed information
        details = {
            'signature_id': match.signature.signature_id,
            'signature_type': match.signature.signature_type.value,
            'match_offset': match.match_offset,
            'match_length': match.match_length,
            'confidence': match.confidence,
            'context': match.context.hex() if match.context else "",
            'file_size': file_info.size,
            'file_hash_md5': file_info.hash_md5,
            'file_hash_sha256': file_info.hash_sha256,
            'threat_category': match.signature.threat_category,
            'educational_info': match.signature.metadata.get('explanation', ''),
            'harmless': match.signature.metadata.get('harmless', False)
        }
        
        return Detection(
            file_path=match.file_path,
            detection_type=DetectionType.SIGNATURE,
            threat_name=match.signature.name,
            risk_score=risk_score,
            signature_id=match.signature.signature_id,
            timestamp=datetime.now(),
            details=details
        )
    
    def add_custom_signature(self, name: str, pattern: bytes, signature_type: str,
                           description: str, threat_category: str, severity: int) -> bool:
        """Add a custom signature to the database.
        
        Args:
            name: Human-readable name for the signature
            pattern: Byte pattern to match
            signature_type: Type of signature (exact_match, pattern_match, etc.)
            description: Description of what this signature detects
            threat_category: Category of threat
            severity: Severity level (1-10)
            
        Returns:
            True if signature was added successfully
            
        Raises:
            SignatureError: If signature addition fails
        """
        try:
            from .signature_models import SignatureType
            
            # Generate unique ID
            signature_id = f"custom_{name.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Create signature object
            signature = Signature(
                signature_id=signature_id,
                name=name,
                signature_type=SignatureType(signature_type),
                pattern=pattern,
                description=description,
                threat_category=threat_category,
                severity=severity,
                metadata={'custom': True, 'educational': True}
            )
            
            # Add to database
            self.db_manager.add_signature(signature)
            
            # Reload signatures
            self._load_signatures()
            
            logger.info(f"Added custom signature: {name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add custom signature: {e}")
            raise SignatureError(f"Custom signature addition failed: {e}")
    
    def get_signature_info(self, signature_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a signature.
        
        Args:
            signature_id: ID of the signature
            
        Returns:
            Dictionary with signature information, or None if not found
        """
        try:
            signature = self.db_manager.get_signature(signature_id)
            if signature:
                return {
                    'id': signature.signature_id,
                    'name': signature.name,
                    'type': signature.signature_type.value,
                    'description': signature.description,
                    'threat_category': signature.threat_category,
                    'severity': signature.severity,
                    'created_date': signature.created_date.isoformat(),
                    'updated_date': signature.updated_date.isoformat(),
                    'enabled': signature.enabled,
                    'metadata': signature.metadata
                }
            return None
            
        except Exception as e:
            logger.error(f"Failed to get signature info: {e}")
            return None
    
    def list_signatures(self, enabled_only: bool = True) -> List[Dict[str, Any]]:
        """List all signatures in the database.
        
        Args:
            enabled_only: If True, only return enabled signatures
            
        Returns:
            List of signature information dictionaries
        """
        try:
            signatures = self.db_manager.get_all_signatures(enabled_only)
            return [
                {
                    'id': sig.signature_id,
                    'name': sig.name,
                    'type': sig.signature_type.value,
                    'threat_category': sig.threat_category,
                    'severity': sig.severity,
                    'enabled': sig.enabled
                }
                for sig in signatures
            ]
            
        except Exception as e:
            logger.error(f"Failed to list signatures: {e}")
            return []
    
    def update_sensitivity(self, sensitivity: int) -> None:
        """Update detection sensitivity.
        
        Args:
            sensitivity: New sensitivity level (1-10)
            
        Raises:
            SignatureError: If sensitivity is invalid
        """
        if not 1 <= sensitivity <= 10:
            raise SignatureError("Sensitivity must be between 1 and 10")
        
        self.sensitivity = sensitivity
        
        # Update pattern matcher if loaded
        if self.pattern_matcher:
            self.pattern_matcher.matcher.set_sensitivity(sensitivity)
        
        logger.info(f"Updated signature detection sensitivity to {sensitivity}")
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scanning statistics.
        
        Returns:
            Dictionary with scan statistics
        """
        stats = self.scan_stats.copy()
        
        # Calculate derived statistics
        if stats['files_scanned'] > 0:
            stats['avg_scan_time'] = stats['scan_time'] / stats['files_scanned']
            stats['detection_rate'] = stats['signatures_matched'] / stats['files_scanned']
        else:
            stats['avg_scan_time'] = 0.0
            stats['detection_rate'] = 0.0
        
        return stats
    
    def reset_statistics(self) -> None:
        """Reset scanning statistics."""
        self.scan_stats = {
            'files_scanned': 0,
            'signatures_matched': 0,
            'total_matches': 0,
            'scan_time': 0.0
        }
        logger.info("Scan statistics reset")
    
    def close(self) -> None:
        """Close the signature engine and cleanup resources."""
        if self.db_manager:
            self.db_manager.close()
            self.db_manager = None
        
        self.pattern_matcher = None
        self._signatures_loaded = False
        
        logger.info("Signature engine closed")
    
    def __enter__(self):
        """Context manager entry."""
        self.initialize()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()