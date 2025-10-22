"""
Core data models for the Educational Antivirus Research Tool.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime
import json


class DetectionType(Enum):
    """Types of detections."""
    SIGNATURE = "signature"
    BEHAVIORAL = "behavioral"
    HEURISTIC = "heuristic"


class ScanStatus(Enum):
    """Status of scan operations."""
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Config:
    """Configuration settings for the antivirus tool."""
    # Detection Settings
    signature_sensitivity: int = 7
    behavioral_threshold: int = 6
    max_file_size_mb: int = 50
    
    # File Paths
    signature_db_path: str = "data/signatures.db"
    quarantine_path: str = "quarantine/"
    samples_path: str = "samples/"
    reports_path: str = "reports/"
    
    # Behavioral Analysis Settings
    entropy_threshold: float = 7.0
    suspicious_extensions: List[str] = field(default_factory=lambda: [
        ".exe", ".scr", ".bat", ".cmd", ".vbs"
    ])
    
    # Logging Configuration
    log_level: str = "INFO"
    log_file: str = "antivirus.log"
    
    # Scanning Options
    recursive_scan: bool = True
    follow_symlinks: bool = False
    skip_extensions: List[str] = field(default_factory=lambda: [
        ".tmp", ".log", ".bak"
    ])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            'signature_sensitivity': self.signature_sensitivity,
            'behavioral_threshold': self.behavioral_threshold,
            'max_file_size_mb': self.max_file_size_mb,
            'signature_db_path': self.signature_db_path,
            'quarantine_path': self.quarantine_path,
            'samples_path': self.samples_path,
            'reports_path': self.reports_path,
            'entropy_threshold': self.entropy_threshold,
            'suspicious_extensions': self.suspicious_extensions,
            'log_level': self.log_level,
            'log_file': self.log_file,
            'recursive_scan': self.recursive_scan,
            'follow_symlinks': self.follow_symlinks,
            'skip_extensions': self.skip_extensions
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Config':
        """Create config from dictionary."""
        return cls(**data)


@dataclass
class FileInfo:
    """Information about a file being scanned."""
    path: str
    size: int
    md5_hash: str
    sha256_hash: str
    file_type: str
    permissions: str
    created_time: datetime
    modified_time: datetime
    entropy: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'path': self.path,
            'size': self.size,
            'md5_hash': self.md5_hash,
            'sha256_hash': self.sha256_hash,
            'file_type': self.file_type,
            'permissions': self.permissions,
            'created_time': self.created_time.isoformat(),
            'modified_time': self.modified_time.isoformat(),
            'entropy': self.entropy
        }


@dataclass
class Detection:
    """Represents a threat detection."""
    file_path: str
    threat_name: str
    detection_type: DetectionType
    risk_score: int
    description: str
    timestamp: datetime = field(default_factory=datetime.now)
    confidence: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'file_path': self.file_path,
            'threat_name': self.threat_name,
            'detection_type': self.detection_type.value,
            'risk_score': self.risk_score,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'confidence': self.confidence
        }


@dataclass
class BehavioralResult:
    """Results from behavioral analysis."""
    file_path: str
    risk_score: int
    entropy_score: float
    suspicious_patterns: List[str]
    file_characteristics: Dict[str, Any]
    analysis_details: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'file_path': self.file_path,
            'risk_score': self.risk_score,
            'entropy_score': self.entropy_score,
            'suspicious_patterns': self.suspicious_patterns,
            'file_characteristics': self.file_characteristics,
            'analysis_details': self.analysis_details
        }


@dataclass
class ScanResult:
    """Results from a file or directory scan."""
    scan_id: str
    start_time: datetime
    end_time: Optional[datetime]
    status: ScanStatus
    files_scanned: int
    threats_found: int
    detections: List[Detection]
    errors: List[str]
    scan_path: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'scan_id': self.scan_id,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'status': self.status.value,
            'files_scanned': self.files_scanned,
            'threats_found': self.threats_found,
            'detections': [d.to_dict() for d in self.detections],
            'errors': self.errors,
            'scan_path': self.scan_path
        }


@dataclass
class ScanOptions:
    """Options for scanning operations."""
    recursive: bool = True
    follow_symlinks: bool = False
    max_file_size_mb: int = 50
    skip_extensions: List[str] = field(default_factory=list)
    include_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)


@dataclass
class QuarantineEntry:
    """Information about a quarantined file."""
    original_path: str
    quarantine_path: str
    threat_name: str
    detection_type: DetectionType
    risk_score: int
    quarantine_time: datetime
    file_hash: str
    file_size: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'original_path': self.original_path,
            'quarantine_path': self.quarantine_path,
            'threat_name': self.threat_name,
            'detection_type': self.detection_type.value,
            'risk_score': self.risk_score,
            'quarantine_time': self.quarantine_time.isoformat(),
            'file_hash': self.file_hash,
            'file_size': self.file_size
        }


@dataclass
class SampleInfo:
    """Information about test samples."""
    name: str
    file_path: str
    sample_type: str
    description: str
    threat_level: int
    created_time: datetime
    file_hash: str
    file_size: int
    educational_notes: str = ""
    sample_id: str = ""
    signatures: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'name': self.name,
            'file_path': self.file_path,
            'sample_type': self.sample_type,
            'description': self.description,
            'threat_level': self.threat_level,
            'created_time': self.created_time.isoformat(),
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'educational_notes': self.educational_notes,
            'sample_id': self.sample_id,
            'signatures': self.signatures
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SampleInfo':
        """Create SampleInfo from dictionary."""
        # Handle datetime conversion
        if isinstance(data.get('created_time'), str):
            data['created_time'] = datetime.fromisoformat(data['created_time'])
        elif 'creation_date' in data:
            # Handle legacy field name
            if isinstance(data['creation_date'], str):
                data['created_time'] = datetime.fromisoformat(data['creation_date'])
            else:
                data['created_time'] = data['creation_date']
            del data['creation_date']
        
        # Set defaults for missing fields
        data.setdefault('educational_notes', '')
        data.setdefault('sample_id', '')
        data.setdefault('signatures', [])
        data.setdefault('threat_level', 1)
        data.setdefault('file_hash', '')
        data.setdefault('file_size', 0)
        
        return cls(**data)


@dataclass
class AnalysisDetails:
    """Detailed analysis information for educational purposes."""
    file_path: str
    analysis_type: str
    findings: Dict[str, Any]
    educational_content: Dict[str, str]
    recommendations: List[str]
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'file_path': self.file_path,
            'analysis_type': self.analysis_type,
            'findings': self.findings,
            'educational_content': self.educational_content,
            'recommendations': self.recommendations,
            'timestamp': self.timestamp.isoformat()
        }