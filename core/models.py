"""
Core data models for the Educational Antivirus Research Tool.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum
import json


class DetectionType(Enum):
    """Types of detection methods."""
    SIGNATURE = "signature"
    BEHAVIORAL = "behavioral"


class ScanStatus(Enum):
    """Status of scan operations."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Detection:
    """Represents a threat detection result."""
    file_path: str
    detection_type: DetectionType
    threat_name: str
    risk_score: int
    signature_id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert Detection to dictionary for JSON serialization."""
        data = asdict(self)
        data['detection_type'] = self.detection_type.value
        data['timestamp'] = self.timestamp.isoformat()
        return data
    
    def to_json(self) -> str:
        """Convert Detection to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Detection':
        """Create Detection from dictionary."""
        data = data.copy()
        data['detection_type'] = DetectionType(data['detection_type'])
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)


@dataclass
class ScanOptions:
    """Configuration options for scanning operations."""
    recursive: bool = True
    follow_symlinks: bool = False
    max_file_size_mb: int = 100
    signature_sensitivity: int = 5
    behavioral_threshold: int = 7
    skip_extensions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert ScanOptions to dictionary for JSON serialization."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert ScanOptions to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanOptions':
        """Create ScanOptions from dictionary."""
        return cls(**data)


@dataclass
class ScanResult:
    """Complete result of a scanning operation."""
    scan_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    scanned_paths: List[str] = field(default_factory=list)
    total_files: int = 0
    detections: List[Detection] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scan_options: Optional[ScanOptions] = None
    status: ScanStatus = ScanStatus.PENDING
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert ScanResult to dictionary for JSON serialization."""
        data = asdict(self)
        data['start_time'] = self.start_time.isoformat()
        data['end_time'] = self.end_time.isoformat() if self.end_time else None
        data['detections'] = [detection.to_dict() for detection in self.detections]
        data['status'] = self.status.value
        if self.scan_options:
            data['scan_options'] = self.scan_options.to_dict()
        return data
    
    def to_json(self) -> str:
        """Convert ScanResult to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanResult':
        """Create ScanResult from dictionary."""
        data = data.copy()
        data['start_time'] = datetime.fromisoformat(data['start_time'])
        data['end_time'] = datetime.fromisoformat(data['end_time']) if data['end_time'] else None
        data['detections'] = [Detection.from_dict(d) for d in data.get('detections', [])]
        data['status'] = ScanStatus(data['status'])
        if data.get('scan_options'):
            data['scan_options'] = ScanOptions.from_dict(data['scan_options'])
        return cls(**data)


@dataclass
class FileInfo:
    """Detailed information about a file."""
    path: str
    size: int
    file_type: str
    entropy: float
    creation_time: datetime
    modification_time: datetime
    permissions: str
    hash_md5: str
    hash_sha256: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert FileInfo to dictionary for JSON serialization."""
        data = asdict(self)
        data['creation_time'] = self.creation_time.isoformat()
        data['modification_time'] = self.modification_time.isoformat()
        return data
    
    def to_json(self) -> str:
        """Convert FileInfo to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FileInfo':
        """Create FileInfo from dictionary."""
        data = data.copy()
        data['creation_time'] = datetime.fromisoformat(data['creation_time'])
        data['modification_time'] = datetime.fromisoformat(data['modification_time'])
        return cls(**data)

@dataclass
class SampleInfo:
    """Information about a test malware sample."""
    sample_id: str
    name: str
    sample_type: str
    description: str
    creation_date: datetime
    file_path: str
    signatures: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert SampleInfo to dictionary for JSON serialization."""
        data = asdict(self)
        data['creation_date'] = self.creation_date.isoformat()
        return data
    
    def to_json(self) -> str:
        """Convert SampleInfo to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SampleInfo':
        """Create SampleInfo from dictionary."""
        data = data.copy()
        data['creation_date'] = datetime.fromisoformat(data['creation_date'])
        return cls(**data)


@dataclass
class QuarantineEntry:
    """Information about a quarantined file."""
    quarantine_id: str
    original_path: str
    quarantine_path: str
    detection_info: Detection
    quarantine_date: datetime
    restored: bool = False


@dataclass
class BehavioralResult:
    """Result of behavioral analysis."""
    file_path: str
    risk_score: int
    entropy: float
    suspicious_patterns: List[str] = field(default_factory=list)
    analysis_details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisDetails:
    """Detailed analysis information for educational purposes."""
    detection_method: str
    explanation: str
    threat_category: str
    educational_info: str
    mitigation_advice: str


@dataclass
class Config:
    """Main configuration class for the Educational Antivirus Research Tool."""
    # Detection Settings
    signature_sensitivity: int = 5  # 1-10 scale
    behavioral_threshold: int = 7   # Risk score threshold
    max_file_size_mb: int = 100    # Skip files larger than this
    
    # Paths
    signature_db_path: str = "data/signatures.db"
    quarantine_path: str = "quarantine/"
    samples_path: str = "samples/"
    reports_path: str = "reports/"
    
    # Behavioral Analysis
    entropy_threshold: float = 7.5
    suspicious_extensions: List[str] = field(default_factory=lambda: [".exe", ".scr", ".bat", ".cmd"])
    
    # Logging
    log_level: str = "INFO"
    log_file: str = "antivirus.log"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Scanning Options
    recursive_scan: bool = True
    follow_symlinks: bool = False
    skip_extensions: List[str] = field(default_factory=lambda: [".tmp", ".log"])
    
    def validate(self) -> List[str]:
        """Validate configuration values and return list of errors."""
        errors = []
        
        # Validate sensitivity range
        if not 1 <= self.signature_sensitivity <= 10:
            errors.append("signature_sensitivity must be between 1 and 10")
        
        # Validate behavioral threshold
        if not 1 <= self.behavioral_threshold <= 10:
            errors.append("behavioral_threshold must be between 1 and 10")
        
        # Validate max file size
        if self.max_file_size_mb <= 0:
            errors.append("max_file_size_mb must be positive")
        
        # Validate entropy threshold
        if not 0 <= self.entropy_threshold <= 8:
            errors.append("entropy_threshold must be between 0 and 8")
        
        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level.upper() not in valid_log_levels:
            errors.append(f"log_level must be one of: {', '.join(valid_log_levels)}")
        
        # Validate paths are not empty
        if not self.signature_db_path.strip():
            errors.append("signature_db_path cannot be empty")
        if not self.quarantine_path.strip():
            errors.append("quarantine_path cannot be empty")
        if not self.samples_path.strip():
            errors.append("samples_path cannot be empty")
        if not self.reports_path.strip():
            errors.append("reports_path cannot be empty")
        if not self.log_file.strip():
            errors.append("log_file cannot be empty")
        
        return errors
    
    def is_valid(self) -> bool:
        """Check if configuration is valid."""
        return len(self.validate()) == 0