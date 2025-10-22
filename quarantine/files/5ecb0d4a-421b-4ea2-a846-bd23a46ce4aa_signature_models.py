"""
Signature database models for the Educational Antivirus Research Tool.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum
import json


class SignatureType(Enum):
    """Types of signatures."""
    EXACT_MATCH = "exact_match"
    PATTERN_MATCH = "pattern_match"
    HASH_MATCH = "hash_match"
    EICAR = "eicar"


@dataclass
class Signature:
    """Represents a malware signature for detection."""
    signature_id: str
    name: str
    signature_type: SignatureType
    pattern: bytes
    description: str
    threat_category: str
    severity: int  # 1-10 scale
    created_date: datetime = field(default_factory=datetime.now)
    updated_date: datetime = field(default_factory=datetime.now)
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert Signature to dictionary for JSON serialization."""
        data = asdict(self)
        data['signature_type'] = self.signature_type.value
        data['pattern'] = self.pattern.hex()  # Convert bytes to hex string
        data['created_date'] = self.created_date.isoformat()
        data['updated_date'] = self.updated_date.isoformat()
        return data
    
    def to_json(self) -> str:
        """Convert Signature to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Signature':
        """Create Signature from dictionary."""
        data = data.copy()
        data['signature_type'] = SignatureType(data['signature_type'])
        data['pattern'] = bytes.fromhex(data['pattern'])  # Convert hex string back to bytes
        data['created_date'] = datetime.fromisoformat(data['created_date'])
        data['updated_date'] = datetime.fromisoformat(data['updated_date'])
        return cls(**data)


@dataclass
class SignatureMatch:
    """Represents a signature match result."""
    signature: Signature
    file_path: str
    match_offset: int
    match_length: int
    confidence: float  # 0.0 to 1.0
    context: bytes = b""  # Surrounding bytes for context
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert SignatureMatch to dictionary."""
        return {
            'signature_id': self.signature.signature_id,
            'signature_name': self.signature.name,
            'file_path': self.file_path,
            'match_offset': self.match_offset,
            'match_length': self.match_length,
            'confidence': self.confidence,
            'context': self.context.hex() if self.context else ""
        }


@dataclass
class SignatureDatabase:
    """Container for signature database metadata."""
    version: str
    created_date: datetime
    updated_date: datetime
    signature_count: int
    description: str = "Educational Antivirus Signature Database"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert SignatureDatabase to dictionary."""
        return {
            'version': self.version,
            'created_date': self.created_date.isoformat(),
            'updated_date': self.updated_date.isoformat(),
            'signature_count': self.signature_count,
            'description': self.description
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SignatureDatabase':
        """Create SignatureDatabase from dictionary."""
        data = data.copy()
        data['created_date'] = datetime.fromisoformat(data['created_date'])
        data['updated_date'] = datetime.fromisoformat(data['updated_date'])
        return cls(**data)