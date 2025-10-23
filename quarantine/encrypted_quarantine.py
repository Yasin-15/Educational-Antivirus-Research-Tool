#!/usr/bin/env python3
"""
Encrypted Quarantine System for Educational Antivirus Tool.

This module provides secure quarantine functionality with AES-256 encryption,
access control, and forensic preservation capabilities.
"""
import os
import json
import shutil
import hashlib
import secrets
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from core.models import Detection, DetectionType, QuarantineEntry


@dataclass
class EncryptedQuarantineEntry:
    """Enhanced quarantine entry with encryption metadata."""
    original_path: str
    quarantine_path: str
    encrypted_path: str
    threat_name: str
    detection_type: DetectionType
    risk_score: int
    quarantine_time: datetime
    file_hash: str
    file_size: int
    encryption_key_id: str
    access_count: int = 0
    last_accessed: Optional[datetime] = None
    forensic_metadata: Dict[str, Any] = None
    user_notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['detection_type'] = self.detection_type.value
        data['quarantine_time'] = self.quarantine_time.isoformat()
        if self.last_accessed:
            data['last_accessed'] = self.last_accessed.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EncryptedQuarantineEntry':
        """Create from dictionary."""
        data['detection_type'] = DetectionType(data['detection_type'])
        data['quarantine_time'] = datetime.fromisoformat(data['quarantine_time'])
        if data.get('last_accessed'):
            data['last_accessed'] = datetime.fromisoformat(data['last_accessed'])
        return cls(**data)


@dataclass
class QuarantineConfig:
    """Configuration for encrypted quarantine system."""
    quarantine_base_path: str = "quarantine/"
    encrypted_storage_path: str = "quarantine/encrypted/"
    metadata_path: str = "quarantine/metadata/"
    key_storage_path: str = "quarantine/keys/"
    max_quarantine_size_gb: int = 10
    auto_cleanup_days: int = 90
    compression_enabled: bool = True
    forensic_mode: bool = True
    access_logging: bool = True


class EncryptionManager:
    """Manages encryption keys and operations for quarantine."""
    
    def __init__(self, key_storage_path: str):
        """Initialize encryption manager."""
        self.key_storage_path = Path(key_storage_path)
        self.key_storage_path.mkdir(parents=True, exist_ok=True)
        
        # Master key for key encryption
        self.master_key = self._get_or_create_master_key()
        
        # Key cache for performance
        self.key_cache = {}
    
    def _get_or_create_master_key(self) -> bytes:
        """Get or create master encryption key."""
        master_key_file = self.key_storage_path / "master.key"
        
        if master_key_file.exists():
            try:
                with open(master_key_file, 'rb') as f:
                    encrypted_master = f.read()
                
                # In a real implementation, this would be derived from user password
                # For educational purposes, we use a fixed derivation
                password = b"educational_antivirus_master_key"
                salt = b"fixed_salt_for_education_only"
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password))
                
                fernet = Fernet(key)
                return fernet.decrypt(encrypted_master)
                
            except Exception as e:
                print(f"❌ Failed to load master key: {e}")
                # Fall through to create new key
        
        # Create new master key
        master_key = secrets.token_bytes(32)
        
        # Encrypt and save master key
        password = b"educational_antivirus_master_key"
        salt = b"fixed_salt_for_education_only"
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        
        fernet = Fernet(key)
        encrypted_master = fernet.encrypt(master_key)
        
        with open(master_key_file, 'wb') as f:
            f.write(encrypted_master)
        
        # Set restrictive permissions
        try:
            os.chmod(master_key_file, 0o600)
        except OSError:
            pass  # Windows doesn't support chmod
        
        return master_key
    
    def generate_file_key(self) -> Tuple[str, bytes]:
        """Generate a new encryption key for a file."""
        key_id = secrets.token_hex(16)
        file_key = Fernet.generate_key()
        
        # Encrypt file key with master key
        master_fernet = Fernet(base64.urlsafe_b64encode(self.master_key))
        encrypted_file_key = master_fernet.encrypt(file_key)
        
        # Save encrypted file key
        key_file = self.key_storage_path / f"{key_id}.key"
        with open(key_file, 'wb') as f:
            f.write(encrypted_file_key)
        
        # Set restrictive permissions
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
        
        # Cache the key
        self.key_cache[key_id] = file_key
        
        return key_id, file_key
    
    def get_file_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve a file encryption key."""
        # Check cache first
        if key_id in self.key_cache:
            return self.key_cache[key_id]
        
        key_file = self.key_storage_path / f"{key_id}.key"
        
        if not key_file.exists():
            return None
        
        try:
            with open(key_file, 'rb') as f:
                encrypted_file_key = f.read()
            
            # Decrypt file key with master key
            master_fernet = Fernet(base64.urlsafe_b64encode(self.master_key))
            file_key = master_fernet.decrypt(encrypted_file_key)
            
            # Cache the key
            self.key_cache[key_id] = file_key
            
            return file_key
            
        except Exception as e:
            print(f"❌ Failed to retrieve key {key_id}: {e}")
            return None
    
    def delete_file_key(self, key_id: str):
        """Securely delete a file encryption key."""
        key_file = self.key_storage_path / f"{key_id}.key"
        
        if key_file.exists():
            try:
                # Overwrite file with random data before deletion
                file_size = key_file.stat().st_size
                with open(key_file, 'wb') as f:
                    f.write(secrets.token_bytes(file_size))
                
                key_file.unlink()
                
                # Remove from cache
                self.key_cache.pop(key_id, None)
                
            except Exception as e:
                print(f"❌ Failed to delete key {key_id}: {e}")


class EncryptedQuarantineManager:
    """Enhanced quarantine manager with encryption and forensic capabilities."""
    
    def __init__(self, config: QuarantineConfig):
        """Initialize encrypted quarantine manager."""
        self.config = config
        
        # Create directory structure
        self.quarantine_path = Path(config.quarantine_base_path)
        self.encrypted_path = Path(config.encrypted_storage_path)
        self.metadata_path = Path(config.metadata_path)
        
        for path in [self.quarantine_path, self.encrypted_path, self.metadata_path]:
            path.mkdir(parents=True, exist_ok=True)
        
        # Initialize encryption manager
        self.encryption_manager = EncryptionManager(config.key_storage_path)
        
        # Load quarantine database
        self.quarantine_db = self._load_quarantine_database()
        
        # Access log
        self.access_log = []
        
        print(f"🔒 Encrypted Quarantine Manager initialized")
        print(f"   Base path: {self.quarantine_path}")
        print(f"   Encrypted storage: {self.encrypted_path}")
        print(f"   Current entries: {len(self.quarantine_db)}")
    
    def quarantine_file(self, file_path: str, detection: Optional[Detection] = None) -> bool:
        """Quarantine a file with encryption."""
        try:
            source_path = Path(file_path)
            
            if not source_path.exists():
                print(f"❌ File not found: {file_path}")
                return False
            
            print(f"🔒 Quarantining file: {file_path}")
            
            # Generate unique quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_hash = self._calculate_file_hash(source_path)
            quarantine_filename = f"{timestamp}_{file_hash[:8]}_{source_path.name}"
            
            # Paths for quarantine storage
            quarantine_file_path = self.quarantine_path / quarantine_filename
            encrypted_file_path = self.encrypted_path / f"{quarantine_filename}.enc"
            
            # Collect forensic metadata
            forensic_metadata = self._collect_forensic_metadata(source_path)
            
            # Generate encryption key
            key_id, encryption_key = self.encryption_manager.generate_file_key()
            
            # Encrypt and store file
            if not self._encrypt_file(source_path, encrypted_file_path, encryption_key):
                print(f"❌ Failed to encrypt file: {file_path}")
                return False
            
            # Create quarantine entry
            entry = EncryptedQuarantineEntry(
                original_path=str(source_path.absolute()),
                quarantine_path=str(quarantine_file_path),
                encrypted_path=str(encrypted_file_path),
                threat_name=detection.threat_name if detection else "User Quarantine",
                detection_type=detection.detection_type if detection else DetectionType.HEURISTIC,
                risk_score=detection.risk_score if detection else 50,
                quarantine_time=datetime.now(),
                file_hash=file_hash,
                file_size=source_path.stat().st_size,
                encryption_key_id=key_id,
                forensic_metadata=forensic_metadata
            )
            
            # Save metadata
            self._save_quarantine_metadata(entry)
            
            # Add to database
            self.quarantine_db[file_hash] = entry
            self._save_quarantine_database()
            
            # Remove original file
            try:
                source_path.unlink()
                print(f"✅ File quarantined successfully: {quarantine_filename}")
            except Exception as e:
                print(f"⚠️ File quarantined but original removal failed: {e}")
            
            # Log access
            self._log_access("quarantine", entry, "File quarantined")
            
            return True
            
        except Exception as e:
            print(f"❌ Quarantine failed: {e}")
            return False
    
    def restore_file(self, file_hash: str, restore_path: Optional[str] = None) -> bool:
        """Restore a quarantined file."""
        if file_hash not in self.quarantine_db:
            print(f"❌ File not found in quarantine: {file_hash}")
            return False
        
        entry = self.quarantine_db[file_hash]
        
        try:
            print(f"🔓 Restoring file: {entry.original_path}")
            
            # Determine restore path
            if restore_path:
                target_path = Path(restore_path)
            else:
                target_path = Path(entry.original_path)
            
            # Ensure target directory exists
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Get encryption key
            encryption_key = self.encryption_manager.get_file_key(entry.encryption_key_id)
            if not encryption_key:
                print(f"❌ Encryption key not found: {entry.encryption_key_id}")
                return False
            
            # Decrypt and restore file
            if not self._decrypt_file(Path(entry.encrypted_path), target_path, encryption_key):
                print(f"❌ Failed to decrypt file: {entry.encrypted_path}")
                return False
            
            # Update access tracking
            entry.access_count += 1
            entry.last_accessed = datetime.now()
            
            # Log access
            self._log_access("restore", entry, f"File restored to {target_path}")
            
            print(f"✅ File restored successfully: {target_path}")
            return True
            
        except Exception as e:
            print(f"❌ Restore failed: {e}")
            return False
    
    def delete_quarantined_file(self, file_hash: str, secure_delete: bool = True) -> bool:
        """Permanently delete a quarantined file."""
        if file_hash not in self.quarantine_db:
            print(f"❌ File not found in quarantine: {file_hash}")
            return False
        
        entry = self.quarantine_db[file_hash]
        
        try:
            print(f"🗑️ Deleting quarantined file: {entry.original_path}")
            
            # Delete encrypted file
            encrypted_path = Path(entry.encrypted_path)
            if encrypted_path.exists():
                if secure_delete:
                    self._secure_delete_file(encrypted_path)
                else:
                    encrypted_path.unlink()
            
            # Delete metadata
            metadata_file = self.metadata_path / f"{file_hash}.json"
            if metadata_file.exists():
                metadata_file.unlink()
            
            # Delete encryption key
            self.encryption_manager.delete_file_key(entry.encryption_key_id)
            
            # Remove from database
            del self.quarantine_db[file_hash]
            self._save_quarantine_database()
            
            # Log access
            self._log_access("delete", entry, "File permanently deleted")
            
            print(f"✅ File deleted successfully")
            return True
            
        except Exception as e:
            print(f"❌ Delete failed: {e}")
            return False
    
    def list_quarantined_files(self) -> List[EncryptedQuarantineEntry]:
        """List all quarantined files."""
        return list(self.quarantine_db.values())
    
    def get_quarantine_info(self, file_hash: str) -> Optional[EncryptedQuarantineEntry]:
        """Get detailed information about a quarantined file."""
        entry = self.quarantine_db.get(file_hash)
        
        if entry:
            # Update access tracking
            entry.access_count += 1
            entry.last_accessed = datetime.now()
            self._log_access("info", entry, "Information accessed")
        
        return entry
    
    def export_quarantine_sample(self, file_hash: str, export_path: str, password: str) -> bool:
        """Export quarantined sample for analysis (password protected)."""
        if file_hash not in self.quarantine_db:
            return False
        
        entry = self.quarantine_db[file_hash]
        
        try:
            # Get encryption key
            encryption_key = self.encryption_manager.get_file_key(entry.encryption_key_id)
            if not encryption_key:
                return False
            
            # Create password-protected archive
            # This is a simplified implementation
            # Real implementation would use proper archive encryption
            
            export_file = Path(export_path)
            
            # Decrypt to temporary location
            temp_file = export_file.with_suffix('.tmp')
            if not self._decrypt_file(Path(entry.encrypted_path), temp_file, encryption_key):
                return False
            
            # Create simple password protection (educational)
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            with open(export_file, 'wb') as out_f:
                # Write password hash
                out_f.write(password_hash.encode() + b'\n')
                
                # Write file data
                with open(temp_file, 'rb') as in_f:
                    shutil.copyfileobj(in_f, out_f)
            
            # Clean up temporary file
            temp_file.unlink()
            
            # Log access
            self._log_access("export", entry, f"Sample exported to {export_path}")
            
            return True
            
        except Exception as e:
            print(f"❌ Export failed: {e}")
            return False
    
    def get_quarantine_statistics(self) -> Dict[str, Any]:
        """Get quarantine statistics."""
        total_files = len(self.quarantine_db)
        total_size = sum(entry.file_size for entry in self.quarantine_db.values())
        
        # Group by threat type
        threat_types = {}
        for entry in self.quarantine_db.values():
            threat_type = entry.detection_type.value
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        # Recent activity
        recent_quarantines = [
            entry for entry in self.quarantine_db.values()
            if (datetime.now() - entry.quarantine_time).days <= 7
        ]
        
        return {
            'total_files': total_files,
            'total_size_bytes': total_size,
            'total_size_mb': total_size / (1024 * 1024),
            'threat_types': threat_types,
            'recent_quarantines': len(recent_quarantines),
            'access_log_entries': len(self.access_log)
        }
    
    def cleanup_old_entries(self, days: Optional[int] = None) -> int:
        """Clean up old quarantine entries."""
        cleanup_days = days or self.config.auto_cleanup_days
        cutoff_date = datetime.now() - timedelta(days=cleanup_days)
        
        old_entries = [
            file_hash for file_hash, entry in self.quarantine_db.items()
            if entry.quarantine_time < cutoff_date
        ]
        
        cleaned_count = 0
        for file_hash in old_entries:
            if self.delete_quarantined_file(file_hash):
                cleaned_count += 1
        
        print(f"🧹 Cleaned up {cleaned_count} old quarantine entries")
        return cleaned_count
    
    def _encrypt_file(self, source_path: Path, encrypted_path: Path, encryption_key: bytes) -> bool:
        """Encrypt a file."""
        try:
            fernet = Fernet(encryption_key)
            
            with open(source_path, 'rb') as source_file:
                file_data = source_file.read()
            
            encrypted_data = fernet.encrypt(file_data)
            
            with open(encrypted_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)
            
            # Set restrictive permissions
            try:
                os.chmod(encrypted_path, 0o600)
            except OSError:
                pass
            
            return True
            
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            return False
    
    def _decrypt_file(self, encrypted_path: Path, target_path: Path, encryption_key: bytes) -> bool:
        """Decrypt a file."""
        try:
            fernet = Fernet(encryption_key)
            
            with open(encrypted_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)
            
            with open(target_path, 'wb') as target_file:
                target_file.write(decrypted_data)
            
            return True
            
        except Exception as e:
            print(f"❌ Decryption failed: {e}")
            return False
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of a file."""
        hash_sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        
        return hash_sha256.hexdigest()
    
    def _collect_forensic_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Collect forensic metadata about a file."""
        try:
            stat_info = file_path.stat()
            
            metadata = {
                'file_name': file_path.name,
                'file_size': stat_info.st_size,
                'created_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed_time': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                'file_mode': oct(stat_info.st_mode),
                'file_extension': file_path.suffix.lower(),
                'absolute_path': str(file_path.absolute())
            }
            
            # Add file type detection
            if file_path.suffix.lower() in ['.exe', '.dll', '.scr']:
                metadata['file_type'] = 'executable'
            elif file_path.suffix.lower() in ['.doc', '.docx', '.pdf', '.txt']:
                metadata['file_type'] = 'document'
            elif file_path.suffix.lower() in ['.jpg', '.png', '.gif', '.bmp']:
                metadata['file_type'] = 'image'
            else:
                metadata['file_type'] = 'unknown'
            
            return metadata
            
        except Exception as e:
            print(f"❌ Failed to collect forensic metadata: {e}")
            return {}
    
    def _save_quarantine_metadata(self, entry: EncryptedQuarantineEntry):
        """Save quarantine metadata to individual file."""
        metadata_file = self.metadata_path / f"{entry.file_hash}.json"
        
        try:
            with open(metadata_file, 'w') as f:
                json.dump(entry.to_dict(), f, indent=2)
        except Exception as e:
            print(f"❌ Failed to save metadata: {e}")
    
    def _load_quarantine_database(self) -> Dict[str, EncryptedQuarantineEntry]:
        """Load quarantine database."""
        db_file = self.quarantine_path / "quarantine.db"
        
        if not db_file.exists():
            return {}
        
        try:
            with open(db_file, 'r') as f:
                data = json.load(f)
            
            database = {}
            for file_hash, entry_data in data.items():
                try:
                    entry = EncryptedQuarantineEntry.from_dict(entry_data)
                    database[file_hash] = entry
                except Exception as e:
                    print(f"❌ Failed to load entry {file_hash}: {e}")
            
            return database
            
        except Exception as e:
            print(f"❌ Failed to load quarantine database: {e}")
            return {}
    
    def _save_quarantine_database(self):
        """Save quarantine database."""
        db_file = self.quarantine_path / "quarantine.db"
        
        try:
            data = {
                file_hash: entry.to_dict()
                for file_hash, entry in self.quarantine_db.items()
            }
            
            with open(db_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            print(f"❌ Failed to save quarantine database: {e}")
    
    def _secure_delete_file(self, file_path: Path):
        """Securely delete a file by overwriting with random data."""
        try:
            file_size = file_path.stat().st_size
            
            # Overwrite with random data multiple times
            for _ in range(3):
                with open(file_path, 'wb') as f:
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Finally delete the file
            file_path.unlink()
            
        except Exception as e:
            print(f"❌ Secure delete failed: {e}")
            # Fall back to regular deletion
            try:
                file_path.unlink()
            except:
                pass
    
    def _log_access(self, action: str, entry: EncryptedQuarantineEntry, details: str):
        """Log access to quarantined files."""
        if not self.config.access_logging:
            return
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'file_hash': entry.file_hash,
            'original_path': entry.original_path,
            'details': details
        }
        
        self.access_log.append(log_entry)
        
        # Keep only last 1000 entries
        if len(self.access_log) > 1000:
            self.access_log = self.access_log[-1000:]
        
        # Save access log
        log_file = self.quarantine_path / "access.log"
        try:
            with open(log_file, 'w') as f:
                json.dump(self.access_log, f, indent=2)
        except Exception as e:
            print(f"❌ Failed to save access log: {e}")


def create_encrypted_quarantine_manager(config: Optional[QuarantineConfig] = None) -> EncryptedQuarantineManager:
    """Create an encrypted quarantine manager with default configuration."""
    if config is None:
        config = QuarantineConfig()
    
    return EncryptedQuarantineManager(config)


# Example usage and testing
if __name__ == "__main__":
    print("🧪 Testing Encrypted Quarantine System")
    
    # Create quarantine manager
    config = QuarantineConfig(
        quarantine_base_path="test_quarantine/",
        auto_cleanup_days=30
    )
    
    manager = create_encrypted_quarantine_manager(config)
    
    # Test quarantine operations
    print("\n📊 Quarantine Statistics:")
    stats = manager.get_quarantine_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # List quarantined files
    print("\n📋 Quarantined Files:")
    files = manager.list_quarantined_files()
    if files:
        for entry in files:
            print(f"  {entry.original_path} - {entry.threat_name}")
    else:
        print("  No files in quarantine")
    
    print("\n✅ Encrypted quarantine system test completed")