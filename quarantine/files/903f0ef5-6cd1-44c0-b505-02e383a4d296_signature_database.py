"""
Signature database management for the Educational Antivirus Research Tool.
"""
import json
import os
import sqlite3
from datetime import datetime
from typing import List, Dict, Optional, Iterator
from pathlib import Path

from core.exceptions import SignatureError, DatabaseError
from core.logging_config import get_logger
from .signature_models import Signature, SignatureDatabase, SignatureType

logger = get_logger(__name__)


class SignatureDatabaseManager:
    """Manages signature database operations including storage, loading, and querying."""
    
    def __init__(self, db_path: str):
        """Initialize the signature database manager.
        
        Args:
            db_path: Path to the signature database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection: Optional[sqlite3.Connection] = None
        self._initialize_database()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection, creating if necessary."""
        if self._connection is None:
            self._connection = sqlite3.connect(str(self.db_path))
            self._connection.row_factory = sqlite3.Row
        return self._connection
    
    def _initialize_database(self) -> None:
        """Initialize the database schema."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Create signatures table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS signatures (
                    signature_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    signature_type TEXT NOT NULL,
                    pattern BLOB NOT NULL,
                    description TEXT NOT NULL,
                    threat_category TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    created_date TEXT NOT NULL,
                    updated_date TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    metadata TEXT DEFAULT '{}'
                )
            """)
            
            # Create database metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS database_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            
            # Initialize metadata if not exists
            cursor.execute("SELECT COUNT(*) FROM database_metadata WHERE key = 'version'")
            if cursor.fetchone()[0] == 0:
                metadata = SignatureDatabase(
                    version="1.0.0",
                    created_date=datetime.now(),
                    updated_date=datetime.now(),
                    signature_count=0
                )
                self._update_metadata(metadata)
            
            conn.commit()
            logger.info(f"Signature database initialized at {self.db_path}")
            
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to initialize signature database: {e}")
    
    def _update_metadata(self, metadata: SignatureDatabase) -> None:
        """Update database metadata."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        metadata_dict = metadata.to_dict()
        for key, value in metadata_dict.items():
            cursor.execute(
                "INSERT OR REPLACE INTO database_metadata (key, value) VALUES (?, ?)",
                (key, json.dumps(value) if not isinstance(value, str) else value)
            )
        conn.commit()
    
    def get_metadata(self) -> SignatureDatabase:
        """Get database metadata."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT key, value FROM database_metadata")
            metadata_dict = {}
            for row in cursor.fetchall():
                key, value = row
                try:
                    metadata_dict[key] = json.loads(value)
                except json.JSONDecodeError:
                    metadata_dict[key] = value
            
            return SignatureDatabase.from_dict(metadata_dict)
            
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to get database metadata: {e}")
    
    def add_signature(self, signature: Signature) -> bool:
        """Add a new signature to the database.
        
        Args:
            signature: Signature object to add
            
        Returns:
            True if signature was added successfully
            
        Raises:
            SignatureError: If signature already exists or invalid
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Check if signature already exists
            cursor.execute("SELECT signature_id FROM signatures WHERE signature_id = ?", 
                         (signature.signature_id,))
            if cursor.fetchone():
                raise SignatureError(f"Signature with ID '{signature.signature_id}' already exists")
            
            # Insert signature
            cursor.execute("""
                INSERT INTO signatures (
                    signature_id, name, signature_type, pattern, description,
                    threat_category, severity, created_date, updated_date, enabled, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                signature.signature_id,
                signature.name,
                signature.signature_type.value,
                signature.pattern,
                signature.description,
                signature.threat_category,
                signature.severity,
                signature.created_date.isoformat(),
                signature.updated_date.isoformat(),
                1 if signature.enabled else 0,
                json.dumps(signature.metadata)
            ))
            
            conn.commit()
            
            # Update metadata
            metadata = self.get_metadata()
            metadata.signature_count += 1
            metadata.updated_date = datetime.now()
            self._update_metadata(metadata)
            
            logger.info(f"Added signature: {signature.signature_id}")
            return True
            
        except sqlite3.Error as e:
            raise SignatureError(f"Failed to add signature: {e}")
    
    def get_signature(self, signature_id: str) -> Optional[Signature]:
        """Get a signature by ID.
        
        Args:
            signature_id: ID of the signature to retrieve
            
        Returns:
            Signature object if found, None otherwise
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM signatures WHERE signature_id = ?", (signature_id,))
            row = cursor.fetchone()
            
            if row:
                return self._row_to_signature(row)
            return None
            
        except sqlite3.Error as e:
            raise SignatureError(f"Failed to get signature: {e}")
    
    def get_all_signatures(self, enabled_only: bool = True) -> List[Signature]:
        """Get all signatures from the database.
        
        Args:
            enabled_only: If True, only return enabled signatures
            
        Returns:
            List of Signature objects
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            if enabled_only:
                cursor.execute("SELECT * FROM signatures WHERE enabled = 1 ORDER BY name")
            else:
                cursor.execute("SELECT * FROM signatures ORDER BY name")
            
            signatures = []
            for row in cursor.fetchall():
                signatures.append(self._row_to_signature(row))
            
            return signatures
            
        except sqlite3.Error as e:
            raise SignatureError(f"Failed to get signatures: {e}")
    
    def get_signatures_by_type(self, signature_type: SignatureType, enabled_only: bool = True) -> List[Signature]:
        """Get signatures by type.
        
        Args:
            signature_type: Type of signatures to retrieve
            enabled_only: If True, only return enabled signatures
            
        Returns:
            List of Signature objects
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            if enabled_only:
                cursor.execute(
                    "SELECT * FROM signatures WHERE signature_type = ? AND enabled = 1 ORDER BY name",
                    (signature_type.value,)
                )
            else:
                cursor.execute(
                    "SELECT * FROM signatures WHERE signature_type = ? ORDER BY name",
                    (signature_type.value,)
                )
            
            signatures = []
            for row in cursor.fetchall():
                signatures.append(self._row_to_signature(row))
            
            return signatures
            
        except sqlite3.Error as e:
            raise SignatureError(f"Failed to get signatures by type: {e}")
    
    def update_signature(self, signature: Signature) -> bool:
        """Update an existing signature.
        
        Args:
            signature: Updated signature object
            
        Returns:
            True if signature was updated successfully
            
        Raises:
            SignatureError: If signature doesn't exist
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Check if signature exists
            cursor.execute("SELECT signature_id FROM signatures WHERE signature_id = ?", 
                         (signature.signature_id,))
            if not cursor.fetchone():
                raise SignatureError(f"Signature with ID '{signature.signature_id}' not found")
            
            # Update signature
            signature.updated_date = datetime.now()
            cursor.execute("""
                UPDATE signatures SET
                    name = ?, signature_type = ?, pattern = ?, description = ?,
                    threat_category = ?, severity = ?, updated_date = ?, enabled = ?, metadata = ?
                WHERE signature_id = ?
            """, (
                signature.name,
                signature.signature_type.value,
                signature.pattern,
                signature.description,
                signature.threat_category,
                signature.severity,
                signature.updated_date.isoformat(),
                1 if signature.enabled else 0,
                json.dumps(signature.metadata),
                signature.signature_id
            ))
            
            conn.commit()
            
            # Update metadata
            metadata = self.get_metadata()
            metadata.updated_date = datetime.now()
            self._update_metadata(metadata)
            
            logger.info(f"Updated signature: {signature.signature_id}")
            return True
            
        except sqlite3.Error as e:
            raise SignatureError(f"Failed to update signature: {e}")
    
    def delete_signature(self, signature_id: str) -> bool:
        """Delete a signature from the database.
        
        Args:
            signature_id: ID of the signature to delete
            
        Returns:
            True if signature was deleted successfully
            
        Raises:
            SignatureError: If signature doesn't exist
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Check if signature exists
            cursor.execute("SELECT signature_id FROM signatures WHERE signature_id = ?", 
                         (signature_id,))
            if not cursor.fetchone():
                raise SignatureError(f"Signature with ID '{signature_id}' not found")
            
            # Delete signature
            cursor.execute("DELETE FROM signatures WHERE signature_id = ?", (signature_id,))
            conn.commit()
            
            # Update metadata
            metadata = self.get_metadata()
            metadata.signature_count -= 1
            metadata.updated_date = datetime.now()
            self._update_metadata(metadata)
            
            logger.info(f"Deleted signature: {signature_id}")
            return True
            
        except sqlite3.Error as e:
            raise SignatureError(f"Failed to delete signature: {e}")
    
    def search_signatures(self, query: str, field: str = "name") -> List[Signature]:
        """Search signatures by field.
        
        Args:
            query: Search query
            field: Field to search in (name, description, threat_category)
            
        Returns:
            List of matching Signature objects
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            valid_fields = ["name", "description", "threat_category"]
            if field not in valid_fields:
                raise SignatureError(f"Invalid search field: {field}")
            
            cursor.execute(
                f"SELECT * FROM signatures WHERE {field} LIKE ? AND enabled = 1 ORDER BY name",
                (f"%{query}%",)
            )
            
            signatures = []
            for row in cursor.fetchall():
                signatures.append(self._row_to_signature(row))
            
            return signatures
            
        except sqlite3.Error as e:
            raise SignatureError(f"Failed to search signatures: {e}")
    
    def _row_to_signature(self, row: sqlite3.Row) -> Signature:
        """Convert database row to Signature object."""
        return Signature(
            signature_id=row['signature_id'],
            name=row['name'],
            signature_type=SignatureType(row['signature_type']),
            pattern=row['pattern'],
            description=row['description'],
            threat_category=row['threat_category'],
            severity=row['severity'],
            created_date=datetime.fromisoformat(row['created_date']),
            updated_date=datetime.fromisoformat(row['updated_date']),
            enabled=bool(row['enabled']),
            metadata=json.loads(row['metadata'])
        )
    
    def close(self) -> None:
        """Close database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()