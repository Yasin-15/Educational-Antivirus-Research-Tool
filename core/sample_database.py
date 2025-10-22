"""
Sample database management for the Educational Antivirus Research Tool.
Handles creation, validation, and management of educational test samples.
"""
import os
import json
import sqlite3
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from .models import Config, SampleInfo
from .exceptions import DatabaseError, SampleManagementError
from .threat_database import ThreatDatabase, initialize_threat_database


class SampleDatabaseManager:
    """Manages the educational sample database and test file creation."""
    
    def __init__(self, config: Config):
        """Initialize sample database manager.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.db_path = os.path.join(config.samples_path, "samples.db")
        self.samples_dir = config.samples_path
        self.threat_db = ThreatDatabase(config)
    
    def initialize_database(self, force_reset: bool = False) -> None:
        """Initialize the sample database with educational samples.
        
        Args:
            force_reset: If True, recreate the database
        """
        if os.path.exists(self.db_path) and not force_reset:
            print(f"Sample database already exists: {self.db_path}")
            return
        
        print("Creating sample database...")
        
        # Ensure directory exists
        Path(self.samples_dir).mkdir(parents=True, exist_ok=True)
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create samples table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    file_path TEXT NOT NULL,
                    sample_type TEXT NOT NULL,
                    description TEXT,
                    threat_level INTEGER DEFAULT 1,
                    file_hash TEXT,
                    file_size INTEGER,
                    created_time TEXT,
                    educational_notes TEXT,
                    detection_methods TEXT,
                    learning_objectives TEXT
                )
            ''')
            
            # Create sample metadata table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sample_metadata (
                    sample_id INTEGER,
                    metadata_key TEXT,
                    metadata_value TEXT,
                    FOREIGN KEY (sample_id) REFERENCES samples (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            
            # Initialize threat database first
            self.threat_db.initialize_database()
            
            # Create default educational samples
            self._create_default_samples()
            
            print("✓ Sample database initialized successfully")
            
        except Exception as e:
            raise DatabaseError(f"Failed to initialize sample database: {e}")
    
    def _create_default_samples(self) -> None:
        """Create default educational test samples."""
        print("Creating default educational samples...")
        
        samples_to_create = [
            {
                'name': 'EICAR Test File',
                'filename': 'eicar.com',
                'content': 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
                'sample_type': 'test_signature',
                'description': 'Standard EICAR antivirus test file',
                'threat_level': 1,
                'educational_notes': 'This is the industry-standard test file used to verify antivirus functionality. It is completely harmless but should trigger antivirus detection.',
                'detection_methods': 'Signature-based detection using known EICAR pattern',
                'learning_objectives': 'Understand how signature-based detection works with known patterns'
            },
            {
                'name': 'High Entropy Test File',
                'filename': 'high_entropy_test.bin',
                'content': self._generate_high_entropy_content(),
                'sample_type': 'behavioral_test',
                'description': 'File with artificially high entropy to trigger behavioral analysis',
                'threat_level': 3,
                'educational_notes': 'This file contains random data to simulate encrypted or packed malware, demonstrating entropy-based detection.',
                'detection_methods': 'Behavioral analysis based on file entropy calculation',
                'learning_objectives': 'Learn how entropy analysis can detect potentially obfuscated or encrypted content'
            },
            {
                'name': 'Suspicious PowerShell Script',
                'filename': 'suspicious_script.ps1',
                'content': self._generate_suspicious_powershell(),
                'sample_type': 'script_test',
                'description': 'PowerShell script with suspicious patterns',
                'threat_level': 5,
                'educational_notes': 'Contains patterns commonly found in malicious PowerShell scripts, but performs no harmful actions.',
                'detection_methods': 'Pattern matching for suspicious PowerShell commands and behavioral analysis',
                'learning_objectives': 'Understand how script-based threats are detected through content analysis'
            },
            {
                'name': 'Suspicious Batch File',
                'filename': 'suspicious_batch.bat',
                'content': self._generate_suspicious_batch(),
                'sample_type': 'script_test',
                'description': 'Batch file with potentially dangerous commands',
                'threat_level': 4,
                'educational_notes': 'Demonstrates batch file patterns that could be used maliciously, but contains only harmless echo commands.',
                'detection_methods': 'Content analysis for suspicious batch file commands',
                'learning_objectives': 'Learn to identify potentially dangerous batch file patterns'
            },
            {
                'name': 'Suspicious VBScript',
                'filename': 'suspicious_script.vbs',
                'content': self._generate_suspicious_vbscript(),
                'sample_type': 'script_test',
                'description': 'VBScript with suspicious object creation patterns',
                'threat_level': 4,
                'educational_notes': 'Contains VBScript patterns that could be used for malicious purposes, but only displays harmless messages.',
                'detection_methods': 'Pattern matching for suspicious VBScript object creation and method calls',
                'learning_objectives': 'Understand VBScript-based threat detection techniques'
            },
            {
                'name': 'Large File Test',
                'filename': 'large_file_test.bin',
                'content': self._generate_large_file_content(),
                'sample_type': 'size_test',
                'description': 'Large file to test size-based filtering',
                'threat_level': 2,
                'educational_notes': 'Tests the scanner\'s ability to handle large files and size-based filtering rules.',
                'detection_methods': 'File size analysis and scanning performance testing',
                'learning_objectives': 'Learn about file size considerations in malware scanning'
            }
        ]
        
        created_count = 0
        for sample_info in samples_to_create:
            try:
                self._create_sample_file(sample_info)
                created_count += 1
            except Exception as e:
                print(f"  Warning: Failed to create sample '{sample_info['name']}': {e}")
        
        print(f"✓ Created {created_count} educational samples")
    
    def _create_sample_file(self, sample_info: Dict) -> None:
        """Create a sample file and add it to the database.
        
        Args:
            sample_info: Dictionary with sample information
        """
        # Create file path
        file_path = os.path.join(self.samples_dir, "educational", sample_info['filename'])
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Write file content
        if isinstance(sample_info['content'], str):
            content_bytes = sample_info['content'].encode('utf-8')
        else:
            content_bytes = sample_info['content']
        
        with open(file_path, 'wb') as f:
            f.write(content_bytes)
        
        # Calculate file hash and size
        file_hash = hashlib.sha256(content_bytes).hexdigest()
        file_size = len(content_bytes)
        
        # Add to database
        self._add_sample_to_database(
            name=sample_info['name'],
            file_path=file_path,
            sample_type=sample_info['sample_type'],
            description=sample_info['description'],
            threat_level=sample_info['threat_level'],
            file_hash=file_hash,
            file_size=file_size,
            educational_notes=sample_info['educational_notes'],
            detection_methods=sample_info['detection_methods'],
            learning_objectives=sample_info['learning_objectives']
        )
    
    def _add_sample_to_database(self, **kwargs) -> int:
        """Add a sample to the database.
        
        Returns:
            Sample ID
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO samples (name, file_path, sample_type, description, threat_level,
                                   file_hash, file_size, created_time, educational_notes,
                                   detection_methods, learning_objectives)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                kwargs['name'],
                kwargs['file_path'],
                kwargs['sample_type'],
                kwargs['description'],
                kwargs['threat_level'],
                kwargs['file_hash'],
                kwargs['file_size'],
                datetime.now().isoformat(),
                kwargs['educational_notes'],
                kwargs['detection_methods'],
                kwargs['learning_objectives']
            ))
            
            sample_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return sample_id
            
        except Exception as e:
            raise DatabaseError(f"Failed to add sample to database: {e}")
    
    def _generate_high_entropy_content(self) -> bytes:
        """Generate high entropy content for testing.
        
        Returns:
            High entropy byte content
        """
        import random
        
        # Generate 1KB of random data
        random.seed(42)  # For reproducible results
        return bytes([random.randint(0, 255) for _ in range(1024)])
    
    def _generate_suspicious_powershell(self) -> str:
        """Generate suspicious PowerShell script content.
        
        Returns:
            PowerShell script content
        """
        return '''# Educational PowerShell Script - HARMLESS
# This script contains patterns that might be flagged as suspicious
# but performs no harmful actions

# Suspicious pattern: DownloadString (but not actually downloading)
$webClient = "System.Net.WebClient would be used here"
$downloadString = "DownloadString method would be called here"

# Suspicious pattern: Hidden window execution
$windowStyle = "Hidden"

# Suspicious pattern: Base64 content (harmless)
$encodedCommand = "VGhpcyBpcyBqdXN0IGEgdGVzdCBzdHJpbmc="  # "This is just a test string"

# Educational output
Write-Host "This is an educational PowerShell script"
Write-Host "It contains suspicious patterns but performs no harmful actions"
Write-Host "Decoded message: This is just a test string"
'''
    
    def _generate_suspicious_batch(self) -> str:
        """Generate suspicious batch file content.
        
        Returns:
            Batch file content
        """
        return '''@echo off
REM Educational Batch Script - HARMLESS
REM This script contains patterns that might be flagged as suspicious
REM but performs no harmful actions

REM Suspicious pattern: File deletion commands (but not actually deleting)
echo This would delete files: del /q /s *.tmp
echo This would delete directories: rmdir /s /q temp_folder

REM Suspicious pattern: Registry modification (but not actually modifying)
echo This would modify registry: reg add HKCU\\Software\\Test

REM Suspicious pattern: Network activity (but not actually connecting)
echo This would download: powershell -command "& {some download command}"

REM Educational output
echo This is an educational batch script
echo It contains suspicious patterns but performs no harmful actions
echo All dangerous commands are only echoed, not executed

pause
'''
    
    def _generate_suspicious_vbscript(self) -> str:
        """Generate suspicious VBScript content.
        
        Returns:
            VBScript content
        """
        return '''' Educational VBScript - HARMLESS
' This script contains patterns that might be flagged as suspicious
' but performs no harmful actions

' Suspicious pattern: Shell object creation (but not actually creating)
Dim shellObject
' Set shellObject = CreateObject("WScript.Shell")

' Suspicious pattern: File system object (but not actually creating)
Dim fso
' Set fso = CreateObject("Scripting.FileSystemObject")

' Suspicious pattern: HTTP request object (but not actually creating)
Dim http
' Set http = CreateObject("MSXML2.XMLHTTP")

' Educational output
MsgBox "This is an educational VBScript"
MsgBox "It contains suspicious patterns but performs no harmful actions"
MsgBox "All object creation is commented out for safety"
'''
    
    def _generate_large_file_content(self) -> bytes:
        """Generate large file content for testing.
        
        Returns:
            Large file content (about 1MB)
        """
        # Generate 1MB of repeating pattern
        pattern = b"This is a large file test pattern for educational purposes. " * 16
        return pattern * 1000  # Approximately 1MB
    
    def get_all_samples(self) -> List[SampleInfo]:
        """Get all samples from the database.
        
        Returns:
            List of SampleInfo objects
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT name, file_path, sample_type, description, threat_level,
                       created_time, file_hash, file_size, educational_notes
                FROM samples
                ORDER BY name
            ''')
            
            samples = []
            for row in cursor.fetchall():
                sample = SampleInfo(
                    name=row[0],
                    file_path=row[1],
                    sample_type=row[2],
                    description=row[3],
                    threat_level=row[4],
                    created_time=datetime.fromisoformat(row[5]),
                    file_hash=row[6],
                    file_size=row[7],
                    educational_notes=row[8] or ""
                )
                samples.append(sample)
            
            conn.close()
            return samples
            
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve samples: {e}")
    
    def get_sample_by_name(self, name: str) -> Optional[SampleInfo]:
        """Get a specific sample by name.
        
        Args:
            name: Sample name
            
        Returns:
            SampleInfo object or None if not found
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT name, file_path, sample_type, description, threat_level,
                       created_time, file_hash, file_size, educational_notes
                FROM samples
                WHERE name = ?
            ''', (name,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return SampleInfo(
                    name=row[0],
                    file_path=row[1],
                    sample_type=row[2],
                    description=row[3],
                    threat_level=row[4],
                    created_time=datetime.fromisoformat(row[5]),
                    file_hash=row[6],
                    file_size=row[7],
                    educational_notes=row[8] or ""
                )
            return None
            
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve sample: {e}")
    
    def validate_database(self) -> Dict[str, bool]:
        """Validate the sample database and files.
        
        Returns:
            Dictionary with validation results
        """
        results = {
            'database_exists': False,
            'database_accessible': False,
            'samples_exist': False,
            'files_accessible': False
        }
        
        try:
            # Check if database exists
            results['database_exists'] = os.path.exists(self.db_path)
            
            if results['database_exists']:
                # Check if database is accessible
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM samples")
                sample_count = cursor.fetchone()[0]
                conn.close()
                
                results['database_accessible'] = True
                results['samples_exist'] = sample_count > 0
                
                # Check if sample files exist
                if results['samples_exist']:
                    samples = self.get_all_samples()
                    missing_files = []
                    for sample in samples:
                        if not os.path.exists(sample.file_path):
                            missing_files.append(sample.file_path)
                    
                    results['files_accessible'] = len(missing_files) == 0
                    if missing_files:
                        results['missing_files'] = missing_files
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def repair_database(self) -> bool:
        """Repair the sample database by recreating missing files.
        
        Returns:
            True if repair was successful
        """
        try:
            validation = self.validate_database()
            
            if not validation['database_exists']:
                print("Database doesn't exist, initializing...")
                self.initialize_database()
                return True
            
            if not validation['files_accessible'] and 'missing_files' in validation:
                print(f"Repairing {len(validation['missing_files'])} missing sample files...")
                
                # For now, just recreate the default samples
                # In a more sophisticated implementation, we could try to recreate
                # specific missing files based on their database records
                self._create_default_samples()
                
                return True
            
            print("Database validation passed, no repair needed")
            return True
            
        except Exception as e:
            print(f"Database repair failed: {e}")
            return False


def initialize_sample_database(config: Config, force_reset: bool = False) -> SampleDatabaseManager:
    """Initialize the sample database.
    
    Args:
        config: Configuration object
        force_reset: If True, recreate the database
        
    Returns:
        Initialized SampleDatabaseManager
    """
    manager = SampleDatabaseManager(config)
    manager.initialize_database(force_reset)
    return manager