"""
Initialization system for the Educational Antivirus Research Tool.
Handles first-run setup, default configuration, and sample database creation.
"""
import os
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime

from .config import ConfigManager, create_initial_config
from .models import Config
from .exceptions import ConfigurationError, DatabaseError
from .logging_config import LoggingManager
from .sample_database import SampleDatabaseManager


class InitializationManager:
    """Manages first-run setup and initialization."""
    
    def __init__(self):
        """Initialize the setup manager."""
        self.config_manager = ConfigManager()
        self.logger = None
    
    def initialize_system(self, force_reset: bool = False) -> Config:
        """Initialize the complete system with defaults.
        
        Args:
            force_reset: If True, recreate all default files
            
        Returns:
            Initialized configuration
        """
        print("Initializing Educational Antivirus Research Tool...")
        
        # Step 1: Create default configuration
        config = self._setup_configuration(force_reset)
        
        # Step 2: Setup logging
        self._setup_logging(config)
        
        # Step 3: Create directory structure
        self._create_directory_structure(config)
        
        # Step 4: Initialize signature database
        self._initialize_signature_database(config, force_reset)
        
        # Step 5: Create educational content database
        self._initialize_educational_database(config, force_reset)
        
        # Step 6: Initialize sample database
        self._initialize_sample_database(config, force_reset)
        
        print("✓ System initialization completed successfully!")
        return config
    
    def _setup_configuration(self, force_reset: bool = False) -> Config:
        """Set up default configuration file.
        
        Args:
            force_reset: If True, recreate configuration file
            
        Returns:
            Configuration object
        """
        config_exists = any(os.path.exists(path) for path in ConfigManager.DEFAULT_CONFIG_PATHS)
        
        if not config_exists or force_reset:
            print("Creating default configuration file...")
            config = create_initial_config("config.json")
            print("✓ Default configuration created: config.json")
        else:
            print("Loading existing configuration...")
            config = self.config_manager.load_config()
            print("✓ Configuration loaded successfully")
        
        return config
    
    def _setup_logging(self, config: Config) -> None:
        """Set up logging system.
        
        Args:
            config: Configuration object
        """
        print("Setting up logging system...")
        logging_manager = LoggingManager(config)
        self.logger = logging_manager.setup_logging()
        print(f"✓ Logging configured: {config.log_file}")
    
    def _create_directory_structure(self, config: Config) -> None:
        """Create required directory structure.
        
        Args:
            config: Configuration object
        """
        print("Creating directory structure...")
        
        directories = [
            config.quarantine_path,
            config.samples_path,
            config.reports_path,
            os.path.dirname(config.signature_db_path),
            os.path.join(config.quarantine_path, "files"),
            os.path.join(config.samples_path, "educational"),
            os.path.join(config.samples_path, "test")
        ]
        
        for directory in directories:
            if directory:  # Skip empty paths
                Path(directory).mkdir(parents=True, exist_ok=True)
                print(f"  ✓ Created: {directory}")
    
    def _initialize_signature_database(self, config: Config, force_reset: bool = False) -> None:
        """Initialize signature database with educational samples.
        
        Args:
            config: Configuration object
            force_reset: If True, recreate database
        """
        db_path = config.signature_db_path
        
        if os.path.exists(db_path) and not force_reset:
            print(f"Signature database already exists: {db_path}")
            return
        
        print("Creating signature database with educational samples...")
        
        # Ensure directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create signatures table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    description TEXT,
                    threat_level INTEGER DEFAULT 5,
                    signature_type TEXT DEFAULT 'hex',
                    created_date TEXT,
                    educational_notes TEXT
                )
            ''')
            
            # Insert educational signatures
            educational_signatures = self._get_educational_signatures()
            
            for sig in educational_signatures:
                cursor.execute('''
                    INSERT INTO signatures (name, pattern, description, threat_level, 
                                          signature_type, created_date, educational_notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', sig)
            
            conn.commit()
            conn.close()
            
            print(f"✓ Signature database created with {len(educational_signatures)} educational signatures")
            
        except Exception as e:
            raise DatabaseError(f"Failed to initialize signature database: {e}")
    
    def _initialize_educational_database(self, config: Config, force_reset: bool = False) -> None:
        """Initialize educational content database.
        
        Args:
            config: Configuration object
            force_reset: If True, recreate database
        """
        edu_db_path = os.path.join(os.path.dirname(config.signature_db_path), "educational.db")
        
        if os.path.exists(edu_db_path) and not force_reset:
            print(f"Educational database already exists: {edu_db_path}")
            return
        
        print("Creating educational content database...")
        
        try:
            conn = sqlite3.connect(edu_db_path)
            cursor = conn.cursor()
            
            # Create threat information table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_name TEXT NOT NULL,
                    category TEXT,
                    description TEXT,
                    how_it_works TEXT,
                    prevention_tips TEXT,
                    detection_methods TEXT,
                    severity_level INTEGER DEFAULT 5,
                    created_date TEXT
                )
            ''')
            
            # Create learning recommendations table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS learning_recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection_type TEXT,
                    user_level TEXT,
                    recommendations TEXT,
                    resources TEXT,
                    next_steps TEXT,
                    created_date TEXT
                )
            ''')
            
            # Insert educational content
            threat_info = self._get_educational_threat_info()
            learning_recs = self._get_learning_recommendations()
            
            for threat in threat_info:
                cursor.execute('''
                    INSERT INTO threat_info (threat_name, category, description, how_it_works,
                                           prevention_tips, detection_methods, severity_level, created_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', threat)
            
            for rec in learning_recs:
                cursor.execute('''
                    INSERT INTO learning_recommendations (detection_type, user_level, recommendations,
                                                        resources, next_steps, created_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', rec)
            
            conn.commit()
            conn.close()
            
            print(f"✓ Educational database created with {len(threat_info)} threat descriptions")
            print(f"  and {len(learning_recs)} learning recommendations")
            
        except Exception as e:
            raise DatabaseError(f"Failed to initialize educational database: {e}")
    
    def _initialize_sample_database(self, config: Config, force_reset: bool = False) -> None:
        """Initialize sample database with educational test samples.
        
        Args:
            config: Configuration object
            force_reset: If True, recreate database
        """
        print("Initializing sample database...")
        
        try:
            sample_manager = SampleDatabaseManager(config)
            sample_manager.initialize_database(force_reset)
            
            # Validate the database
            validation = sample_manager.validate_database()
            if all(validation.values()):
                print("✓ Sample database validation passed")
            else:
                print("⚠ Sample database validation issues detected")
                if not sample_manager.repair_database():
                    print("✗ Failed to repair sample database")
                else:
                    print("✓ Sample database repaired successfully")
            
        except Exception as e:
            raise DatabaseError(f"Failed to initialize sample database: {e}")
    
    def _get_educational_signatures(self) -> List[Tuple]:
        """Get educational signature patterns.
        
        Returns:
            List of signature tuples for database insertion
        """
        current_time = datetime.now().isoformat()
        
        return [
            # EICAR test signature
            (
                "EICAR Test File",
                "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                "Standard EICAR antivirus test file - harmless test pattern",
                8,
                "string",
                current_time,
                "This is the industry-standard test file used to verify antivirus functionality. It's completely harmless but triggers most antivirus engines."
            ),
            
            # Suspicious executable patterns
            (
                "PE Executable Header",
                "4D5A",  # MZ header
                "Windows PE executable file header",
                3,
                "hex",
                current_time,
                "The 'MZ' signature indicates a Windows executable file. While not malicious by itself, it's the first check in identifying executable files."
            ),
            
            # Suspicious script patterns
            (
                "PowerShell Download Pattern",
                "powershell.*downloadstring",
                "PowerShell script attempting to download content",
                7,
                "regex",
                current_time,
                "This pattern detects PowerShell scripts that download content from the internet, a common technique used by malware."
            ),
            
            # Batch file patterns
            (
                "Batch File Autorun",
                "@echo off.*del.*\\*\\.\\*",
                "Batch file with deletion commands",
                6,
                "regex",
                current_time,
                "Detects batch files that attempt to delete files, which could be destructive behavior."
            ),
            
            # VBS script patterns
            (
                "VBScript Suspicious Pattern",
                "CreateObject.*WScript\\.Shell",
                "VBScript creating shell objects",
                5,
                "regex",
                current_time,
                "VBScript that creates shell objects can execute system commands, potentially dangerous behavior."
            ),
            
            # High entropy pattern (simulated)
            (
                "High Entropy Content",
                "[A-Za-z0-9+/]{100,}={0,2}",
                "Base64 encoded content (possible encrypted payload)",
                4,
                "regex",
                current_time,
                "Long base64 strings might indicate encrypted or obfuscated content, common in malware."
            )
        ]
    
    def _get_educational_threat_info(self) -> List[Tuple]:
        """Get educational threat information.
        
        Returns:
            List of threat info tuples for database insertion
        """
        current_time = datetime.now().isoformat()
        
        return [
            (
                "EICAR Test File",
                "Test Pattern",
                "A harmless test file designed to trigger antivirus software without containing actual malicious code.",
                "The EICAR test file contains a specific text string that antivirus programs recognize as a test signature. When scanned, it should be detected as if it were malware, allowing users to verify their antivirus is working properly.",
                "No prevention needed - this is a legitimate test file. However, some antivirus software may quarantine it automatically.",
                "Signature-based detection using the known EICAR test string pattern.",
                2,
                current_time
            ),
            
            (
                "PowerShell Downloader",
                "Script-based Malware",
                "Malicious PowerShell scripts that download and execute additional payloads from remote servers.",
                "Attackers use PowerShell's built-in capabilities to download malicious code from the internet and execute it directly in memory, often bypassing traditional file-based detection.",
                "Restrict PowerShell execution policy, monitor network connections, use application whitelisting, and implement behavioral analysis.",
                "Behavioral analysis of PowerShell processes, network monitoring, and script content analysis.",
                7,
                current_time
            ),
            
            (
                "Batch File Malware",
                "Script-based Malware",
                "Malicious batch files that can delete files, modify system settings, or download additional malware.",
                "Batch files use Windows command-line instructions to perform automated tasks. Malicious versions can damage systems by deleting files, changing configurations, or installing other malware.",
                "Be cautious with .bat and .cmd files from unknown sources, use antivirus with real-time protection, and avoid running scripts with administrative privileges.",
                "File extension monitoring, content analysis for suspicious commands, and behavioral monitoring of file system changes.",
                6,
                current_time
            ),
            
            (
                "VBScript Malware",
                "Script-based Malware",
                "Malicious Visual Basic scripts that can manipulate system settings, steal data, or install additional malware.",
                "VBScript can interact with Windows system components, access files, modify registry settings, and execute other programs, making it a versatile tool for attackers.",
                "Disable Windows Script Host if not needed, use updated antivirus software, and be cautious with .vbs files from untrusted sources.",
                "Script content analysis, behavioral monitoring of system changes, and signature-based detection of known malicious patterns.",
                5,
                current_time
            ),
            
            (
                "High Entropy File",
                "Packed/Encrypted Malware",
                "Files with unusually high entropy may indicate encrypted, compressed, or obfuscated malicious content.",
                "Malware authors often encrypt or pack their code to evade signature-based detection. High entropy (randomness) in a file can indicate such obfuscation techniques.",
                "Use antivirus with behavioral analysis capabilities, implement application sandboxing, and be suspicious of files with unusual characteristics.",
                "Entropy analysis, unpacking detection, behavioral analysis in sandboxed environments.",
                4,
                current_time
            )
        ]
    
    def _get_learning_recommendations(self) -> List[Tuple]:
        """Get learning recommendations for different user levels.
        
        Returns:
            List of learning recommendation tuples for database insertion
        """
        current_time = datetime.now().isoformat()
        
        return [
            (
                "signature",
                "beginner",
                "Learn about signature-based detection: how antivirus software uses known patterns to identify malware. Practice with the EICAR test file to understand how detection works.",
                "EICAR test file documentation, basic antivirus concepts, signature database fundamentals",
                "Try creating your own harmless test patterns and see how the scanner detects them",
                current_time
            ),
            
            (
                "behavioral",
                "beginner",
                "Understand behavioral analysis: how suspicious file characteristics (like high entropy or unusual extensions) can indicate potential threats.",
                "File entropy concepts, suspicious file patterns, behavioral analysis basics",
                "Experiment with different file types and observe their entropy scores and risk assessments",
                current_time
            ),
            
            (
                "signature",
                "intermediate",
                "Study advanced signature techniques: regular expressions, hex patterns, and multi-pattern matching for more sophisticated threat detection.",
                "Regular expression tutorials, hex editing basics, advanced pattern matching",
                "Create custom signatures for specific threat types and test their effectiveness",
                current_time
            ),
            
            (
                "behavioral",
                "intermediate",
                "Explore advanced behavioral analysis: file structure analysis, API call monitoring, and dynamic analysis techniques.",
                "PE file format, API monitoring tools, dynamic analysis concepts",
                "Set up a safe analysis environment to study malware behavior patterns",
                current_time
            ),
            
            (
                "signature",
                "advanced",
                "Master signature evasion and detection: polymorphic malware, signature optimization, and machine learning approaches to pattern recognition.",
                "Polymorphic malware research, ML in cybersecurity, advanced evasion techniques",
                "Research current malware trends and develop adaptive detection strategies",
                current_time
            ),
            
            (
                "behavioral",
                "advanced",
                "Deep dive into behavioral analysis: sandbox evasion techniques, advanced static analysis, and threat intelligence integration.",
                "Sandbox evasion research, static analysis tools, threat intelligence platforms",
                "Contribute to open-source security tools and research projects",
                current_time
            )
        ]
    
    def check_system_status(self) -> Dict[str, bool]:
        """Check if system components are properly initialized.
        
        Returns:
            Dictionary with component status
        """
        status = {}
        
        # Check configuration
        config_exists = any(os.path.exists(path) for path in ConfigManager.DEFAULT_CONFIG_PATHS)
        status['configuration'] = config_exists
        
        if config_exists:
            try:
                config = self.config_manager.load_config()
                
                # Check directories
                status['directories'] = all([
                    os.path.exists(config.quarantine_path),
                    os.path.exists(config.samples_path),
                    os.path.exists(config.reports_path)
                ])
                
                # Check signature database
                status['signature_database'] = os.path.exists(config.signature_db_path)
                
                # Check educational database
                edu_db_path = os.path.join(os.path.dirname(config.signature_db_path), "educational.db")
                status['educational_database'] = os.path.exists(edu_db_path)
                
                # Check sample database
                sample_db_path = os.path.join(config.samples_path, "samples.db")
                status['sample_database'] = os.path.exists(sample_db_path)
                
            except Exception:
                status['directories'] = False
                status['signature_database'] = False
                status['educational_database'] = False
                status['sample_database'] = False
        else:
            status['directories'] = False
            status['signature_database'] = False
            status['educational_database'] = False
            status['sample_database'] = False
        
        return status


def initialize_system(force_reset: bool = False) -> Config:
    """Initialize the complete system.
    
    Args:
        force_reset: If True, recreate all default files
        
    Returns:
        Initialized configuration
    """
    manager = InitializationManager()
    return manager.initialize_system(force_reset)


def check_initialization() -> bool:
    """Check if system is properly initialized.
    
    Returns:
        True if system is initialized, False otherwise
    """
    manager = InitializationManager()
    status = manager.check_system_status()
    return all(status.values())