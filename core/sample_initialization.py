"""
Sample database initialization module for the Educational Antivirus Research Tool.
Handles comprehensive initialization of sample databases, threat information, and validation.
"""
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .models import Config
from .sample_database import SampleDatabaseManager, initialize_sample_database
from .threat_database import ThreatDatabase, initialize_threat_database
from .exceptions import DatabaseError, SampleManagementError


class SampleInitializationManager:
    """Manages comprehensive sample database initialization and validation."""
    
    def __init__(self, config: Config):
        """Initialize the sample initialization manager.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.sample_db_manager = SampleDatabaseManager(config)
        self.threat_db = ThreatDatabase(config)
    
    def initialize_all_databases(self, force_reset: bool = False) -> Dict[str, bool]:
        """Initialize all sample and threat databases.
        
        Args:
            force_reset: If True, recreate all databases
            
        Returns:
            Dictionary with initialization results
        """
        results = {
            'threat_database': False,
            'sample_database': False,
            'default_samples': False,
            'validation_passed': False
        }
        
        print("=== Educational Antivirus Sample Database Initialization ===")
        
        try:
            # Initialize threat information database
            print("\n1. Initializing threat information database...")
            self.threat_db.initialize_database(force_reset)
            results['threat_database'] = True
            
            # Initialize sample database
            print("\n2. Initializing sample database...")
            self.sample_db_manager.initialize_database(force_reset)
            results['sample_database'] = True
            
            # Create additional educational samples
            print("\n3. Creating additional educational samples...")
            self._create_advanced_educational_samples()
            results['default_samples'] = True
            
            # Validate all databases
            print("\n4. Validating databases...")
            validation_results = self.validate_all_databases()
            results['validation_passed'] = all(validation_results.values())
            
            if results['validation_passed']:
                print("\n✓ All databases initialized and validated successfully!")
                self._print_initialization_summary()
            else:
                print("\n⚠ Some validation checks failed. See details above.")
            
        except Exception as e:
            print(f"\n✗ Initialization failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def validate_all_databases(self) -> Dict[str, bool]:
        """Validate all databases and their contents.
        
        Returns:
            Dictionary with validation results
        """
        print("Validating databases...")
        
        results = {}
        
        # Validate threat database
        threat_validation = self.threat_db.validate_database()
        results['threat_database_exists'] = threat_validation.get('database_exists', False)
        results['threat_database_accessible'] = threat_validation.get('database_accessible', False)
        results['threats_exist'] = threat_validation.get('threats_exist', False)
        
        # Validate sample database
        sample_validation = self.sample_db_manager.validate_database()
        results['sample_database_exists'] = sample_validation.get('database_exists', False)
        results['sample_database_accessible'] = sample_validation.get('database_accessible', False)
        results['samples_exist'] = sample_validation.get('samples_exist', False)
        results['sample_files_accessible'] = sample_validation.get('files_accessible', False)
        
        # Print validation results
        print(f"  Threat database: {'✓' if results['threat_database_exists'] else '✗'}")
        print(f"  Threat data: {'✓' if results['threats_exist'] else '✗'}")
        print(f"  Sample database: {'✓' if results['sample_database_exists'] else '✗'}")
        print(f"  Sample data: {'✓' if results['samples_exist'] else '✗'}")
        print(f"  Sample files: {'✓' if results['sample_files_accessible'] else '✗'}")
        
        return results
    
    def repair_databases(self) -> Dict[str, bool]:
        """Repair all databases by recreating missing or corrupted components.
        
        Returns:
            Dictionary with repair results
        """
        print("Repairing databases...")
        
        results = {
            'threat_database_repaired': False,
            'sample_database_repaired': False
        }
        
        try:
            # Repair threat database
            if self.threat_db.repair_database():
                results['threat_database_repaired'] = True
                print("✓ Threat database repaired")
            
            # Repair sample database
            if self.sample_db_manager.repair_database():
                results['sample_database_repaired'] = True
                print("✓ Sample database repaired")
            
        except Exception as e:
            print(f"✗ Database repair failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _create_advanced_educational_samples(self) -> None:
        """Create additional advanced educational samples."""
        print("Creating advanced educational samples...")
        
        # Check if samples directory structure exists
        educational_dir = Path(self.config.samples_path) / "educational"
        educational_dir.mkdir(parents=True, exist_ok=True)
        
        advanced_samples = [
            {
                'name': 'Multi-Stage Malware Simulation',
                'filename': 'multistage_simulation.txt',
                'content': self._generate_multistage_simulation(),
                'sample_type': 'educational_simulation',
                'description': 'Simulates multi-stage malware behavior patterns for educational analysis',
                'threat_level': 4,
                'educational_notes': 'Demonstrates how modern malware uses multiple stages to evade detection and establish persistence.',
                'detection_methods': 'Behavioral analysis, process monitoring, network traffic analysis',
                'learning_objectives': 'Understand multi-stage attack patterns and detection strategies'
            },
            {
                'name': 'Obfuscation Techniques Demo',
                'filename': 'obfuscation_demo.js',
                'content': self._generate_obfuscation_demo(),
                'sample_type': 'obfuscation_demo',
                'description': 'JavaScript file demonstrating various obfuscation techniques',
                'threat_level': 3,
                'educational_notes': 'Shows common obfuscation methods used by malware to hide malicious code.',
                'detection_methods': 'Static analysis, deobfuscation tools, behavioral analysis',
                'learning_objectives': 'Learn to identify and analyze obfuscated code patterns'
            },
            {
                'name': 'Social Engineering Simulation',
                'filename': 'social_engineering_example.html',
                'content': self._generate_social_engineering_demo(),
                'sample_type': 'social_engineering_demo',
                'description': 'HTML file demonstrating social engineering techniques',
                'threat_level': 2,
                'educational_notes': 'Illustrates how social engineering attacks manipulate users through psychological techniques.',
                'detection_methods': 'Content analysis, URL reputation, user education',
                'learning_objectives': 'Recognize social engineering tactics and develop countermeasures'
            },
            {
                'name': 'Persistence Mechanism Demo',
                'filename': 'persistence_demo.bat',
                'content': self._generate_persistence_demo(),
                'sample_type': 'persistence_demo',
                'description': 'Batch file demonstrating persistence mechanisms (harmless)',
                'threat_level': 3,
                'educational_notes': 'Shows common methods malware uses to maintain persistence on infected systems.',
                'detection_methods': 'Registry monitoring, startup analysis, behavioral detection',
                'learning_objectives': 'Understand malware persistence techniques and detection methods'
            }
        ]
        
        created_count = 0
        for sample_info in advanced_samples:
            try:
                self.sample_db_manager._create_sample_file(sample_info)
                created_count += 1
            except Exception as e:
                print(f"  Warning: Failed to create advanced sample '{sample_info['name']}': {e}")
        
        print(f"✓ Created {created_count} advanced educational samples")
    
    def _generate_multistage_simulation(self) -> str:
        """Generate multi-stage malware simulation content."""
        return '''# Multi-Stage Malware Simulation - EDUCATIONAL ONLY
# This file simulates the behavior patterns of multi-stage malware
# It contains NO executable code and is completely harmless

## Stage 1: Initial Infection Vector
# Simulated email attachment or drive-by download
INITIAL_VECTOR = "email_attachment_simulation"
PAYLOAD_URL = "http://example-malware-c2.invalid/payload"

## Stage 2: Environment Reconnaissance  
# Malware typically gathers system information
SYSTEM_INFO_COLLECTION = [
    "Operating System Version",
    "Installed Security Software", 
    "Network Configuration",
    "Running Processes",
    "User Privileges"
]

## Stage 3: Persistence Establishment
# Common persistence mechanisms
PERSISTENCE_METHODS = [
    "Registry Run Keys",
    "Scheduled Tasks",
    "Service Installation", 
    "Startup Folder",
    "DLL Hijacking"
]

## Stage 4: Command and Control
# Communication with remote servers
C2_COMMUNICATION = {
    "protocol": "HTTPS",
    "encryption": "AES-256",
    "beacon_interval": "300 seconds",
    "backup_domains": ["backup1.invalid", "backup2.invalid"]
}

## Stage 5: Payload Execution
# Final malicious activities
PAYLOAD_ACTIVITIES = [
    "Data Exfiltration",
    "Credential Harvesting",
    "Lateral Movement",
    "Additional Payload Download"
]

# Educational Note: This simulation helps understand the complexity
# of modern malware and the importance of multi-layered defense
'''
    
    def _generate_obfuscation_demo(self) -> str:
        """Generate obfuscation demonstration content."""
        return '''// Obfuscation Techniques Demonstration - EDUCATIONAL ONLY
// This JavaScript file demonstrates various obfuscation methods
// It contains NO malicious code and is completely harmless

// 1. String Obfuscation
var _0x1234 = ["hello", "world", "educational", "demo"];
var greeting = _0x1234[0] + " " + _0x1234[1];

// 2. Base64 Encoding
var encoded = "ZWR1Y2F0aW9uYWwgZGVtbw=="; // "educational demo"
var decoded = atob(encoded);

// 3. Character Code Obfuscation  
var obfuscated = String.fromCharCode(101,100,117,99,97,116,105,111,110,97,108);

// 4. Hexadecimal Encoding
var hex_string = "\\x65\\x64\\x75\\x63\\x61\\x74\\x69\\x6f\\x6e\\x61\\x6c";

// 5. Function Name Obfuscation
var _0xabcd = function() {
    return "This is an educational demonstration";
};

// 6. Control Flow Obfuscation
var result = "";
for(var i = 0; i < 10; i++) {
    if(i % 2 == 0) {
        result += "even ";
    } else {
        result += "odd ";
    }
}

// Educational Note: Real malware uses these techniques to hide
// malicious code from static analysis tools
console.log("Educational obfuscation demo completed");
'''
    
    def _generate_social_engineering_demo(self) -> str:
        """Generate social engineering demonstration content."""
        return '''<!DOCTYPE html>
<html>
<head>
    <title>Social Engineering Demonstration - EDUCATIONAL ONLY</title>
    <style>
        .warning { color: red; font-weight: bold; }
        .urgent { background-color: yellow; padding: 10px; }
    </style>
</head>
<body>
    <h1>Social Engineering Techniques Demo</h1>
    <p class="warning">THIS IS AN EDUCATIONAL DEMONSTRATION - NOT A REAL ATTACK</p>
    
    <h2>Common Social Engineering Tactics:</h2>
    
    <div class="urgent">
        <h3>1. Urgency and Fear</h3>
        <p>"Your account will be suspended in 24 hours unless you verify immediately!"</p>
        <p><em>Educational Note: Creates pressure to act without thinking</em></p>
    </div>
    
    <h3>2. Authority Impersonation</h3>
    <p>"This is your IT department. We need your password for security updates."</p>
    <p><em>Educational Note: Exploits trust in authority figures</em></p>
    
    <h3>3. Curiosity Exploitation</h3>
    <p>"You won't believe what your coworker said about you - click here!"</p>
    <p><em>Educational Note: Uses human curiosity as attack vector</em></p>
    
    <h3>4. Reciprocity</h3>
    <p>"We've selected you for a special offer as a valued customer..."</p>
    <p><em>Educational Note: Makes victim feel special or obligated</em></p>
    
    <h3>5. Scarcity</h3>
    <p>"Limited time offer - only 3 spots remaining!"</p>
    <p><em>Educational Note: Creates false sense of scarcity</em></p>
    
    <h2>Defense Strategies:</h2>
    <ul>
        <li>Verify requests through independent channels</li>
        <li>Be suspicious of urgent requests</li>
        <li>Never provide credentials via email or phone</li>
        <li>Check URLs carefully before clicking</li>
        <li>When in doubt, ask IT security team</li>
    </ul>
    
    <p class="warning">Remember: This is educational content to help recognize real attacks!</p>
</body>
</html>'''
    
    def _generate_persistence_demo(self) -> str:
        """Generate persistence mechanism demonstration content."""
        return '''@echo off
REM Persistence Mechanism Demonstration - EDUCATIONAL ONLY
REM This batch file demonstrates persistence techniques
REM It contains NO executable code and is completely harmless

echo Educational Persistence Mechanism Demo
echo =====================================

REM 1. Registry Run Keys (DEMONSTRATION ONLY)
echo Demonstrating Registry Run Key persistence:
echo reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "MalwareDemo" /t REG_SZ /d "C:\\demo\\malware.exe"
echo (This command is NOT executed - for educational purposes only)

REM 2. Scheduled Tasks (DEMONSTRATION ONLY)  
echo.
echo Demonstrating Scheduled Task persistence:
echo schtasks /create /tn "MalwareTask" /tr "C:\\demo\\malware.exe" /sc onlogon
echo (This command is NOT executed - for educational purposes only)

REM 3. Service Installation (DEMONSTRATION ONLY)
echo.
echo Demonstrating Service persistence:
echo sc create "MalwareService" binPath= "C:\\demo\\malware.exe" start= auto
echo (This command is NOT executed - for educational purposes only)

REM 4. Startup Folder (DEMONSTRATION ONLY)
echo.
echo Demonstrating Startup Folder persistence:
echo copy "malware.exe" "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
echo (This command is NOT executed - for educational purposes only)

REM 5. WMI Event Subscription (DEMONSTRATION ONLY)
echo.
echo Demonstrating WMI persistence:
echo wmic /namespace:"\\\\root\\subscription" PATH __EventFilter CREATE Name="MalwareFilter", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"
echo (This command is NOT executed - for educational purposes only)

echo.
echo Educational Notes:
echo - Real malware uses these techniques to survive reboots
echo - Detection requires monitoring these persistence locations
echo - Regular system audits can identify unauthorized persistence
echo - Behavioral analysis can detect persistence establishment

echo.
echo This demonstration helps understand malware persistence methods
echo All commands shown are for educational purposes only
pause
'''
    
    def _print_initialization_summary(self) -> None:
        """Print a summary of the initialization process."""
        print("\n=== Initialization Summary ===")
        
        # Get sample statistics
        samples = self.sample_db_manager.get_all_samples()
        sample_types = {}
        for sample in samples:
            sample_type = sample.sample_type
            sample_types[sample_type] = sample_types.get(sample_type, 0) + 1
        
        print(f"Total samples created: {len(samples)}")
        for sample_type, count in sample_types.items():
            print(f"  {sample_type}: {count}")
        
        # Get threat information statistics
        threats = self.threat_db.get_all_threats()
        threat_categories = {}
        for threat in threats:
            category = threat.category
            threat_categories[category] = threat_categories.get(category, 0) + 1
        
        print(f"\nThreat information entries: {len(threats)}")
        for category, count in threat_categories.items():
            print(f"  {category}: {count}")
        
        print(f"\nSample database location: {self.sample_db_manager.db_path}")
        print(f"Threat database location: {self.threat_db.db_path}")
        print(f"Sample files location: {self.config.samples_path}")
        
        print("\n✓ Educational antivirus sample databases are ready for use!")
    
    def get_initialization_status(self) -> Dict[str, any]:
        """Get current initialization status.
        
        Returns:
            Dictionary with detailed status information
        """
        status = {
            'databases_initialized': False,
            'sample_count': 0,
            'threat_count': 0,
            'validation_results': {},
            'sample_types': {},
            'threat_categories': {}
        }
        
        try:
            # Check validation
            validation = self.validate_all_databases()
            status['validation_results'] = validation
            status['databases_initialized'] = all(validation.values())
            
            # Get sample statistics
            if validation.get('sample_database_accessible', False):
                samples = self.sample_db_manager.get_all_samples()
                status['sample_count'] = len(samples)
                
                sample_types = {}
                for sample in samples:
                    sample_type = sample.sample_type
                    sample_types[sample_type] = sample_types.get(sample_type, 0) + 1
                status['sample_types'] = sample_types
            
            # Get threat statistics
            if validation.get('threat_database_accessible', False):
                threats = self.threat_db.get_all_threats()
                status['threat_count'] = len(threats)
                
                threat_categories = {}
                for threat in threats:
                    category = threat.category
                    threat_categories[category] = threat_categories.get(category, 0) + 1
                status['threat_categories'] = threat_categories
        
        except Exception as e:
            status['error'] = str(e)
        
        return status


def initialize_educational_databases(config: Config, force_reset: bool = False) -> SampleInitializationManager:
    """Initialize all educational databases.
    
    Args:
        config: Configuration object
        force_reset: If True, recreate all databases
        
    Returns:
        Initialized SampleInitializationManager
    """
    manager = SampleInitializationManager(config)
    manager.initialize_all_databases(force_reset)
    return manager


def main():
    """Main function for standalone execution."""
    from .config import ConfigManager
    
    # Load configuration
    config_manager = ConfigManager()
    config = config_manager.get_config()
    
    # Initialize databases
    manager = initialize_educational_databases(config, force_reset=False)
    
    # Print status
    status = manager.get_initialization_status()
    if status.get('databases_initialized', False):
        print("✓ All databases are properly initialized")
    else:
        print("⚠ Some databases need attention")
        print("Run with force_reset=True to recreate databases")


if __name__ == "__main__":
    main()