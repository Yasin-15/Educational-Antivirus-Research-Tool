"""
Educational threat information database for the Educational Antivirus Research Tool.
Provides comprehensive information about different types of threats for educational purposes.
"""
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from .models import Config
from .exceptions import DatabaseError


class ThreatInfo:
    """Information about a specific threat type."""
    
    def __init__(self, threat_id: str, name: str, category: str, description: str,
                 detection_methods: List[str], educational_content: Dict[str, str],
                 examples: List[str], prevention_tips: List[str], severity: int = 1):
        self.threat_id = threat_id
        self.name = name
        self.category = category
        self.description = description
        self.detection_methods = detection_methods
        self.educational_content = educational_content
        self.examples = examples
        self.prevention_tips = prevention_tips
        self.severity = severity
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'threat_id': self.threat_id,
            'name': self.name,
            'category': self.category,
            'description': self.description,
            'detection_methods': self.detection_methods,
            'educational_content': self.educational_content,
            'examples': self.examples,
            'prevention_tips': self.prevention_tips,
            'severity': self.severity
        }


class ThreatDatabase:
    """Educational threat information database."""
    
    def __init__(self, config: Config):
        """Initialize threat database.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.db_path = Path("data") / "educational.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
    
    def initialize_database(self, force_reset: bool = False) -> None:
        """Initialize the threat information database.
        
        Args:
            force_reset: If True, recreate the database
        """
        if self.db_path.exists() and not force_reset:
            print(f"Threat database already exists: {self.db_path}")
            return
        
        print("Creating educational threat information database...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create threats table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    threat_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    description TEXT,
                    detection_methods TEXT,
                    educational_content TEXT,
                    examples TEXT,
                    prevention_tips TEXT,
                    severity INTEGER DEFAULT 1,
                    created_time TEXT
                )
            ''')
            
            # Create detection patterns table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS detection_patterns (
                    pattern_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id TEXT,
                    pattern_type TEXT,
                    pattern_value TEXT,
                    description TEXT,
                    FOREIGN KEY (threat_id) REFERENCES threats (threat_id)
                )
            ''')
            
            # Create learning objectives table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS learning_objectives (
                    objective_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id TEXT,
                    objective TEXT,
                    explanation TEXT,
                    FOREIGN KEY (threat_id) REFERENCES threats (threat_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            
            # Populate with educational threat information
            self._populate_threat_database()
            
            print("✓ Educational threat database initialized successfully")
            
        except Exception as e:
            raise DatabaseError(f"Failed to initialize threat database: {e}")
    
    def _populate_threat_database(self) -> None:
        """Populate database with educational threat information."""
        print("Populating threat database with educational content...")
        
        threats = [
            ThreatInfo(
                threat_id="virus_basic",
                name="Computer Virus",
                category="Malware",
                description="A computer virus is a type of malicious software that replicates itself by modifying other computer programs and inserting its own code.",
                detection_methods=["Signature-based detection", "Heuristic analysis", "Behavioral monitoring"],
                educational_content={
                    "definition": "A virus is self-replicating malware that attaches to other programs",
                    "history": "The first computer virus was created in 1971 by Bob Thomas",
                    "impact": "Viruses can corrupt files, steal data, or make systems unusable",
                    "evolution": "Modern viruses use encryption and polymorphism to evade detection"
                },
                examples=["EICAR test file", "Boot sector viruses", "File infector viruses"],
                prevention_tips=[
                    "Keep antivirus software updated",
                    "Avoid opening suspicious email attachments",
                    "Regular system backups",
                    "Keep operating system patched"
                ],
                severity=4
            ),
            ThreatInfo(
                threat_id="trojan_basic",
                name="Trojan Horse",
                category="Malware",
                description="A Trojan horse is malicious software that misleads users by appearing to be legitimate software.",
                detection_methods=["Behavioral analysis", "Network monitoring", "File reputation analysis"],
                educational_content={
                    "definition": "Trojans disguise themselves as legitimate software to gain system access",
                    "origin": "Named after the wooden horse from Greek mythology",
                    "types": "Banking trojans, RATs (Remote Access Trojans), Backdoor trojans",
                    "payload": "Can steal data, provide remote access, or download additional malware"
                },
                examples=["Banking trojans", "Remote access trojans", "Backdoor trojans"],
                prevention_tips=[
                    "Download software only from trusted sources",
                    "Use application whitelisting",
                    "Monitor network traffic",
                    "Regular security audits"
                ],
                severity=5
            ),
            ThreatInfo(
                threat_id="worm_basic",
                name="Computer Worm",
                category="Malware",
                description="A computer worm is a standalone malware program that replicates itself to spread to other computers.",
                detection_methods=["Network traffic analysis", "Signature detection", "Anomaly detection"],
                educational_content={
                    "definition": "Worms spread automatically across networks without user interaction",
                    "propagation": "Uses network vulnerabilities, email, or removable media",
                    "famous_examples": "Morris Worm (1988), ILOVEYOU (2000), Conficker (2008)",
                    "damage": "Can consume network bandwidth and system resources"
                },
                examples=["Network worms", "Email worms", "USB worms"],
                prevention_tips=[
                    "Keep systems patched",
                    "Use network segmentation",
                    "Monitor network traffic",
                    "Disable unnecessary network services"
                ],
                severity=4
            ),
            ThreatInfo(
                threat_id="adware_basic",
                name="Adware",
                category="Potentially Unwanted Program",
                description="Adware is software that automatically displays or downloads advertising material when a user is online.",
                detection_methods=["Behavioral analysis", "Registry monitoring", "Network traffic analysis"],
                educational_content={
                    "definition": "Software that displays unwanted advertisements",
                    "business_model": "Generates revenue through advertising impressions",
                    "privacy_concerns": "May track user behavior and browsing habits",
                    "legal_status": "Often legally installed but unwanted by users"
                },
                examples=["Browser toolbars", "Pop-up generators", "Search hijackers"],
                prevention_tips=[
                    "Read software installation agreements carefully",
                    "Use ad blockers",
                    "Regular system scans",
                    "Avoid suspicious downloads"
                ],
                severity=2
            ),
            ThreatInfo(
                threat_id="spyware_basic",
                name="Spyware",
                category="Malware",
                description="Spyware is software that secretly monitors and collects user information without their knowledge.",
                detection_methods=["Behavioral monitoring", "Registry analysis", "Network monitoring"],
                educational_content={
                    "definition": "Malware that secretly collects user information",
                    "data_collected": "Keystrokes, browsing habits, personal information",
                    "installation": "Often bundled with legitimate software or installed via exploits",
                    "legal_implications": "Violates privacy laws in many jurisdictions"
                },
                examples=["Keyloggers", "Screen capture tools", "Browser hijackers"],
                prevention_tips=[
                    "Use anti-spyware tools",
                    "Monitor system processes",
                    "Regular privacy audits",
                    "Secure browsing practices"
                ],
                severity=4
            ),
            ThreatInfo(
                threat_id="ransomware_basic",
                name="Ransomware",
                category="Malware",
                description="Ransomware is malware that encrypts files and demands payment for decryption.",
                detection_methods=["Behavioral analysis", "File system monitoring", "Network traffic analysis"],
                educational_content={
                    "definition": "Malware that encrypts files and demands ransom payment",
                    "payment_methods": "Usually demands cryptocurrency payments",
                    "variants": "Crypto-ransomware, Locker ransomware, Scareware",
                    "impact": "Can cause significant business disruption and data loss"
                },
                examples=["WannaCry", "CryptoLocker", "Petya"],
                prevention_tips=[
                    "Regular offline backups",
                    "Keep systems updated",
                    "User education and training",
                    "Network segmentation"
                ],
                severity=5
            ),
            ThreatInfo(
                threat_id="rootkit_basic",
                name="Rootkit",
                category="Malware",
                description="A rootkit is malware designed to remain hidden on a computer while maintaining persistent access.",
                detection_methods=["Memory analysis", "Boot sector scanning", "Integrity checking"],
                educational_content={
                    "definition": "Malware that hides its presence and maintains system access",
                    "stealth_techniques": "Hooks system calls, modifies kernel structures",
                    "types": "User-mode rootkits, Kernel-mode rootkits, Bootkit rootkits",
                    "detection_challenges": "Designed to evade traditional antivirus detection"
                },
                examples=["Kernel rootkits", "Bootkit rootkits", "Firmware rootkits"],
                prevention_tips=[
                    "Use specialized rootkit scanners",
                    "Boot from clean media for scanning",
                    "Monitor system integrity",
                    "Regular security assessments"
                ],
                severity=5
            ),
            ThreatInfo(
                threat_id="phishing_basic",
                name="Phishing",
                category="Social Engineering",
                description="Phishing is a social engineering attack that tricks users into revealing sensitive information.",
                detection_methods=["URL analysis", "Content analysis", "Reputation checking"],
                educational_content={
                    "definition": "Fraudulent attempts to obtain sensitive information",
                    "methods": "Email, SMS, phone calls, fake websites",
                    "targets": "Login credentials, financial information, personal data",
                    "psychology": "Uses urgency, fear, and authority to manipulate victims"
                },
                examples=["Email phishing", "Spear phishing", "Whaling attacks"],
                prevention_tips=[
                    "Verify sender identity",
                    "Check URLs carefully",
                    "Use two-factor authentication",
                    "Security awareness training"
                ],
                severity=3
            )
        ]
        
        # Insert threats into database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for threat in threats:
            cursor.execute('''
                INSERT OR REPLACE INTO threats 
                (threat_id, name, category, description, detection_methods, 
                 educational_content, examples, prevention_tips, severity, created_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat.threat_id,
                threat.name,
                threat.category,
                threat.description,
                json.dumps(threat.detection_methods),
                json.dumps(threat.educational_content),
                json.dumps(threat.examples),
                json.dumps(threat.prevention_tips),
                threat.severity,
                datetime.now().isoformat()
            ))
        
        conn.commit()
        conn.close()
        
        print(f"✓ Added {len(threats)} threat types to educational database")
    
    def get_threat_info(self, threat_id: str) -> Optional[ThreatInfo]:
        """Get information about a specific threat.
        
        Args:
            threat_id: ID of the threat
            
        Returns:
            ThreatInfo object or None if not found
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT threat_id, name, category, description, detection_methods,
                       educational_content, examples, prevention_tips, severity
                FROM threats WHERE threat_id = ?
            ''', (threat_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return ThreatInfo(
                    threat_id=row[0],
                    name=row[1],
                    category=row[2],
                    description=row[3],
                    detection_methods=json.loads(row[4]),
                    educational_content=json.loads(row[5]),
                    examples=json.loads(row[6]),
                    prevention_tips=json.loads(row[7]),
                    severity=row[8]
                )
            return None
            
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve threat info: {e}")
    
    def get_all_threats(self) -> List[ThreatInfo]:
        """Get all threat information.
        
        Returns:
            List of ThreatInfo objects
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT threat_id, name, category, description, detection_methods,
                       educational_content, examples, prevention_tips, severity
                FROM threats ORDER BY category, name
            ''')
            
            threats = []
            for row in cursor.fetchall():
                threat = ThreatInfo(
                    threat_id=row[0],
                    name=row[1],
                    category=row[2],
                    description=row[3],
                    detection_methods=json.loads(row[4]),
                    educational_content=json.loads(row[5]),
                    examples=json.loads(row[6]),
                    prevention_tips=json.loads(row[7]),
                    severity=row[8]
                )
                threats.append(threat)
            
            conn.close()
            return threats
            
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve threats: {e}")
    
    def get_threats_by_category(self, category: str) -> List[ThreatInfo]:
        """Get threats by category.
        
        Args:
            category: Threat category
            
        Returns:
            List of ThreatInfo objects
        """
        all_threats = self.get_all_threats()
        return [threat for threat in all_threats if threat.category == category]
    
    def search_threats(self, query: str) -> List[ThreatInfo]:
        """Search threats by name or description.
        
        Args:
            query: Search query
            
        Returns:
            List of matching ThreatInfo objects
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT threat_id, name, category, description, detection_methods,
                       educational_content, examples, prevention_tips, severity
                FROM threats 
                WHERE name LIKE ? OR description LIKE ?
                ORDER BY name
            ''', (f'%{query}%', f'%{query}%'))
            
            threats = []
            for row in cursor.fetchall():
                threat = ThreatInfo(
                    threat_id=row[0],
                    name=row[1],
                    category=row[2],
                    description=row[3],
                    detection_methods=json.loads(row[4]),
                    educational_content=json.loads(row[5]),
                    examples=json.loads(row[6]),
                    prevention_tips=json.loads(row[7]),
                    severity=row[8]
                )
                threats.append(threat)
            
            conn.close()
            return threats
            
        except Exception as e:
            raise DatabaseError(f"Failed to search threats: {e}")
    
    def validate_database(self) -> Dict[str, bool]:
        """Validate the threat database.
        
        Returns:
            Dictionary with validation results
        """
        results = {
            'database_exists': False,
            'database_accessible': False,
            'threats_exist': False
        }
        
        try:
            results['database_exists'] = self.db_path.exists()
            
            if results['database_exists']:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM threats")
                threat_count = cursor.fetchone()[0]
                conn.close()
                
                results['database_accessible'] = True
                results['threats_exist'] = threat_count > 0
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def repair_database(self) -> bool:
        """Repair the threat database by recreating it.
        
        Returns:
            True if repair was successful
        """
        try:
            print("Repairing threat database...")
            self.initialize_database(force_reset=True)
            return True
        except Exception as e:
            print(f"Database repair failed: {e}")
            return False


def initialize_threat_database(config: Config, force_reset: bool = False) -> ThreatDatabase:
    """Initialize the threat information database.
    
    Args:
        config: Configuration object
        force_reset: If True, recreate the database
        
    Returns:
        Initialized ThreatDatabase
    """
    db = ThreatDatabase(config)
    db.initialize_database(force_reset)
    return db