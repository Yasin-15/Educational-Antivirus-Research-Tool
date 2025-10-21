"""
Educational content system for the Educational Antivirus Research Tool.

This module provides educational information about threats, detection methods,
and cybersecurity concepts to help users learn about antivirus technology.
"""
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from core.models import Detection, DetectionType
from core.logging_config import get_logger

logger = get_logger(__name__)


class ThreatCategory(Enum):
    """Categories of threats for educational classification."""
    VIRUS = "virus"
    TROJAN = "trojan"
    WORM = "worm"
    ADWARE = "adware"
    SPYWARE = "spyware"
    RANSOMWARE = "ransomware"
    ROOTKIT = "rootkit"
    BACKDOOR = "backdoor"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    TEST_FILE = "test_file"
    UNKNOWN = "unknown"


class DetectionMethod(Enum):
    """Detection methods for educational explanation."""
    SIGNATURE_MATCHING = "signature_matching"
    HEURISTIC_ANALYSIS = "heuristic_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    ENTROPY_ANALYSIS = "entropy_analysis"
    PATTERN_RECOGNITION = "pattern_recognition"


@dataclass
class ThreatInfo:
    """Educational information about a specific threat."""
    threat_name: str
    category: ThreatCategory
    description: str
    how_it_works: str
    potential_damage: str
    prevention_tips: List[str]
    detection_methods: List[DetectionMethod]
    severity_level: int  # 1-10 scale
    educational_notes: str
    real_world_examples: List[str] = field(default_factory=list)
    related_threats: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'threat_name': self.threat_name,
            'category': self.category.value,
            'description': self.description,
            'how_it_works': self.how_it_works,
            'potential_damage': self.potential_damage,
            'prevention_tips': self.prevention_tips,
            'detection_methods': [method.value for method in self.detection_methods],
            'severity_level': self.severity_level,
            'educational_notes': self.educational_notes,
            'real_world_examples': self.real_world_examples,
            'related_threats': self.related_threats
        }


@dataclass
class DetectionExplanation:
    """Explanation of how a detection was made."""
    detection_method: DetectionMethod
    method_description: str
    why_flagged: str
    confidence_level: str
    educational_context: str
    learning_objectives: List[str]
    further_reading: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'detection_method': self.detection_method.value,
            'method_description': self.method_description,
            'why_flagged': self.why_flagged,
            'confidence_level': self.confidence_level,
            'educational_context': self.educational_context,
            'learning_objectives': self.learning_objectives,
            'further_reading': self.further_reading
        }


class EducationalDatabase:
    """Database of educational content about threats and detection methods."""
    
    def __init__(self):
        """Initialize the educational database with default content."""
        self.threat_info: Dict[str, ThreatInfo] = {}
        self.detection_explanations: Dict[DetectionMethod, DetectionExplanation] = {}
        self._initialize_default_content()
    
    def _initialize_default_content(self) -> None:
        """Initialize database with default educational content."""
        # Initialize threat information
        self._add_default_threat_info()
        
        # Initialize detection method explanations
        self._add_default_detection_explanations()
    
    def _add_default_threat_info(self) -> None:
        """Add default threat information to the database."""
        
        # EICAR Test File
        self.threat_info["EICAR"] = ThreatInfo(
            threat_name="EICAR Test File",
            category=ThreatCategory.TEST_FILE,
            description="A harmless test file used to verify antivirus functionality.",
            how_it_works="Contains a specific text string that antivirus software recognizes as a test signature. It's completely harmless and contains no executable code.",
            potential_damage="None - this is a test file designed for educational purposes.",
            prevention_tips=[
                "This is a test file, no prevention needed",
                "Used to verify antivirus is working correctly",
                "Safe to create and scan for testing purposes"
            ],
            detection_methods=[DetectionMethod.SIGNATURE_MATCHING],
            severity_level=1,
            educational_notes="The EICAR test file is the industry standard for testing antivirus software. It allows users to verify their antivirus is working without using actual malware.",
            real_world_examples=[
                "Used by IT professionals to test antivirus installations",
                "Included in antivirus testing suites",
                "Used in cybersecurity training programs"
            ],
            related_threats=["Test signatures", "Harmless test files"]
        )
        
        # High Entropy File
        self.threat_info["High Entropy Content"] = ThreatInfo(
            threat_name="High Entropy Content",
            category=ThreatCategory.SUSPICIOUS_BEHAVIOR,
            description="Files with unusually high entropy that may indicate encryption, compression, or obfuscation.",
            how_it_works="Entropy measures randomness in data. High entropy can indicate encrypted/compressed content or attempts to hide malicious code through obfuscation.",
            potential_damage="May indicate packed malware, encrypted payloads, or attempts to evade detection.",
            prevention_tips=[
                "Be cautious with files that have unusually high entropy",
                "Verify the source and purpose of high-entropy files",
                "Use additional analysis methods beyond entropy",
                "Consider the file type and expected entropy levels"
            ],
            detection_methods=[DetectionMethod.ENTROPY_ANALYSIS, DetectionMethod.HEURISTIC_ANALYSIS],
            severity_level=5,
            educational_notes="Entropy analysis is a heuristic method that helps identify potentially suspicious files. However, legitimate compressed or encrypted files also have high entropy, so this method requires careful interpretation.",
            real_world_examples=[
                "Packed malware using UPX or similar packers",
                "Encrypted ransomware payloads",
                "Legitimate compressed archives (ZIP, RAR)",
                "Encrypted documents and files"
            ],
            related_threats=["Packed malware", "Encrypted payloads", "Obfuscated code"]
        )
        
        # Suspicious File Extension
        self.threat_info["Suspicious File Extension"] = ThreatInfo(
            threat_name="Suspicious File Extension",
            category=ThreatCategory.SUSPICIOUS_BEHAVIOR,
            description="Files with extensions commonly associated with executable or potentially dangerous content.",
            how_it_works="Certain file extensions (.exe, .scr, .bat, .cmd, .pif) are commonly used by malware. Behavioral analysis flags these for additional scrutiny.",
            potential_damage="Executable files can run code on the system, potentially causing damage or installing malware.",
            prevention_tips=[
                "Be cautious when opening executable files from unknown sources",
                "Verify the legitimacy of .exe and .scr files",
                "Use caution with script files (.bat, .cmd, .vbs)",
                "Enable file extension display in file explorer"
            ],
            detection_methods=[DetectionMethod.BEHAVIORAL_ANALYSIS, DetectionMethod.PATTERN_RECOGNITION],
            severity_level=6,
            educational_notes="File extension analysis is a basic but important security measure. While many legitimate programs use these extensions, they're also favored by malware authors.",
            real_world_examples=[
                "Trojan horses disguised as legitimate programs",
                "Email attachments with double extensions",
                "Malicious screen savers (.scr files)",
                "Batch file malware for system manipulation"
            ],
            related_threats=["Trojans", "Email malware", "Script-based attacks"]
        )
        
        # Custom Test Signature
        self.threat_info["Custom Test Signature"] = ThreatInfo(
            threat_name="Custom Test Signature",
            category=ThreatCategory.TEST_FILE,
            description="A custom-created test signature for educational demonstration purposes.",
            how_it_works="Contains a specific byte pattern that matches a signature in the test database. Used to demonstrate signature-based detection.",
            potential_damage="None - this is a harmless test pattern for educational purposes.",
            prevention_tips=[
                "This is a test signature for learning purposes",
                "Safe to create and scan for educational activities",
                "Helps understand how signature-based detection works"
            ],
            detection_methods=[DetectionMethod.SIGNATURE_MATCHING],
            severity_level=2,
            educational_notes="Custom test signatures help students understand how antivirus software uses pattern matching to identify known threats. This is the foundation of signature-based detection.",
            real_world_examples=[
                "Antivirus training programs",
                "Cybersecurity education labs",
                "Security software testing environments"
            ],
            related_threats=["EICAR test file", "Educational test patterns"]
        )
        
        # Behavioral Anomaly
        self.threat_info["Behavioral Anomaly"] = ThreatInfo(
            threat_name="Behavioral Anomaly",
            category=ThreatCategory.SUSPICIOUS_BEHAVIOR,
            description="File exhibiting multiple suspicious characteristics that collectively suggest potential threat.",
            how_it_works="Combines multiple indicators like high entropy, suspicious extensions, unusual file size, or other anomalous properties to assess threat likelihood.",
            potential_damage="Varies depending on the specific anomalies detected. Could indicate various types of malware or suspicious activity.",
            prevention_tips=[
                "Investigate files flagged for behavioral anomalies",
                "Consider the context and source of suspicious files",
                "Use multiple detection methods for verification",
                "Quarantine suspicious files for further analysis"
            ],
            detection_methods=[
                DetectionMethod.BEHAVIORAL_ANALYSIS,
                DetectionMethod.HEURISTIC_ANALYSIS,
                DetectionMethod.PATTERN_RECOGNITION
            ],
            severity_level=7,
            educational_notes="Behavioral analysis represents the evolution of antivirus technology beyond simple signature matching. It helps detect new and unknown threats by analyzing suspicious patterns.",
            real_world_examples=[
                "Zero-day malware without known signatures",
                "Polymorphic viruses that change their code",
                "Advanced persistent threats (APTs)",
                "Fileless malware attacks"
            ],
            related_threats=["Unknown malware", "Polymorphic threats", "Advanced attacks"]
        )
    
    def _add_default_detection_explanations(self) -> None:
        """Add default detection method explanations."""
        
        self.detection_explanations[DetectionMethod.SIGNATURE_MATCHING] = DetectionExplanation(
            detection_method=DetectionMethod.SIGNATURE_MATCHING,
            method_description="Signature-based detection compares file content against a database of known malware signatures (unique byte patterns).",
            why_flagged="The file contains a byte pattern that matches a known threat signature in the database.",
            confidence_level="High - signature matches are very reliable for known threats",
            educational_context="This is the oldest and most reliable antivirus detection method. It works by maintaining a database of 'fingerprints' from known malware samples.",
            learning_objectives=[
                "Understand how signature databases work",
                "Learn about pattern matching in cybersecurity",
                "Recognize the limitations of signature-only detection",
                "Appreciate the importance of signature updates"
            ],
            further_reading=[
                "History of antivirus signature detection",
                "How malware signatures are created",
                "Limitations of signature-based detection"
            ]
        )
        
        self.detection_explanations[DetectionMethod.HEURISTIC_ANALYSIS] = DetectionExplanation(
            detection_method=DetectionMethod.HEURISTIC_ANALYSIS,
            method_description="Heuristic analysis uses rules and algorithms to identify suspicious behavior patterns that may indicate malware.",
            why_flagged="The file exhibits characteristics or behaviors that match heuristic rules for potentially malicious activity.",
            confidence_level="Medium - heuristics can produce false positives but catch unknown threats",
            educational_context="Heuristic analysis helps detect new and unknown malware by looking for suspicious patterns rather than exact matches.",
            learning_objectives=[
                "Understand proactive threat detection",
                "Learn about rule-based security systems",
                "Recognize the balance between detection and false positives",
                "Appreciate the evolution beyond signature-only detection"
            ],
            further_reading=[
                "Heuristic analysis in antivirus software",
                "Machine learning in threat detection",
                "Balancing security and usability"
            ]
        )
        
        self.detection_explanations[DetectionMethod.BEHAVIORAL_ANALYSIS] = DetectionExplanation(
            detection_method=DetectionMethod.BEHAVIORAL_ANALYSIS,
            method_description="Behavioral analysis monitors file characteristics and system interactions to identify potentially malicious behavior.",
            why_flagged="The file's behavior or characteristics match patterns associated with malicious software.",
            confidence_level="Medium to High - depends on the specific behaviors observed",
            educational_context="Modern antivirus systems use behavioral analysis to detect threats that don't match known signatures, including zero-day attacks.",
            learning_objectives=[
                "Understand dynamic threat analysis",
                "Learn about behavioral indicators of compromise",
                "Recognize the importance of context in security",
                "Appreciate advanced detection techniques"
            ],
            further_reading=[
                "Behavioral analysis in cybersecurity",
                "Zero-day threat detection",
                "Advanced persistent threat detection"
            ]
        )
        
        self.detection_explanations[DetectionMethod.ENTROPY_ANALYSIS] = DetectionExplanation(
            detection_method=DetectionMethod.ENTROPY_ANALYSIS,
            method_description="Entropy analysis measures the randomness or disorder in file data to identify potentially packed, encrypted, or obfuscated content.",
            why_flagged="The file has unusually high entropy, suggesting it may be compressed, encrypted, or obfuscated to hide malicious content.",
            confidence_level="Low to Medium - high entropy has many legitimate causes",
            educational_context="Entropy is a mathematical concept used in cybersecurity to identify files that may be hiding their true nature through encryption or compression.",
            learning_objectives=[
                "Understand the concept of entropy in data analysis",
                "Learn about file obfuscation techniques",
                "Recognize legitimate vs. suspicious high-entropy content",
                "Appreciate mathematical approaches to security"
            ],
            further_reading=[
                "Information theory and entropy",
                "Malware packing and obfuscation",
                "Statistical analysis in cybersecurity"
            ]
        )
        
        self.detection_explanations[DetectionMethod.PATTERN_RECOGNITION] = DetectionExplanation(
            detection_method=DetectionMethod.PATTERN_RECOGNITION,
            method_description="Pattern recognition identifies suspicious patterns in file names, extensions, structures, or metadata.",
            why_flagged="The file matches patterns commonly associated with malicious software or suspicious activity.",
            confidence_level="Medium - patterns can indicate threats but may have false positives",
            educational_context="Pattern recognition helps identify threats based on common characteristics and naming conventions used by malware authors.",
            learning_objectives=[
                "Understand pattern-based threat identification",
                "Learn about common malware characteristics",
                "Recognize social engineering in file naming",
                "Appreciate the role of metadata in security"
            ],
            further_reading=[
                "Malware naming conventions",
                "Social engineering in cybersecurity",
                "File metadata analysis"
            ]
        )
    
    def get_threat_info(self, threat_name: str) -> Optional[ThreatInfo]:
        """Get educational information about a specific threat.
        
        Args:
            threat_name: Name of the threat to look up
            
        Returns:
            ThreatInfo object if found, None otherwise
        """
        # Try exact match first
        if threat_name in self.threat_info:
            return self.threat_info[threat_name]
        
        # Try partial matching for similar threats
        threat_name_lower = threat_name.lower()
        for key, info in self.threat_info.items():
            if threat_name_lower in key.lower() or key.lower() in threat_name_lower:
                return info
        
        # Try category-based matching
        for info in self.threat_info.values():
            if any(keyword in threat_name_lower for keyword in [
                'eicar', 'test', 'entropy', 'suspicious', 'behavioral', 'signature'
            ]):
                if info.category == ThreatCategory.TEST_FILE and 'test' in threat_name_lower:
                    return info
                elif info.category == ThreatCategory.SUSPICIOUS_BEHAVIOR and 'suspicious' in threat_name_lower:
                    return info
        
        return None
    
    def get_detection_explanation(self, detection: Detection) -> DetectionExplanation:
        """Get explanation for how a detection was made.
        
        Args:
            detection: Detection object to explain
            
        Returns:
            DetectionExplanation object
        """
        # Determine detection method based on detection type and details
        if detection.detection_type == DetectionType.SIGNATURE:
            method = DetectionMethod.SIGNATURE_MATCHING
        elif detection.detection_type == DetectionType.BEHAVIORAL:
            # Check details for specific behavioral indicators
            details = detection.details or {}
            if 'entropy' in details and details.get('entropy', 0) > 7:
                method = DetectionMethod.ENTROPY_ANALYSIS
            elif 'suspicious_patterns' in details:
                method = DetectionMethod.PATTERN_RECOGNITION
            else:
                method = DetectionMethod.BEHAVIORAL_ANALYSIS
        else:
            method = DetectionMethod.HEURISTIC_ANALYSIS
        
        # Get base explanation
        base_explanation = self.detection_explanations.get(method)
        if not base_explanation:
            # Create a generic explanation
            return DetectionExplanation(
                detection_method=method,
                method_description="Detection method analysis not available.",
                why_flagged=f"File flagged by {detection.detection_type.value} detection with risk score {detection.risk_score}.",
                confidence_level="Unknown",
                educational_context="This detection requires further analysis to determine the specific method used.",
                learning_objectives=["Investigate detection methods", "Analyze threat characteristics"]
            )
        
        # Customize explanation based on specific detection details
        customized_explanation = DetectionExplanation(
            detection_method=base_explanation.detection_method,
            method_description=base_explanation.method_description,
            why_flagged=self._customize_why_flagged(detection, base_explanation.why_flagged),
            confidence_level=base_explanation.confidence_level,
            educational_context=base_explanation.educational_context,
            learning_objectives=base_explanation.learning_objectives,
            further_reading=base_explanation.further_reading
        )
        
        return customized_explanation
    
    def _customize_why_flagged(self, detection: Detection, base_reason: str) -> str:
        """Customize the 'why flagged' explanation based on detection details.
        
        Args:
            detection: Detection object
            base_reason: Base explanation text
            
        Returns:
            Customized explanation
        """
        details = detection.details or {}
        custom_parts = [base_reason]
        
        # Add specific details based on detection type
        if detection.detection_type == DetectionType.SIGNATURE:
            if detection.signature_id:
                custom_parts.append(f"Specific signature ID: {detection.signature_id}")
        
        elif detection.detection_type == DetectionType.BEHAVIORAL:
            if 'entropy' in details:
                entropy = details['entropy']
                custom_parts.append(f"File entropy: {entropy:.2f} (threshold: {details.get('behavioral_threshold', 7)})")
            
            if 'suspicious_patterns' in details and details['suspicious_patterns']:
                patterns = details['suspicious_patterns']
                custom_parts.append(f"Suspicious patterns found: {', '.join(patterns[:3])}")
        
        # Add risk score context
        risk_score = detection.risk_score
        if risk_score >= 8:
            custom_parts.append(f"High risk score ({risk_score}/10) indicates significant threat potential.")
        elif risk_score >= 5:
            custom_parts.append(f"Medium risk score ({risk_score}/10) suggests caution is warranted.")
        else:
            custom_parts.append(f"Low risk score ({risk_score}/10) indicates minimal threat level.")
        
        return " ".join(custom_parts)
    
    def get_all_threat_categories(self) -> List[ThreatCategory]:
        """Get all available threat categories.
        
        Returns:
            List of ThreatCategory enums
        """
        return list(ThreatCategory)
    
    def get_threats_by_category(self, category: ThreatCategory) -> List[ThreatInfo]:
        """Get all threats in a specific category.
        
        Args:
            category: ThreatCategory to filter by
            
        Returns:
            List of ThreatInfo objects in the category
        """
        return [info for info in self.threat_info.values() if info.category == category]
    
    def search_threats(self, query: str) -> List[ThreatInfo]:
        """Search for threats by name or description.
        
        Args:
            query: Search query string
            
        Returns:
            List of matching ThreatInfo objects
        """
        query_lower = query.lower()
        matches = []
        
        for info in self.threat_info.values():
            if (query_lower in info.threat_name.lower() or
                query_lower in info.description.lower() or
                query_lower in info.educational_notes.lower()):
                matches.append(info)
        
        return matches
    
    def add_custom_threat_info(self, threat_info: ThreatInfo) -> None:
        """Add custom threat information to the database.
        
        Args:
            threat_info: ThreatInfo object to add
        """
        self.threat_info[threat_info.threat_name] = threat_info
        logger.info(f"Added custom threat info: {threat_info.threat_name}")
    
    def export_database(self, file_path: str) -> None:
        """Export the educational database to a JSON file.
        
        Args:
            file_path: Path to save the database
        """
        export_data = {
            'threat_info': {name: info.to_dict() for name, info in self.threat_info.items()},
            'detection_explanations': {
                method.value: explanation.to_dict() 
                for method, explanation in self.detection_explanations.items()
            }
        }
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Educational database exported to: {file_path}")
    
    def import_database(self, file_path: str) -> None:
        """Import educational database from a JSON file.
        
        Args:
            file_path: Path to the database file
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            # Import threat info
            if 'threat_info' in import_data:
                for name, data in import_data['threat_info'].items():
                    threat_info = ThreatInfo(
                        threat_name=data['threat_name'],
                        category=ThreatCategory(data['category']),
                        description=data['description'],
                        how_it_works=data['how_it_works'],
                        potential_damage=data['potential_damage'],
                        prevention_tips=data['prevention_tips'],
                        detection_methods=[DetectionMethod(m) for m in data['detection_methods']],
                        severity_level=data['severity_level'],
                        educational_notes=data['educational_notes'],
                        real_world_examples=data.get('real_world_examples', []),
                        related_threats=data.get('related_threats', [])
                    )
                    self.threat_info[name] = threat_info
            
            # Import detection explanations
            if 'detection_explanations' in import_data:
                for method_str, data in import_data['detection_explanations'].items():
                    method = DetectionMethod(method_str)
                    explanation = DetectionExplanation(
                        detection_method=method,
                        method_description=data['method_description'],
                        why_flagged=data['why_flagged'],
                        confidence_level=data['confidence_level'],
                        educational_context=data['educational_context'],
                        learning_objectives=data['learning_objectives'],
                        further_reading=data.get('further_reading', [])
                    )
                    self.detection_explanations[method] = explanation
            
            logger.info(f"Educational database imported from: {file_path}")
            
        except Exception as e:
            logger.error(f"Failed to import educational database: {e}")
            raise


class EducationalContentDisplay:
    """System for displaying educational content to users."""
    
    def __init__(self, database: Optional[EducationalDatabase] = None):
        """Initialize the display system.
        
        Args:
            database: Educational database to use (creates default if None)
        """
        self.database = database or EducationalDatabase()
    
    def format_threat_explanation(self, detection: Detection) -> str:
        """Format a comprehensive threat explanation for display.
        
        Args:
            detection: Detection to explain
            
        Returns:
            Formatted explanation text
        """
        lines = []
        
        # Header
        lines.append("=" * 60)
        lines.append("THREAT DETECTION EXPLANATION")
        lines.append("=" * 60)
        lines.append(f"File: {detection.file_path}")
        lines.append(f"Threat: {detection.threat_name}")
        lines.append(f"Risk Score: {detection.risk_score}/10")
        lines.append(f"Detection Time: {detection.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # Get threat information
        threat_info = self.database.get_threat_info(detection.threat_name)
        if threat_info:
            lines.append("THREAT INFORMATION")
            lines.append("-" * 30)
            lines.append(f"Category: {threat_info.category.value.title()}")
            lines.append(f"Severity Level: {threat_info.severity_level}/10")
            lines.append("")
            lines.append("Description:")
            lines.append(threat_info.description)
            lines.append("")
            lines.append("How it works:")
            lines.append(threat_info.how_it_works)
            lines.append("")
            lines.append("Potential damage:")
            lines.append(threat_info.potential_damage)
            lines.append("")
            
            if threat_info.prevention_tips:
                lines.append("Prevention tips:")
                for tip in threat_info.prevention_tips:
                    lines.append(f"  • {tip}")
                lines.append("")
        
        # Get detection explanation
        detection_explanation = self.database.get_detection_explanation(detection)
        lines.append("DETECTION METHOD EXPLANATION")
        lines.append("-" * 30)
        lines.append(f"Method: {detection_explanation.detection_method.value.replace('_', ' ').title()}")
        lines.append(f"Confidence: {detection_explanation.confidence_level}")
        lines.append("")
        lines.append("How detection works:")
        lines.append(detection_explanation.method_description)
        lines.append("")
        lines.append("Why this file was flagged:")
        lines.append(detection_explanation.why_flagged)
        lines.append("")
        lines.append("Educational context:")
        lines.append(detection_explanation.educational_context)
        lines.append("")
        
        if detection_explanation.learning_objectives:
            lines.append("Learning objectives:")
            for objective in detection_explanation.learning_objectives:
                lines.append(f"  • {objective}")
            lines.append("")
        
        # Additional details from detection
        if detection.details:
            lines.append("TECHNICAL DETAILS")
            lines.append("-" * 30)
            for key, value in detection.details.items():
                if key not in ['behavioral_threshold']:  # Skip internal thresholds
                    lines.append(f"{key.replace('_', ' ').title()}: {value}")
            lines.append("")
        
        # Educational notes
        if threat_info and threat_info.educational_notes:
            lines.append("EDUCATIONAL NOTES")
            lines.append("-" * 30)
            lines.append(threat_info.educational_notes)
            lines.append("")
        
        # Related information
        if threat_info and (threat_info.related_threats or threat_info.real_world_examples):
            lines.append("ADDITIONAL INFORMATION")
            lines.append("-" * 30)
            
            if threat_info.related_threats:
                lines.append("Related threats:")
                for related in threat_info.related_threats:
                    lines.append(f"  • {related}")
                lines.append("")
            
            if threat_info.real_world_examples:
                lines.append("Real-world examples:")
                for example in threat_info.real_world_examples:
                    lines.append(f"  • {example}")
                lines.append("")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def format_threat_summary(self, detection: Detection) -> str:
        """Format a brief threat summary for display.
        
        Args:
            detection: Detection to summarize
            
        Returns:
            Brief summary text
        """
        threat_info = self.database.get_threat_info(detection.threat_name)
        detection_explanation = self.database.get_detection_explanation(detection)
        
        summary_parts = [
            f"🚨 {detection.threat_name} (Risk: {detection.risk_score}/10)",
            f"📁 File: {detection.file_path}",
            f"🔍 Method: {detection_explanation.detection_method.value.replace('_', ' ').title()}",
        ]
        
        if threat_info:
            summary_parts.append(f"📋 Category: {threat_info.category.value.title()}")
            summary_parts.append(f"💡 {threat_info.description}")
        
        return "\n".join(summary_parts)
    
    def list_available_educational_content(self) -> str:
        """List all available educational content.
        
        Returns:
            Formatted list of available content
        """
        lines = []
        lines.append("AVAILABLE EDUCATIONAL CONTENT")
        lines.append("=" * 50)
        lines.append("")
        
        # Group threats by category
        categories = {}
        for threat_info in self.database.threat_info.values():
            category = threat_info.category
            if category not in categories:
                categories[category] = []
            categories[category].append(threat_info)
        
        for category, threats in categories.items():
            lines.append(f"{category.value.upper().replace('_', ' ')}")
            lines.append("-" * 30)
            for threat in sorted(threats, key=lambda x: x.threat_name):
                lines.append(f"  • {threat.threat_name} (Severity: {threat.severity_level}/10)")
                lines.append(f"    {threat.description[:80]}...")
            lines.append("")
        
        lines.append("DETECTION METHODS")
        lines.append("-" * 30)
        for method, explanation in self.database.detection_explanations.items():
            lines.append(f"  • {method.value.replace('_', ' ').title()}")
            lines.append(f"    {explanation.method_description[:80]}...")
        
        return "\n".join(lines)
    
    def get_learning_recommendations(self, detections: List[Detection]) -> str:
        """Generate learning recommendations based on detections.
        
        Args:
            detections: List of detections to analyze
            
        Returns:
            Formatted learning recommendations
        """
        lines = []
        lines.append("LEARNING RECOMMENDATIONS")
        lines.append("=" * 40)
        lines.append("")
        
        if not detections:
            lines.append("No detections found. Consider:")
            lines.append("  • Creating test samples to practice with")
            lines.append("  • Learning about different threat types")
            lines.append("  • Understanding detection methods")
            return "\n".join(lines)
        
        # Analyze detection patterns
        detection_methods = set()
        threat_categories = set()
        risk_levels = []
        
        for detection in detections:
            explanation = self.database.get_detection_explanation(detection)
            detection_methods.add(explanation.detection_method)
            
            threat_info = self.database.get_threat_info(detection.threat_name)
            if threat_info:
                threat_categories.add(threat_info.category)
            
            risk_levels.append(detection.risk_score)
        
        # Generate recommendations
        lines.append("Based on your scan results, consider learning about:")
        lines.append("")
        
        # Method-specific recommendations
        if DetectionMethod.SIGNATURE_MATCHING in detection_methods:
            lines.append("📝 SIGNATURE-BASED DETECTION:")
            lines.append("  • How antivirus signatures are created")
            lines.append("  • Limitations of signature-only detection")
            lines.append("  • The importance of signature database updates")
            lines.append("")
        
        if DetectionMethod.BEHAVIORAL_ANALYSIS in detection_methods:
            lines.append("🔍 BEHAVIORAL ANALYSIS:")
            lines.append("  • Heuristic detection techniques")
            lines.append("  • How behavioral patterns indicate threats")
            lines.append("  • Balancing detection accuracy with false positives")
            lines.append("")
        
        if DetectionMethod.ENTROPY_ANALYSIS in detection_methods:
            lines.append("📊 ENTROPY ANALYSIS:")
            lines.append("  • Mathematical concepts in cybersecurity")
            lines.append("  • How malware uses obfuscation")
            lines.append("  • Legitimate vs. suspicious high-entropy content")
            lines.append("")
        
        # Risk-based recommendations
        avg_risk = sum(risk_levels) / len(risk_levels) if risk_levels else 0
        if avg_risk >= 7:
            lines.append("⚠️  HIGH-RISK DETECTIONS FOUND:")
            lines.append("  • Learn about incident response procedures")
            lines.append("  • Study advanced threat analysis techniques")
            lines.append("  • Understand quarantine and remediation")
        elif avg_risk >= 4:
            lines.append("⚡ MEDIUM-RISK DETECTIONS:")
            lines.append("  • Practice threat assessment skills")
            lines.append("  • Learn about risk scoring methodologies")
            lines.append("  • Study false positive analysis")
        else:
            lines.append("✅ LOW-RISK DETECTIONS:")
            lines.append("  • Good for learning basic concepts")
            lines.append("  • Practice with more challenging samples")
            lines.append("  • Explore advanced detection techniques")
        
        lines.append("")
        lines.append("💡 NEXT STEPS:")
        lines.append("  • Review the detailed explanations for each detection")
        lines.append("  • Create additional test samples for practice")
        lines.append("  • Experiment with different detection settings")
        lines.append("  • Study real-world cybersecurity case studies")
        
        return "\n".join(lines)