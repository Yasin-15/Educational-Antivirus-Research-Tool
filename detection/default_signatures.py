"""
Default signatures for educational purposes.
"""
from datetime import datetime
from typing import List

from .signature_models import Signature, SignatureType


def get_default_signatures() -> List[Signature]:
    """Get a list of default educational signatures.
    
    Returns:
        List of default Signature objects for educational use
    """
    signatures = []
    
    # EICAR test signatures
    signatures.append(Signature(
        signature_id="eicar_standard",
        name="EICAR Standard Test",
        signature_type=SignatureType.EICAR,
        pattern=b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
        description="Standard EICAR antivirus test string - completely harmless",
        threat_category="Test File",
        severity=1,
        metadata={
            "educational": True,
            "harmless": True,
            "reference": "https://www.eicar.org/",
            "purpose": "Antivirus testing"
        }
    ))
    
    # Suspicious file patterns (educational)
    signatures.append(Signature(
        signature_id="suspicious_autorun",
        name="Suspicious Autorun.inf",
        signature_type=SignatureType.PATTERN_MATCH,
        pattern=b'\\[autorun\\].*open=.*\\.exe',
        description="Detects autorun.inf files that automatically execute programs",
        threat_category="Suspicious Behavior",
        severity=6,
        metadata={
            "educational": True,
            "file_type": "autorun.inf",
            "explanation": "Autorun files can be used to automatically execute malware when removable media is inserted"
        }
    ))
    
    signatures.append(Signature(
        signature_id="batch_file_suspicious",
        name="Suspicious Batch Commands",
        signature_type=SignatureType.PATTERN_MATCH,
        pattern=b'(del|format|rmdir).*\\*.*',
        description="Detects batch files with potentially destructive commands",
        threat_category="Suspicious Script",
        severity=7,
        metadata={
            "educational": True,
            "file_type": "batch",
            "explanation": "Batch files with wildcard deletion commands can be used to destroy data"
        }
    ))
    
    # Educational malware signatures (harmless patterns)
    signatures.append(Signature(
        signature_id="educational_trojan_sim",
        name="Educational Trojan Simulator",
        signature_type=SignatureType.EXACT_MATCH,
        pattern=b'EDUCATIONAL_TROJAN_SIGNATURE_DO_NOT_EXECUTE',
        description="Harmless educational signature simulating trojan detection",
        threat_category="Educational Malware",
        severity=8,
        metadata={
            "educational": True,
            "harmless": True,
            "malware_type": "Trojan",
            "explanation": "This signature simulates how antivirus software detects known trojan patterns"
        }
    ))
    
    signatures.append(Signature(
        signature_id="educational_worm_sim",
        name="Educational Worm Simulator",
        signature_type=SignatureType.EXACT_MATCH,
        pattern=b'EDUCATIONAL_WORM_REPLICATION_PATTERN_HARMLESS',
        description="Harmless educational signature simulating worm detection",
        threat_category="Educational Malware",
        severity=9,
        metadata={
            "educational": True,
            "harmless": True,
            "malware_type": "Worm",
            "explanation": "This signature demonstrates how worms are identified by their replication patterns"
        }
    ))
    
    # Suspicious registry patterns
    signatures.append(Signature(
        signature_id="registry_startup_mod",
        name="Registry Startup Modification",
        signature_type=SignatureType.PATTERN_MATCH,
        pattern=b'HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
        description="Detects attempts to modify Windows startup registry keys",
        threat_category="System Modification",
        severity=5,
        metadata={
            "educational": True,
            "registry_key": "Run",
            "explanation": "Malware often adds itself to startup registry keys for persistence"
        }
    ))
    
    # Suspicious PowerShell patterns
    signatures.append(Signature(
        signature_id="powershell_encoded",
        name="Encoded PowerShell Command",
        signature_type=SignatureType.PATTERN_MATCH,
        pattern=b'powershell.*-EncodedCommand',
        description="Detects PowerShell commands with encoded payloads",
        threat_category="Suspicious Script",
        severity=7,
        metadata={
            "educational": True,
            "script_type": "PowerShell",
            "explanation": "Encoded PowerShell commands are often used to hide malicious activities"
        }
    ))
    
    # Network-related suspicious patterns
    signatures.append(Signature(
        signature_id="suspicious_url_pattern",
        name="Suspicious URL Pattern",
        signature_type=SignatureType.PATTERN_MATCH,
        pattern=b'http://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+',
        description="Detects hardcoded IP addresses in URLs (suspicious behavior)",
        threat_category="Network Activity",
        severity=4,
        metadata={
            "educational": True,
            "network_indicator": True,
            "explanation": "Malware often uses IP addresses instead of domain names to avoid DNS filtering"
        }
    ))
    
    # File extension spoofing
    signatures.append(Signature(
        signature_id="extension_spoofing",
        name="File Extension Spoofing",
        signature_type=SignatureType.PATTERN_MATCH,
        pattern=b'\\.(jpg|png|pdf|doc)\\.exe',
        description="Detects files that appear to be documents but are actually executables",
        threat_category="Social Engineering",
        severity=8,
        metadata={
            "educational": True,
            "social_engineering": True,
            "explanation": "Attackers often disguise executables as innocent file types to trick users"
        }
    ))
    
    # Educational virus signature
    signatures.append(Signature(
        signature_id="educational_virus_sim",
        name="Educational Virus Simulator",
        signature_type=SignatureType.EXACT_MATCH,
        pattern=b'EDUCATIONAL_VIRUS_INFECTION_MARKER_HARMLESS_DEMO',
        description="Harmless educational signature simulating virus detection",
        threat_category="Educational Malware",
        severity=10,
        metadata={
            "educational": True,
            "harmless": True,
            "malware_type": "Virus",
            "explanation": "This demonstrates how viruses leave infection markers in files they modify"
        }
    ))
    
    return signatures


def get_eicar_variants() -> List[bytes]:
    """Get EICAR test string variants.
    
    Returns:
        List of EICAR test string variants as bytes
    """
    return [
        b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
        b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\x00',
        # Lowercase variant
        b'x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar-standard-antivirus-test-file!$h+h*'
    ]


def create_educational_test_patterns() -> List[bytes]:
    """Create educational test patterns for demonstration.
    
    Returns:
        List of harmless test patterns
    """
    return [
        b'EDUCATIONAL_MALWARE_SIGNATURE_HARMLESS',
        b'TEST_VIRUS_PATTERN_FOR_LEARNING_ONLY',
        b'DEMO_TROJAN_SIGNATURE_NOT_REAL_MALWARE',
        b'EDUCATIONAL_WORM_PATTERN_COMPLETELY_SAFE',
        b'LEARNING_ROOTKIT_SIGNATURE_HARMLESS_DEMO'
    ]