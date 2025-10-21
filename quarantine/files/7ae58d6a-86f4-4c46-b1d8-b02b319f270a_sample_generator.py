"""
Sample generator for creating harmless test malware samples.
"""
import os
import random
import string
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.models import SampleInfo
from core.exceptions import AntivirusError


class SampleGeneratorError(AntivirusError):
    """Raised when sample generation fails."""
    pass


class SampleGenerator:
    """Generates harmless test samples for educational purposes."""
    
    def __init__(self, output_path: str = "samples/"):
        """Initialize the sample generator.
        
        Args:
            output_path: Directory to store generated samples
        """
        self.output_path = Path(output_path)
        self.output_path.mkdir(parents=True, exist_ok=True)
        
        # Available signature patterns for custom samples
        self.available_signatures = [
            "TestVirus-A",
            "TestVirus-B", 
            "TestTrojan-X",
            "TestWorm-Y",
            "TestAdware-Z"
        ]
        
        # Available behavioral triggers
        self.available_triggers = [
            "high_entropy",
            "suspicious_extension",
            "large_file",
            "packed_executable"
        ]
    
    def create_eicar_sample(self, filename: Optional[str] = None) -> SampleInfo:
        """Create EICAR standard antivirus test file.
        
        Args:
            filename: Optional custom filename
            
        Returns:
            SampleInfo object with sample metadata
            
        Raises:
            SampleGeneratorError: If sample creation fails
        """
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"eicar_{timestamp}.txt"
            
            # EICAR test string - completely harmless
            eicar_string = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            
            file_path = self.output_path / filename
            
            with open(file_path, 'w') as f:
                f.write(eicar_string)
            
            # Generate sample ID
            sample_id = f"eicar_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            return SampleInfo(
                sample_id=sample_id,
                name=filename,
                sample_type="eicar",
                description="EICAR Standard Antivirus Test File - Harmless test string recognized by all antivirus software",
                creation_date=datetime.now(),
                file_path=str(file_path),
                signatures=["EICAR-Test-File"]
            )
            
        except Exception as e:
            raise SampleGeneratorError(f"Failed to create EICAR sample: {e}")
    
    def create_custom_signature_sample(self, signature_name: str, filename: Optional[str] = None) -> SampleInfo:
        """Create a sample with custom signature pattern.
        
        Args:
            signature_name: Name of the signature to embed
            filename: Optional custom filename
            
        Returns:
            SampleInfo object with sample metadata
            
        Raises:
            SampleGeneratorError: If sample creation fails
        """
        try:
            if signature_name not in self.available_signatures:
                raise SampleGeneratorError(f"Unknown signature: {signature_name}. Available: {', '.join(self.available_signatures)}")
            
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"custom_{signature_name.lower()}_{timestamp}.txt"
            
            # Create harmless content with embedded signature pattern
            content = self._generate_harmless_content_with_signature(signature_name)
            
            file_path = self.output_path / filename
            
            with open(file_path, 'w') as f:
                f.write(content)
            
            # Generate sample ID
            sample_id = f"custom_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            return SampleInfo(
                sample_id=sample_id,
                name=filename,
                sample_type="custom_signature",
                description=f"Custom test sample with {signature_name} signature pattern - Harmless educational file",
                creation_date=datetime.now(),
                file_path=str(file_path),
                signatures=[signature_name]
            )
            
        except Exception as e:
            raise SampleGeneratorError(f"Failed to create custom signature sample: {e}")
    
    def create_behavioral_trigger_sample(self, trigger_type: str, filename: Optional[str] = None) -> SampleInfo:
        """Create a sample designed to trigger behavioral analysis.
        
        Args:
            trigger_type: Type of behavioral trigger
            filename: Optional custom filename
            
        Returns:
            SampleInfo object with sample metadata
            
        Raises:
            SampleGeneratorError: If sample creation fails
        """
        try:
            if trigger_type not in self.available_triggers:
                raise SampleGeneratorError(f"Unknown trigger type: {trigger_type}. Available: {', '.join(self.available_triggers)}")
            
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"behavioral_{trigger_type}_{timestamp}"
            
            # Generate content based on trigger type
            content, file_extension = self._generate_behavioral_trigger_content(trigger_type)
            
            if not filename.endswith(file_extension):
                filename += file_extension
            
            file_path = self.output_path / filename
            
            # Write content (binary or text depending on trigger type)
            if trigger_type == "high_entropy":
                with open(file_path, 'wb') as f:
                    f.write(content)
            else:
                with open(file_path, 'w') as f:
                    f.write(content)
            
            # Generate sample ID
            sample_id = f"behavioral_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            return SampleInfo(
                sample_id=sample_id,
                name=filename,
                sample_type="behavioral_trigger",
                description=f"Behavioral analysis trigger sample ({trigger_type}) - Harmless file designed to test heuristic detection",
                creation_date=datetime.now(),
                file_path=str(file_path),
                signatures=[f"Behavioral-{trigger_type}"]
            )
            
        except Exception as e:
            raise SampleGeneratorError(f"Failed to create behavioral trigger sample: {e}")
    
    def get_available_signatures(self) -> List[str]:
        """Get list of available signature types.
        
        Returns:
            List of signature names
        """
        return self.available_signatures.copy()
    
    def get_available_behavioral_triggers(self) -> List[str]:
        """Get list of available behavioral trigger types.
        
        Returns:
            List of trigger type names
        """
        return self.available_triggers.copy()
    
    def _generate_harmless_content_with_signature(self, signature_name: str) -> str:
        """Generate harmless content with embedded signature pattern."""
        # Create harmless text content with signature pattern embedded
        content_lines = [
            "This is a harmless test file for educational purposes.",
            "It contains no executable code or malicious content.",
            "",
            f"Embedded test signature: {signature_name}",
            "",
            "This file is used to demonstrate signature-based detection.",
            "It is completely safe and contains only text data.",
            "",
            "Educational Antivirus Research Tool",
            f"Generated on: {datetime.now().isoformat()}",
        ]
        
        return "\n".join(content_lines)
    
    def _generate_behavioral_trigger_content(self, trigger_type: str) -> tuple:
        """Generate content designed to trigger behavioral analysis.
        
        Returns:
            Tuple of (content, file_extension)
        """
        if trigger_type == "high_entropy":
            # Generate high-entropy binary data (appears random)
            content = bytes([random.randint(0, 255) for _ in range(1024)])
            return content, ".bin"
            
        elif trigger_type == "suspicious_extension":
            content = "This is a harmless test file with a suspicious extension.\n"
            content += "It contains no executable code.\n"
            content += f"Generated for educational purposes on {datetime.now().isoformat()}\n"
            return content, ".exe"
            
        elif trigger_type == "large_file":
            # Create a larger file that might trigger size-based heuristics
            content = "This is a harmless large test file.\n" * 1000
            content += f"Generated for educational purposes on {datetime.now().isoformat()}\n"
            return content, ".txt"
            
        elif trigger_type == "packed_executable":
            # Simulate packed executable characteristics (text representation)
            content = "PACKED_EXECUTABLE_SIMULATION\n"
            content += "This file simulates characteristics of packed executables.\n"
            content += "It is completely harmless and contains no executable code.\n"
            content += "UPX_SIGNATURE_SIMULATION\n"
            content += f"Generated for educational purposes on {datetime.now().isoformat()}\n"
            return content, ".exe"
            
        else:
            # Default case
            content = f"Behavioral trigger test file: {trigger_type}\n"
            content += f"Generated on {datetime.now().isoformat()}\n"
            return content, ".txt"