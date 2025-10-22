"""
Behavioral Analysis Engine for the Educational Antivirus Research Tool.

This module implements heuristic-based detection using file characteristics
and behavioral patterns to identify potentially suspicious files.
"""
import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from core.models import BehavioralResult, FileInfo, Config
from core.file_utils import extract_file_metadata, analyze_file_characteristics
from core.exceptions import ScanError
from .risk_scorer import AdvancedRiskScorer, RiskAssessment


@dataclass
class SuspiciousPattern:
    """Represents a suspicious pattern found in file analysis."""
    pattern_type: str
    description: str
    severity: int  # 1-10 scale
    details: Dict[str, Any] = field(default_factory=dict)


class BehavioralAnalysisEngine:
    """
    Behavioral analysis engine that performs heuristic-based detection.
    
    This engine analyzes file characteristics such as entropy, file structure,
    naming patterns, and other behavioral indicators to assess risk levels.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the behavioral analysis engine.
        
        Args:
            config: Configuration object with analysis settings
        """
        self.config = config or Config()
        self._suspicious_patterns = self._load_suspicious_patterns()
        self._risk_weights = self._load_risk_weights()
        self._advanced_scorer = AdvancedRiskScorer(config)
    
    def analyze_file(self, file_path: str) -> BehavioralResult:
        """
        Perform comprehensive behavioral analysis on a file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            BehavioralResult with risk score and analysis details
            
        Raises:
            ScanError: If file analysis fails
        """
        try:
            # Extract file metadata
            file_info = extract_file_metadata(file_path)
            
            # Analyze file characteristics
            characteristics = analyze_file_characteristics(file_info)
            
            # Detect suspicious patterns
            suspicious_patterns = self._detect_suspicious_patterns(file_info, characteristics)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(file_info, characteristics, suspicious_patterns)
            
            # Prepare analysis details
            analysis_details = self._prepare_analysis_details(
                file_info, characteristics, suspicious_patterns, risk_score
            )
            
            return BehavioralResult(
                file_path=file_path,
                risk_score=risk_score,
                entropy=file_info.entropy,
                suspicious_patterns=[p.description for p in suspicious_patterns],
                analysis_details=analysis_details
            )
            
        except Exception as e:
            raise ScanError(f"Behavioral analysis failed for {file_path}: {e}")
    
    def _detect_suspicious_patterns(self, file_info: FileInfo, characteristics: Dict[str, Any]) -> List[SuspiciousPattern]:
        """
        Detect suspicious patterns in file characteristics.
        
        Args:
            file_info: File metadata
            characteristics: Analyzed file characteristics
            
        Returns:
            List of detected suspicious patterns
        """
        patterns = []
        
        # High entropy pattern
        if characteristics['high_entropy']:
            patterns.append(SuspiciousPattern(
                pattern_type="high_entropy",
                description=f"High entropy ({file_info.entropy:.2f}) suggests encrypted/compressed data",
                severity=6,
                details={"entropy": file_info.entropy, "threshold": self.config.entropy_threshold}
            ))
        
        # Suspicious file type pattern
        if characteristics['is_suspicious_type']:
            patterns.append(SuspiciousPattern(
                pattern_type="suspicious_extension",
                description=f"Potentially dangerous file type: {Path(file_info.path).suffix}",
                severity=7,
                details={"extension": Path(file_info.path).suffix, "file_type": file_info.file_type}
            ))
        
        # Double extension pattern
        if characteristics['has_double_extension']:
            patterns.append(SuspiciousPattern(
                pattern_type="double_extension",
                description="File has multiple extensions (possible disguise attempt)",
                severity=8,
                details={"extensions": Path(file_info.path).suffixes}
            ))
        
        # Hidden file pattern
        if characteristics['is_hidden']:
            patterns.append(SuspiciousPattern(
                pattern_type="hidden_file",
                description="Hidden file (starts with dot)",
                severity=4,
                details={"filename": Path(file_info.path).name}
            ))
        
        # Executable with suspicious characteristics
        if characteristics['is_executable'] and characteristics['high_entropy']:
            patterns.append(SuspiciousPattern(
                pattern_type="packed_executable",
                description="Executable with high entropy (possibly packed/obfuscated)",
                severity=9,
                details={"entropy": file_info.entropy, "file_type": file_info.file_type}
            ))
        
        # Suspicious file size patterns
        size_patterns = self._analyze_size_patterns(file_info, characteristics)
        patterns.extend(size_patterns)
        
        # Suspicious naming patterns
        naming_patterns = self._analyze_naming_patterns(file_info)
        patterns.extend(naming_patterns)
        
        # Permission-based patterns
        permission_patterns = self._analyze_permission_patterns(file_info)
        patterns.extend(permission_patterns)
        
        return patterns
    
    def _analyze_size_patterns(self, file_info: FileInfo, characteristics: Dict[str, Any]) -> List[SuspiciousPattern]:
        """Analyze file size for suspicious patterns."""
        patterns = []
        
        # Empty executable files are suspicious
        if file_info.size == 0 and characteristics['is_executable']:
            patterns.append(SuspiciousPattern(
                pattern_type="empty_executable",
                description="Empty executable file",
                severity=8,
                details={"size": file_info.size, "file_type": file_info.file_type}
            ))
        
        # Very small executables might be droppers
        elif file_info.size < 1024 and characteristics['is_executable']:
            patterns.append(SuspiciousPattern(
                pattern_type="tiny_executable",
                description="Unusually small executable (possible dropper)",
                severity=6,
                details={"size": file_info.size, "size_category": characteristics['size_category']}
            ))
        
        # Very large files might be suspicious
        elif characteristics['size_category'] == 'very_large':
            patterns.append(SuspiciousPattern(
                pattern_type="oversized_file",
                description="Unusually large file size",
                severity=3,
                details={"size": file_info.size, "size_mb": file_info.size / (1024 * 1024)}
            ))
        
        return patterns
    
    def _analyze_naming_patterns(self, file_info: FileInfo) -> List[SuspiciousPattern]:
        """Analyze filename for suspicious patterns."""
        patterns = []
        filename = Path(file_info.path).name.lower()
        
        # Common malware naming patterns
        suspicious_names = [
            r'.*virus.*', r'.*trojan.*', r'.*worm.*', r'.*backdoor.*',
            r'.*keylog.*', r'.*crack.*', r'.*patch.*', r'.*keygen.*',
            r'.*loader.*', r'.*inject.*', r'.*payload.*', r'.*exploit.*'
        ]
        
        for pattern in suspicious_names:
            if re.match(pattern, filename):
                patterns.append(SuspiciousPattern(
                    pattern_type="suspicious_filename",
                    description=f"Filename contains suspicious keyword: {pattern}",
                    severity=7,
                    details={"filename": filename, "pattern": pattern}
                ))
                break
        
        # Random-looking filenames (high ratio of consonants/numbers)
        if self._is_random_filename(filename):
            patterns.append(SuspiciousPattern(
                pattern_type="random_filename",
                description="Filename appears randomly generated",
                severity=5,
                details={"filename": filename}
            ))
        
        # System file impersonation
        system_files = ['system32', 'winlogon', 'explorer', 'svchost', 'lsass']
        for sys_file in system_files:
            if sys_file in filename and not file_info.path.lower().startswith('c:\\windows'):
                patterns.append(SuspiciousPattern(
                    pattern_type="system_impersonation",
                    description=f"Filename mimics system file: {sys_file}",
                    severity=8,
                    details={"filename": filename, "system_file": sys_file}
                ))
        
        return patterns
    
    def _analyze_permission_patterns(self, file_info: FileInfo) -> List[SuspiciousPattern]:
        """Analyze file permissions for suspicious patterns."""
        patterns = []
        
        # World-writable executables are suspicious
        if 'x' in file_info.permissions and file_info.permissions[8] == 'w':
            patterns.append(SuspiciousPattern(
                pattern_type="world_writable_executable",
                description="Executable file is world-writable",
                severity=7,
                details={"permissions": file_info.permissions}
            ))
        
        # Files with unusual permission combinations
        if file_info.permissions == 'rwxrwxrwx':
            patterns.append(SuspiciousPattern(
                pattern_type="overly_permissive",
                description="File has overly permissive permissions (777)",
                severity=6,
                details={"permissions": file_info.permissions}
            ))
        
        return patterns
    
    def _is_random_filename(self, filename: str) -> bool:
        """Check if filename appears randomly generated."""
        # Remove extension for analysis
        name_part = Path(filename).stem
        
        if len(name_part) < 6:
            return False
        
        # Count vowels vs consonants
        vowels = 'aeiou'
        vowel_count = sum(1 for c in name_part.lower() if c in vowels)
        consonant_count = sum(1 for c in name_part.lower() if c.isalpha() and c not in vowels)
        digit_count = sum(1 for c in name_part if c.isdigit())
        
        total_chars = len(name_part)
        
        # Random-looking if:
        # - High ratio of digits
        # - Very low vowel ratio
        # - Mix of case with numbers
        if digit_count / total_chars > 0.4:
            return True
        
        if vowel_count > 0 and consonant_count / vowel_count > 4:
            return True
        
        return False
    
    def _calculate_risk_score(self, file_info: FileInfo, characteristics: Dict[str, Any], 
                            patterns: List[SuspiciousPattern]) -> int:
        """
        Calculate overall risk score based on analysis results.
        
        Args:
            file_info: File metadata
            characteristics: File characteristics
            patterns: Detected suspicious patterns
            
        Returns:
            Risk score from 1-10
        """
        base_score = 1
        
        # Add points for each suspicious pattern weighted by severity
        pattern_score = sum(pattern.severity for pattern in patterns)
        
        # Apply weights based on file characteristics
        if characteristics['is_executable']:
            pattern_score *= self._risk_weights['executable_multiplier']
        
        if characteristics['high_entropy']:
            pattern_score *= self._risk_weights['entropy_multiplier']
        
        if characteristics['is_suspicious_type']:
            pattern_score *= self._risk_weights['suspicious_type_multiplier']
        
        # Calculate final score
        final_score = base_score + (pattern_score * self._risk_weights['pattern_weight'])
        
        # Normalize to 1-10 scale
        return min(10, max(1, int(final_score)))
    
    def _prepare_analysis_details(self, file_info: FileInfo, characteristics: Dict[str, Any],
                                patterns: List[SuspiciousPattern], risk_score: int) -> Dict[str, Any]:
        """Prepare detailed analysis information."""
        return {
            'file_characteristics': characteristics,
            'entropy_analysis': {
                'entropy': file_info.entropy,
                'threshold': self.config.entropy_threshold,
                'is_high': characteristics['high_entropy']
            },
            'pattern_analysis': {
                'total_patterns': len(patterns),
                'pattern_details': [
                    {
                        'type': p.pattern_type,
                        'description': p.description,
                        'severity': p.severity,
                        'details': p.details
                    }
                    for p in patterns
                ]
            },
            'risk_assessment': {
                'score': risk_score,
                'threshold': self.config.behavioral_threshold,
                'is_suspicious': risk_score >= self.config.behavioral_threshold
            },
            'file_metadata': {
                'size': file_info.size,
                'type': file_info.file_type,
                'permissions': file_info.permissions,
                'creation_time': file_info.creation_time.isoformat(),
                'modification_time': file_info.modification_time.isoformat()
            }
        }
    
    def _load_suspicious_patterns(self) -> Dict[str, Any]:
        """Load configuration for suspicious pattern detection."""
        return {
            'entropy_threshold': self.config.entropy_threshold,
            'suspicious_extensions': self.config.suspicious_extensions,
            'max_file_size': self.config.max_file_size_mb * 1024 * 1024
        }
    
    def _load_risk_weights(self) -> Dict[str, float]:
        """Load risk calculation weights."""
        return {
            'pattern_weight': 0.3,
            'executable_multiplier': 1.5,
            'entropy_multiplier': 1.3,
            'suspicious_type_multiplier': 1.4
        }
    
    def get_analysis_details(self, file_path: str) -> Dict[str, Any]:
        """
        Get detailed analysis information for educational purposes.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Detailed analysis information
        """
        result = self.analyze_file(file_path)
        return result.analysis_details
    
    def is_file_suspicious(self, file_path: str) -> bool:
        """
        Quick check if file is suspicious based on behavioral analysis.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file is considered suspicious
        """
        try:
            result = self.analyze_file(file_path)
            return result.risk_score >= self.config.behavioral_threshold
        except Exception:
            return False
    
    def get_comprehensive_assessment(self, file_path: str) -> RiskAssessment:
        """
        Get comprehensive risk assessment using advanced scoring.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Comprehensive risk assessment with detailed analysis
        """
        try:
            # Extract file metadata
            file_info = extract_file_metadata(file_path)
            
            # Analyze file characteristics
            characteristics = analyze_file_characteristics(file_info)
            
            # Detect suspicious patterns
            suspicious_patterns = self._detect_suspicious_patterns(file_info, characteristics)
            
            # Get comprehensive assessment
            return self._advanced_scorer.calculate_comprehensive_risk(
                file_info, characteristics, suspicious_patterns
            )
            
        except Exception as e:
            raise ScanError(f"Comprehensive assessment failed for {file_path}: {e}")
    
    def update_config(self, config: Config) -> None:
        """
        Update engine configuration.
        
        Args:
            config: New configuration object
        """
        self.config = config
        self._suspicious_patterns = self._load_suspicious_patterns()
        self._risk_weights = self._load_risk_weights()
        self._advanced_scorer = AdvancedRiskScorer(config)