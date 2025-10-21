"""
Advanced Risk Scoring System for Behavioral Analysis.

This module provides sophisticated risk calculation algorithms with configurable
thresholds and detailed analysis reporting for educational purposes.
"""
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum
import math

from core.models import FileInfo, Config, BehavioralResult


class RiskCategory(Enum):
    """Risk level categories."""
    MINIMAL = "minimal"      # 1-2
    LOW = "low"             # 3-4
    MODERATE = "moderate"   # 5-6
    HIGH = "high"           # 7-8
    CRITICAL = "critical"   # 9-10


@dataclass
class RiskFactor:
    """Individual risk factor with weight and score."""
    name: str
    description: str
    score: float
    weight: float
    category: str
    details: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def weighted_score(self) -> float:
        """Calculate weighted contribution to total risk."""
        return self.score * self.weight


@dataclass
class RiskAssessment:
    """Comprehensive risk assessment result."""
    file_path: str
    total_score: int
    risk_category: RiskCategory
    confidence: float
    risk_factors: List[RiskFactor]
    threshold_analysis: Dict[str, Any]
    recommendations: List[str]
    educational_info: Dict[str, Any]


class AdvancedRiskScorer:
    """
    Advanced risk scoring system with configurable algorithms and thresholds.
    
    This class provides sophisticated risk calculation methods that consider
    multiple factors and their interactions to produce accurate risk assessments.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the advanced risk scorer.
        
        Args:
            config: Configuration object with scoring parameters
        """
        self.config = config or Config()
        self._risk_weights = self._initialize_risk_weights()
        self._threshold_config = self._initialize_thresholds()
        self._scoring_algorithms = self._initialize_algorithms()
    
    def calculate_comprehensive_risk(self, file_info: FileInfo, 
                                   characteristics: Dict[str, Any],
                                   suspicious_patterns: List[Any]) -> RiskAssessment:
        """
        Calculate comprehensive risk assessment with detailed analysis.
        
        Args:
            file_info: File metadata
            characteristics: File characteristics analysis
            suspicious_patterns: List of detected suspicious patterns
            
        Returns:
            Comprehensive risk assessment
        """
        # Calculate individual risk factors
        risk_factors = self._calculate_risk_factors(file_info, characteristics, suspicious_patterns)
        
        # Apply scoring algorithm
        total_score = self._apply_scoring_algorithm(risk_factors)
        
        # Determine risk category and confidence
        risk_category = self._categorize_risk(total_score)
        confidence = self._calculate_confidence(risk_factors, total_score)
        
        # Generate threshold analysis
        threshold_analysis = self._analyze_thresholds(total_score, risk_factors)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(risk_category, risk_factors)
        
        # Prepare educational information
        educational_info = self._prepare_educational_info(risk_factors, risk_category)
        
        return RiskAssessment(
            file_path=file_info.path,
            total_score=total_score,
            risk_category=risk_category,
            confidence=confidence,
            risk_factors=risk_factors,
            threshold_analysis=threshold_analysis,
            recommendations=recommendations,
            educational_info=educational_info
        )    

    def _calculate_risk_factors(self, file_info: FileInfo, characteristics: Dict[str, Any],
                              suspicious_patterns: List[Any]) -> List[RiskFactor]:
        """Calculate individual risk factors."""
        factors = []
        
        # Entropy-based risk factor
        entropy_factor = self._calculate_entropy_risk(file_info.entropy)
        factors.append(entropy_factor)
        
        # File type risk factor
        type_factor = self._calculate_file_type_risk(file_info, characteristics)
        factors.append(type_factor)
        
        # Size-based risk factor
        size_factor = self._calculate_size_risk(file_info.size, characteristics)
        factors.append(size_factor)
        
        # Pattern-based risk factors
        pattern_factors = self._calculate_pattern_risks(suspicious_patterns)
        factors.extend(pattern_factors)
        
        # Permission-based risk factor
        permission_factor = self._calculate_permission_risk(file_info.permissions)
        factors.append(permission_factor)
        
        # Temporal risk factor (based on file timestamps)
        temporal_factor = self._calculate_temporal_risk(file_info)
        factors.append(temporal_factor)
        
        # Structural risk factor (based on file structure analysis)
        structural_factor = self._calculate_structural_risk(file_info, characteristics)
        factors.append(structural_factor)
        
        return factors
    
    def _calculate_entropy_risk(self, entropy: float) -> RiskFactor:
        """Calculate risk factor based on file entropy."""
        # Normalize entropy to 0-10 scale
        normalized_entropy = (entropy / 8.0) * 10
        
        # High entropy is more suspicious for certain file types
        if entropy > 7.5:
            score = 8.0
            description = f"Very high entropy ({entropy:.2f}) indicates encryption/compression"
        elif entropy > 6.5:
            score = 6.0
            description = f"High entropy ({entropy:.2f}) suggests packed/compressed data"
        elif entropy > 5.0:
            score = 3.0
            description = f"Moderate entropy ({entropy:.2f}) within normal range"
        else:
            score = 1.0
            description = f"Low entropy ({entropy:.2f}) indicates structured data"
        
        return RiskFactor(
            name="entropy_analysis",
            description=description,
            score=score,
            weight=self._risk_weights['entropy'],
            category="file_structure",
            details={
                "entropy_value": entropy,
                "normalized_score": normalized_entropy,
                "threshold": self.config.entropy_threshold
            }
        )
    
    def _calculate_file_type_risk(self, file_info: FileInfo, characteristics: Dict[str, Any]) -> RiskFactor:
        """Calculate risk factor based on file type."""
        file_type = file_info.file_type
        is_executable = characteristics.get('is_executable', False)
        is_suspicious_type = characteristics.get('is_suspicious_type', False)
        
        if is_executable and is_suspicious_type:
            score = 9.0
            description = f"Executable file with suspicious type: {file_type}"
        elif is_executable:
            score = 6.0
            description = f"Executable file type: {file_type}"
        elif is_suspicious_type:
            score = 5.0
            description = f"Potentially suspicious file type: {file_type}"
        else:
            score = 2.0
            description = f"Standard file type: {file_type}"
        
        return RiskFactor(
            name="file_type_analysis",
            description=description,
            score=score,
            weight=self._risk_weights['file_type'],
            category="file_classification",
            details={
                "file_type": file_type,
                "is_executable": is_executable,
                "is_suspicious": is_suspicious_type
            }
        )
    
    def _calculate_size_risk(self, size: int, characteristics: Dict[str, Any]) -> RiskFactor:
        """Calculate risk factor based on file size."""
        size_category = characteristics.get('size_category', 'unknown')
        
        if size == 0:
            score = 7.0
            description = "Empty file (potential placeholder or corrupted)"
        elif size_category == 'tiny' and characteristics.get('is_executable', False):
            score = 8.0
            description = f"Unusually small executable ({size} bytes)"
        elif size_category == 'very_large':
            score = 4.0
            description = f"Very large file ({size / (1024*1024):.1f} MB)"
        else:
            score = 2.0
            description = f"Normal file size ({size} bytes)"
        
        return RiskFactor(
            name="size_analysis",
            description=description,
            score=score,
            weight=self._risk_weights['size'],
            category="file_properties",
            details={
                "size_bytes": size,
                "size_category": size_category,
                "size_mb": size / (1024 * 1024)
            }
        ) 
   
    def _calculate_pattern_risks(self, suspicious_patterns: List[Any]) -> List[RiskFactor]:
        """Calculate risk factors for each suspicious pattern."""
        factors = []
        
        for pattern in suspicious_patterns:
            # Convert pattern severity to risk score
            score = min(10.0, pattern.severity * 1.2)
            
            factor = RiskFactor(
                name=f"pattern_{pattern.pattern_type}",
                description=pattern.description,
                score=score,
                weight=self._risk_weights['patterns'],
                category="behavioral_patterns",
                details=pattern.details
            )
            factors.append(factor)
        
        return factors
    
    def _calculate_permission_risk(self, permissions: str) -> RiskFactor:
        """Calculate risk factor based on file permissions."""
        if not permissions or len(permissions) < 9:
            score = 2.0
            description = "Unable to determine file permissions"
        elif permissions == 'rwxrwxrwx':
            score = 7.0
            description = "File has overly permissive permissions (777)"
        elif 'x' in permissions and permissions[8] == 'w':
            score = 6.0
            description = "Executable file is world-writable"
        elif 'x' in permissions:
            score = 4.0
            description = "File has executable permissions"
        else:
            score = 1.0
            description = "Standard file permissions"
        
        return RiskFactor(
            name="permission_analysis",
            description=description,
            score=score,
            weight=self._risk_weights['permissions'],
            category="file_properties",
            details={
                "permissions": permissions,
                "is_executable": 'x' in permissions,
                "is_world_writable": len(permissions) >= 9 and permissions[8] == 'w'
            }
        )
    
    def _calculate_temporal_risk(self, file_info: FileInfo) -> RiskFactor:
        """Calculate risk factor based on file timestamps."""
        from datetime import datetime, timedelta
        
        now = datetime.now()
        creation_age = now - file_info.creation_time
        modification_age = now - file_info.modification_time
        
        # Very recent files might be suspicious
        if creation_age < timedelta(hours=1):
            score = 5.0
            description = "File created very recently (within 1 hour)"
        elif creation_age < timedelta(days=1):
            score = 3.0
            description = "File created recently (within 24 hours)"
        # Files modified much later than creation might be suspicious
        elif (file_info.modification_time - file_info.creation_time) > timedelta(days=30):
            score = 4.0
            description = "File modified long after creation"
        else:
            score = 1.0
            description = "Normal file timestamps"
        
        return RiskFactor(
            name="temporal_analysis",
            description=description,
            score=score,
            weight=self._risk_weights['temporal'],
            category="file_properties",
            details={
                "creation_time": file_info.creation_time.isoformat(),
                "modification_time": file_info.modification_time.isoformat(),
                "creation_age_hours": creation_age.total_seconds() / 3600,
                "modification_age_hours": modification_age.total_seconds() / 3600
            }
        )
    
    def _calculate_structural_risk(self, file_info: FileInfo, characteristics: Dict[str, Any]) -> RiskFactor:
        """Calculate risk factor based on file structure analysis."""
        # Combine various structural indicators
        structural_score = 1.0
        description_parts = []
        
        # Check for suspicious file structure patterns
        if characteristics.get('has_double_extension', False):
            structural_score += 3.0
            description_parts.append("multiple file extensions")
        
        if characteristics.get('is_hidden', False):
            structural_score += 2.0
            description_parts.append("hidden file")
        
        if characteristics.get('unusual_structure', False):
            structural_score += 2.0
            description_parts.append("unusual file structure")
        
        # Limit score to maximum
        structural_score = min(8.0, structural_score)
        
        if description_parts:
            description = f"Structural anomalies detected: {', '.join(description_parts)}"
        else:
            description = "Normal file structure"
        
        return RiskFactor(
            name="structural_analysis",
            description=description,
            score=structural_score,
            weight=self._risk_weights['structural'],
            category="file_structure",
            details={
                "has_double_extension": characteristics.get('has_double_extension', False),
                "is_hidden": characteristics.get('is_hidden', False),
                "unusual_structure": characteristics.get('unusual_structure', False)
            }
        )
    
    def _apply_scoring_algorithm(self, risk_factors: List[RiskFactor]) -> int:
        """Apply the configured scoring algorithm to calculate total risk."""
        algorithm = self._scoring_algorithms['primary']
        
        if algorithm == 'weighted_sum':
            return self._weighted_sum_algorithm(risk_factors)
        elif algorithm == 'exponential':
            return self._exponential_algorithm(risk_factors)
        else:
            return self._weighted_sum_algorithm(risk_factors)  # Default
    
    def _weighted_sum_algorithm(self, risk_factors: List[RiskFactor]) -> int:
        """Simple weighted sum algorithm."""
        total_weighted_score = sum(factor.weighted_score for factor in risk_factors)
        
        # Normalize to 1-10 scale
        max_possible_score = sum(10.0 * factor.weight for factor in risk_factors)
        if max_possible_score > 0:
            normalized_score = (total_weighted_score / max_possible_score) * 10
        else:
            normalized_score = 1.0
        
        return min(10, max(1, int(normalized_score)))
    
    def _exponential_algorithm(self, risk_factors: List[RiskFactor]) -> int:
        """Exponential scoring algorithm that emphasizes high-risk factors."""
        total_score = 0.0
        
        for factor in risk_factors:
            # Apply exponential scaling to emphasize higher scores
            exponential_score = math.pow(factor.score / 10.0, 1.5) * 10.0
            total_score += exponential_score * factor.weight
        
        # Normalize to 1-10 scale
        max_possible_score = sum(10.0 * factor.weight for factor in risk_factors)
        if max_possible_score > 0:
            normalized_score = (total_score / max_possible_score) * 10
        else:
            normalized_score = 1.0
        
        return min(10, max(1, int(normalized_score)))   
 
    def _categorize_risk(self, score: int) -> RiskCategory:
        """Categorize risk level based on score."""
        if score <= 2:
            return RiskCategory.MINIMAL
        elif score <= 4:
            return RiskCategory.LOW
        elif score <= 6:
            return RiskCategory.MODERATE
        elif score <= 8:
            return RiskCategory.HIGH
        else:
            return RiskCategory.CRITICAL
    
    def _calculate_confidence(self, risk_factors: List[RiskFactor], total_score: int) -> float:
        """Calculate confidence level in the risk assessment."""
        # Confidence based on number of factors and their consistency
        if not risk_factors:
            return 0.0
        
        # Calculate variance in factor scores
        scores = [factor.score for factor in risk_factors]
        mean_score = sum(scores) / len(scores)
        variance = sum((score - mean_score) ** 2 for score in scores) / len(scores)
        
        # Lower variance = higher confidence
        confidence = max(0.0, min(1.0, 1.0 - (variance / 25.0)))
        
        # Adjust confidence based on number of factors
        factor_confidence = min(1.0, len(risk_factors) / 5.0)
        
        return (confidence + factor_confidence) / 2.0
    
    def _analyze_thresholds(self, total_score: int, risk_factors: List[RiskFactor]) -> Dict[str, Any]:
        """Analyze how the score relates to configured thresholds."""
        threshold = self.config.behavioral_threshold
        
        return {
            'configured_threshold': threshold,
            'current_score': total_score,
            'exceeds_threshold': total_score >= threshold,
            'margin': total_score - threshold,
            'threshold_analysis': {
                'distance_to_threshold': abs(total_score - threshold),
                'confidence_in_classification': self._calculate_confidence(risk_factors, total_score),
                'factors_above_threshold': len([f for f in risk_factors if f.score >= threshold])
            }
        }
    
    def _generate_recommendations(self, risk_category: RiskCategory, 
                                risk_factors: List[RiskFactor]) -> List[str]:
        """Generate actionable recommendations based on risk assessment."""
        recommendations = []
        
        if risk_category == RiskCategory.CRITICAL:
            recommendations.append("IMMEDIATE ACTION: Quarantine file immediately")
            recommendations.append("Perform detailed malware analysis in isolated environment")
            recommendations.append("Check system for signs of compromise")
        
        elif risk_category == RiskCategory.HIGH:
            recommendations.append("Quarantine file for further analysis")
            recommendations.append("Scan with updated antivirus signatures")
            recommendations.append("Monitor system behavior for anomalies")
        
        elif risk_category == RiskCategory.MODERATE:
            recommendations.append("Consider quarantining file as precaution")
            recommendations.append("Verify file source and legitimacy")
            recommendations.append("Perform additional behavioral analysis")
        
        elif risk_category == RiskCategory.LOW:
            recommendations.append("Monitor file but allow execution if from trusted source")
            recommendations.append("Consider adding to whitelist if legitimate")
        
        else:  # MINIMAL
            recommendations.append("File appears safe for normal use")
            recommendations.append("No immediate action required")
        
        # Add specific recommendations based on risk factors
        for factor in risk_factors:
            if factor.score >= 8:
                if factor.name == "entropy_analysis":
                    recommendations.append("High entropy detected - check for packing/encryption")
                elif factor.name == "file_type_analysis":
                    recommendations.append("Suspicious file type - verify necessity")
                elif "pattern_" in factor.name:
                    recommendations.append(f"Suspicious pattern detected: {factor.description}")
        
        return list(set(recommendations))  # Remove duplicates
    
    def _prepare_educational_info(self, risk_factors: List[RiskFactor], 
                                risk_category: RiskCategory) -> Dict[str, Any]:
        """Prepare educational information about the risk assessment."""
        return {
            'risk_explanation': {
                'category': risk_category.value,
                'description': self._get_risk_category_description(risk_category),
                'factors_contributing': len(risk_factors),
                'primary_concerns': [f.name for f in risk_factors if f.score >= 7]
            },
            'learning_points': {
                'entropy_analysis': "File entropy measures randomness - high values may indicate encryption or compression",
                'behavioral_patterns': "Behavioral analysis looks for suspicious file characteristics and naming patterns",
                'risk_scoring': "Risk scores combine multiple factors to assess overall threat level",
                'threshold_management': "Configurable thresholds allow tuning sensitivity for different environments"
            },
            'detection_methods': {
                'heuristic_analysis': "Uses file characteristics to identify potentially malicious behavior",
                'pattern_matching': "Looks for known suspicious patterns in file structure and naming",
                'statistical_analysis': "Applies mathematical models to assess file risk levels"
            }
        }
    
    def _get_risk_category_description(self, category: RiskCategory) -> str:
        """Get description for risk category."""
        descriptions = {
            RiskCategory.MINIMAL: "Very low risk - file appears completely safe",
            RiskCategory.LOW: "Low risk - minor suspicious indicators present",
            RiskCategory.MODERATE: "Moderate risk - several concerning characteristics detected",
            RiskCategory.HIGH: "High risk - multiple suspicious patterns indicate potential threat",
            RiskCategory.CRITICAL: "Critical risk - strong indicators of malicious content"
        }
        return descriptions.get(category, "Unknown risk level")
    
    def _initialize_risk_weights(self) -> Dict[str, float]:
        """Initialize risk factor weights."""
        return {
            'entropy': 0.20,
            'file_type': 0.25,
            'size': 0.10,
            'patterns': 0.30,
            'permissions': 0.05,
            'temporal': 0.05,
            'structural': 0.05
        }
    
    def _initialize_thresholds(self) -> Dict[str, Any]:
        """Initialize threshold configuration."""
        return {
            'behavioral_threshold': self.config.behavioral_threshold,
            'entropy_threshold': self.config.entropy_threshold,
            'confidence_threshold': 0.7
        }
    
    def _initialize_algorithms(self) -> Dict[str, str]:
        """Initialize scoring algorithms configuration."""
        return {
            'primary': 'weighted_sum',  # Can be: weighted_sum, exponential
            'fallback': 'weighted_sum'
        }
    
    def update_thresholds(self, new_thresholds: Dict[str, Any]) -> None:
        """Update threshold configuration."""
        self._threshold_config.update(new_thresholds)
    
    def update_weights(self, new_weights: Dict[str, float]) -> None:
        """Update risk factor weights."""
        self._risk_weights.update(new_weights)