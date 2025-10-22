"""
Detection module for the Educational Antivirus Research Tool.
"""

from .signature_models import Signature, SignatureMatch, SignatureDatabase, SignatureType
from .signature_database import SignatureDatabaseManager
from .pattern_matcher import PatternMatcher, MultiPatternMatcher
from .signature_engine import SignatureEngine
from .default_signatures import get_default_signatures, get_eicar_variants, create_educational_test_patterns
from .behavioral_engine import BehavioralAnalysisEngine, SuspiciousPattern
from .risk_scorer import AdvancedRiskScorer, RiskAssessment, RiskFactor, RiskCategory

__all__ = [
    'Signature',
    'SignatureMatch', 
    'SignatureDatabase',
    'SignatureType',
    'SignatureDatabaseManager',
    'PatternMatcher',
    'MultiPatternMatcher',
    'SignatureEngine',
    'get_default_signatures',
    'get_eicar_variants',
    'create_educational_test_patterns',
    'BehavioralAnalysisEngine',
    'SuspiciousPattern',
    'AdvancedRiskScorer',
    'RiskAssessment',
    'RiskFactor',
    'RiskCategory'
]