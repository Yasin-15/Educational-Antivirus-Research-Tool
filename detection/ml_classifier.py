#!/usr/bin/env python3
"""
Machine Learning Classifier for Educational Antivirus Tool.

This module implements ML-based malware detection using RandomForest
and other algorithms trained on file features for educational purposes.
"""
import os
import pickle
import hashlib
import struct
import math
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import json

from core.models import Detection, DetectionType, FileInfo


@dataclass
class MLFeatures:
    """Feature vector for ML classification."""
    file_size: int
    entropy: float
    pe_characteristics: Dict[str, Any]
    string_features: Dict[str, int]
    api_features: Dict[str, int]
    structural_features: Dict[str, Any]
    behavioral_features: Dict[str, Any]


@dataclass
class MLResult:
    """Results from ML classification."""
    file_path: str
    prediction: str
    confidence: float
    probability_scores: Dict[str, float]
    feature_importance: Dict[str, float]
    model_version: str
    analysis_time: datetime


class MLClassifier:
    """Machine Learning malware classifier."""
    
    def __init__(self, config=None):
        """Initialize ML classifier."""
        self.config = config
        self.model = None
        self.feature_names = []
        self.model_version = "1.0.0"
        self.is_trained = False
        
        # Initialize with a simple rule-based model for educational purposes
        self._initialize_educational_model()
    
    def _initialize_educational_model(self):
        """Initialize a simple educational model for demonstration."""
        # This creates a rule-based classifier for educational purposes
        # In a real implementation, this would load a trained ML model
        self.model = EducationalMLModel()
        self.is_trained = True
        
        self.feature_names = [
            'file_size', 'entropy', 'section_count', 'import_count',
            'export_count', 'suspicious_strings', 'api_calls',
            'packer_detected', 'high_entropy_sections', 'executable_sections'
        ]
    
    def extract_features(self, file_path: str, file_data: bytes = None) -> MLFeatures:
        """Extract features from a file for ML classification."""
        if file_data is None:
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
            except Exception as e:
                # Return minimal features on error
                return MLFeatures(
                    file_size=0,
                    entropy=0.0,
                    pe_characteristics={},
                    string_features={},
                    api_features={},
                    structural_features={},
                    behavioral_features={}
                )
        
        # Extract basic features
        file_size = len(file_data)
        entropy = self._calculate_entropy(file_data)
        
        # Extract PE characteristics
        pe_characteristics = self._extract_pe_features(file_data)
        
        # Extract string features
        string_features = self._extract_string_features(file_data)
        
        # Extract API features
        api_features = self._extract_api_features(file_data)
        
        # Extract structural features
        structural_features = self._extract_structural_features(file_data, file_path)
        
        # Extract behavioral features
        behavioral_features = self._extract_behavioral_features(file_data)
        
        return MLFeatures(
            file_size=file_size,
            entropy=entropy,
            pe_characteristics=pe_characteristics,
            string_features=string_features,
            api_features=api_features,
            structural_features=structural_features,
            behavioral_features=behavioral_features
        )
    
    def classify_file(self, file_path: str, features: Optional[MLFeatures] = None) -> MLResult:
        """Classify a file using the ML model."""
        start_time = datetime.now()
        
        if not self.is_trained:
            return MLResult(
                file_path=file_path,
                prediction="unknown",
                confidence=0.0,
                probability_scores={},
                feature_importance={},
                model_version=self.model_version,
                analysis_time=start_time
            )
        
        if features is None:
            features = self.extract_features(file_path)
        
        # Convert features to vector
        feature_vector = self._features_to_vector(features)
        
        # Make prediction
        prediction, confidence, probabilities = self.model.predict(feature_vector, self.feature_names)
        
        # Calculate feature importance for this prediction
        feature_importance = self._calculate_feature_importance(features, prediction)
        
        return MLResult(
            file_path=file_path,
            prediction=prediction,
            confidence=confidence,
            probability_scores=probabilities,
            feature_importance=feature_importance,
            model_version=self.model_version,
            analysis_time=start_time
        )
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count == 0:
                continue
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _extract_pe_features(self, data: bytes) -> Dict[str, Any]:
        """Extract PE file characteristics."""
        features = {
            'is_pe': False,
            'section_count': 0,
            'import_count': 0,
            'export_count': 0,
            'has_debug_info': False,
            'has_resources': False,
            'entry_point_section': -1,
            'image_base': 0,
            'suspicious_sections': 0
        }
        
        try:
            # Check if it's a PE file
            if len(data) < 64:
                return features
            
            dos_header = struct.unpack('<H', data[:2])[0]
            if dos_header != 0x5A4D:  # 'MZ'
                return features
            
            pe_offset = struct.unpack('<L', data[60:64])[0]
            if pe_offset >= len(data) - 4:
                return features
            
            pe_signature = struct.unpack('<L', data[pe_offset:pe_offset + 4])[0]
            if pe_signature != 0x00004550:  # 'PE\0\0'
                return features
            
            features['is_pe'] = True
            
            # Get number of sections
            features['section_count'] = struct.unpack('<H', data[pe_offset + 6:pe_offset + 8])[0]
            
            # Get optional header info
            optional_header_offset = pe_offset + 24
            if optional_header_offset + 28 <= len(data):
                features['image_base'] = struct.unpack('<L', data[optional_header_offset + 28:optional_header_offset + 32])[0]
            
            # Analyze sections
            optional_header_size = struct.unpack('<H', data[pe_offset + 20:pe_offset + 22])[0]
            section_table_offset = pe_offset + 24 + optional_header_size
            
            suspicious_sections = 0
            for i in range(min(features['section_count'], 20)):
                section_offset = section_table_offset + (i * 40)
                if section_offset + 40 > len(data):
                    break
                
                # Get section characteristics
                characteristics = struct.unpack('<L', data[section_offset + 36:section_offset + 40])[0]
                
                # Check for suspicious characteristics
                if (characteristics & 0x20000000) and (characteristics & 0x80000000):  # Executable and writable
                    suspicious_sections += 1
            
            features['suspicious_sections'] = suspicious_sections
            
            # Estimate import/export counts (simplified)
            features['import_count'] = self._estimate_imports(data)
            features['export_count'] = self._estimate_exports(data)
            
        except (struct.error, IndexError):
            pass
        
        return features
    
    def _extract_string_features(self, data: bytes) -> Dict[str, int]:
        """Extract string-based features."""
        features = {
            'total_strings': 0,
            'suspicious_strings': 0,
            'crypto_strings': 0,
            'network_strings': 0,
            'system_strings': 0,
            'obfuscated_strings': 0
        }
        
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except:
            text_data = str(data)
        
        # Count printable strings
        import re
        strings = re.findall(r'[a-zA-Z0-9\s]{4,}', text_data)
        features['total_strings'] = len(strings)
        
        # Suspicious string patterns
        suspicious_patterns = [
            'password', 'keylog', 'backdoor', 'trojan', 'virus',
            'malware', 'rootkit', 'botnet', 'ransomware'
        ]
        
        crypto_patterns = [
            'encrypt', 'decrypt', 'cipher', 'hash', 'crypto',
            'aes', 'rsa', 'md5', 'sha'
        ]
        
        network_patterns = [
            'http', 'tcp', 'udp', 'socket', 'connect',
            'download', 'upload', 'url'
        ]
        
        system_patterns = [
            'registry', 'service', 'process', 'thread',
            'kernel', 'driver', 'system32'
        ]
        
        text_lower = text_data.lower()
        
        for pattern in suspicious_patterns:
            features['suspicious_strings'] += text_lower.count(pattern)
        
        for pattern in crypto_patterns:
            features['crypto_strings'] += text_lower.count(pattern)
        
        for pattern in network_patterns:
            features['network_strings'] += text_lower.count(pattern)
        
        for pattern in system_patterns:
            features['system_strings'] += text_lower.count(pattern)
        
        # Count obfuscated strings (base64, hex)
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        features['obfuscated_strings'] += len(base64_pattern.findall(text_data))
        
        hex_pattern = re.compile(r'[0-9A-Fa-f]{40,}')
        features['obfuscated_strings'] += len(hex_pattern.findall(text_data))
        
        return features
    
    def _extract_api_features(self, data: bytes) -> Dict[str, int]:
        """Extract API call features."""
        features = {
            'total_apis': 0,
            'process_apis': 0,
            'file_apis': 0,
            'registry_apis': 0,
            'network_apis': 0,
            'crypto_apis': 0,
            'debug_apis': 0
        }
        
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except:
            text_data = str(data)
        
        api_categories = {
            'process_apis': [
                'CreateProcess', 'OpenProcess', 'TerminateProcess',
                'WriteProcessMemory', 'ReadProcessMemory'
            ],
            'file_apis': [
                'CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile',
                'MoveFile', 'CopyFile'
            ],
            'registry_apis': [
                'RegCreateKey', 'RegSetValue', 'RegDeleteKey',
                'RegOpenKey', 'RegQueryValue'
            ],
            'network_apis': [
                'socket', 'connect', 'send', 'recv',
                'InternetOpen', 'HttpSendRequest'
            ],
            'crypto_apis': [
                'CryptAcquireContext', 'CryptCreateHash',
                'CryptEncrypt', 'CryptDecrypt'
            ],
            'debug_apis': [
                'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                'OutputDebugString'
            ]
        }
        
        text_lower = text_data.lower()
        total_apis = 0
        
        for category, api_list in api_categories.items():
            count = 0
            for api in api_list:
                count += text_lower.count(api.lower())
            features[category] = count
            total_apis += count
        
        features['total_apis'] = total_apis
        
        return features
    
    def _extract_structural_features(self, data: bytes, file_path: str) -> Dict[str, Any]:
        """Extract structural features."""
        features = {
            'file_extension': Path(file_path).suffix.lower(),
            'file_size_category': self._categorize_file_size(len(data)),
            'entropy_category': self._categorize_entropy(self._calculate_entropy(data)),
            'has_overlay': False,
            'packer_detected': False,
            'magic_bytes_match': True
        }
        
        # Check magic bytes vs extension
        if len(data) >= 2:
            magic_bytes = data[:2]
            expected_magic = self._get_expected_magic_bytes(features['file_extension'])
            features['magic_bytes_match'] = (magic_bytes == expected_magic) if expected_magic else True
        
        # Simple packer detection
        if self._calculate_entropy(data) > 7.5 and len(data) > 10000:
            features['packer_detected'] = True
        
        # Check for overlay (data after PE sections)
        if features['file_extension'] in ['.exe', '.dll']:
            features['has_overlay'] = self._has_overlay(data)
        
        return features
    
    def _extract_behavioral_features(self, data: bytes) -> Dict[str, Any]:
        """Extract behavioral indicators."""
        features = {
            'persistence_indicators': 0,
            'evasion_indicators': 0,
            'network_indicators': 0,
            'credential_theft_indicators': 0,
            'system_modification_indicators': 0
        }
        
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except:
            text_data = str(data)
        
        text_lower = text_data.lower()
        
        # Persistence indicators
        persistence_patterns = [
            'startup', 'run', 'runonce', 'service', 'task scheduler'
        ]
        for pattern in persistence_patterns:
            features['persistence_indicators'] += text_lower.count(pattern)
        
        # Evasion indicators
        evasion_patterns = [
            'debugger', 'virtual', 'sandbox', 'analysis', 'sleep'
        ]
        for pattern in evasion_patterns:
            features['evasion_indicators'] += text_lower.count(pattern)
        
        # Network indicators
        network_patterns = [
            'http', 'download', 'upload', 'c2', 'beacon'
        ]
        for pattern in network_patterns:
            features['network_indicators'] += text_lower.count(pattern)
        
        # Credential theft indicators
        credential_patterns = [
            'password', 'credential', 'keylog', 'browser', 'cookie'
        ]
        for pattern in credential_patterns:
            features['credential_theft_indicators'] += text_lower.count(pattern)
        
        # System modification indicators
        system_patterns = [
            'registry', 'firewall', 'antivirus', 'defender', 'disable'
        ]
        for pattern in system_patterns:
            features['system_modification_indicators'] += text_lower.count(pattern)
        
        return features
    
    def _features_to_vector(self, features: MLFeatures) -> List[float]:
        """Convert features to numerical vector."""
        vector = []
        
        # Basic features
        vector.append(float(features.file_size))
        vector.append(features.entropy)
        
        # PE features
        pe_features = features.pe_characteristics
        vector.append(float(pe_features.get('section_count', 0)))
        vector.append(float(pe_features.get('import_count', 0)))
        vector.append(float(pe_features.get('export_count', 0)))
        
        # String features
        string_features = features.string_features
        vector.append(float(string_features.get('suspicious_strings', 0)))
        
        # API features
        api_features = features.api_features
        vector.append(float(api_features.get('total_apis', 0)))
        
        # Structural features
        structural_features = features.structural_features
        vector.append(1.0 if structural_features.get('packer_detected', False) else 0.0)
        
        # Behavioral features (simplified)
        behavioral_features = features.behavioral_features
        high_entropy_sections = 1.0 if features.entropy > 7.0 else 0.0
        vector.append(high_entropy_sections)
        
        executable_sections = 1.0 if pe_features.get('suspicious_sections', 0) > 0 else 0.0
        vector.append(executable_sections)
        
        return vector
    
    def _calculate_feature_importance(self, features: MLFeatures, prediction: str) -> Dict[str, float]:
        """Calculate feature importance for the prediction."""
        # Simplified feature importance calculation
        importance = {}
        
        if prediction == "malware":
            importance['entropy'] = 0.8 if features.entropy > 7.0 else 0.2
            importance['suspicious_strings'] = 0.7 if features.string_features.get('suspicious_strings', 0) > 0 else 0.1
            importance['packer_detected'] = 0.9 if features.structural_features.get('packer_detected', False) else 0.1
            importance['api_calls'] = 0.6 if features.api_features.get('total_apis', 0) > 10 else 0.2
        else:
            importance['entropy'] = 0.2 if features.entropy < 6.0 else 0.8
            importance['suspicious_strings'] = 0.1
            importance['packer_detected'] = 0.1
            importance['api_calls'] = 0.3
        
        return importance
    
    def _categorize_file_size(self, size: int) -> str:
        """Categorize file size."""
        if size < 1024:
            return "tiny"
        elif size < 10240:
            return "small"
        elif size < 102400:
            return "medium"
        elif size < 1048576:
            return "large"
        else:
            return "huge"
    
    def _categorize_entropy(self, entropy: float) -> str:
        """Categorize entropy level."""
        if entropy < 4.0:
            return "low"
        elif entropy < 6.0:
            return "medium"
        elif entropy < 7.5:
            return "high"
        else:
            return "very_high"
    
    def _get_expected_magic_bytes(self, file_ext: str) -> Optional[bytes]:
        """Get expected magic bytes for file extension."""
        magic_bytes = {
            '.exe': b'MZ',
            '.dll': b'MZ',
            '.scr': b'MZ',
            '.pdf': b'%P',
            '.zip': b'PK'
        }
        return magic_bytes.get(file_ext)
    
    def _has_overlay(self, data: bytes) -> bool:
        """Check if PE file has overlay data."""
        # Simplified overlay detection
        try:
            if len(data) < 64:
                return False
            
            pe_offset = struct.unpack('<L', data[60:64])[0]
            if pe_offset >= len(data) - 4:
                return False
            
            # If file is significantly larger than expected PE size, might have overlay
            return len(data) > pe_offset + 1000
        except:
            return False
    
    def _estimate_imports(self, data: bytes) -> int:
        """Estimate number of imports."""
        try:
            text_data = data.decode('utf-8', errors='ignore')
            common_dlls = ['kernel32', 'user32', 'ntdll', 'advapi32', 'ws2_32']
            count = 0
            for dll in common_dlls:
                if dll.lower() in text_data.lower():
                    count += 1
            return count
        except:
            return 0
    
    def _estimate_exports(self, data: bytes) -> int:
        """Estimate number of exports."""
        # Simplified export counting
        try:
            text_data = data.decode('utf-8', errors='ignore')
            # Look for function-like names
            import re
            function_pattern = re.compile(r'[A-Za-z_][A-Za-z0-9_]{3,}')
            matches = function_pattern.findall(text_data)
            return min(len(matches), 100)  # Cap at reasonable number
        except:
            return 0


class EducationalMLModel:
    """Educational ML model for demonstration purposes."""
    
    def __init__(self):
        """Initialize educational model."""
        self.model_type = "rule_based_educational"
        self.version = "1.0.0"
    
    def predict(self, feature_vector: List[float], feature_names: List[str]) -> Tuple[str, float, Dict[str, float]]:
        """Make prediction using rule-based logic."""
        # Simple rule-based classification for educational purposes
        
        # Extract key features
        file_size = feature_vector[0] if len(feature_vector) > 0 else 0
        entropy = feature_vector[1] if len(feature_vector) > 1 else 0
        suspicious_strings = feature_vector[5] if len(feature_vector) > 5 else 0
        packer_detected = feature_vector[7] if len(feature_vector) > 7 else 0
        
        # Calculate malware score
        malware_score = 0.0
        
        # High entropy indicates possible packing/encryption
        if entropy > 7.5:
            malware_score += 0.3
        elif entropy > 7.0:
            malware_score += 0.2
        
        # Suspicious strings
        if suspicious_strings > 5:
            malware_score += 0.4
        elif suspicious_strings > 0:
            malware_score += 0.2
        
        # Packer detection
        if packer_detected > 0.5:
            malware_score += 0.3
        
        # File size considerations
        if file_size < 1024:  # Very small files are suspicious
            malware_score += 0.1
        elif file_size > 10485760:  # Very large files might be suspicious
            malware_score += 0.1
        
        # Make prediction
        if malware_score > 0.6:
            prediction = "malware"
            confidence = min(0.95, malware_score)
        elif malware_score > 0.3:
            prediction = "suspicious"
            confidence = malware_score
        else:
            prediction = "benign"
            confidence = 1.0 - malware_score
        
        # Create probability scores
        probabilities = {
            "malware": malware_score,
            "suspicious": max(0.0, 0.5 - abs(malware_score - 0.5)),
            "benign": 1.0 - malware_score
        }
        
        # Normalize probabilities
        total_prob = sum(probabilities.values())
        if total_prob > 0:
            probabilities = {k: v / total_prob for k, v in probabilities.items()}
        
        return prediction, confidence, probabilities


def create_ml_detection(file_path: str, ml_result: MLResult) -> Optional[Detection]:
    """Create a Detection object from ML classification results."""
    if ml_result.prediction == "benign":
        return None
    
    if ml_result.prediction == "malware":
        threat_name = f"ML.Malware.Detected"
        risk_score = int(ml_result.confidence * 100)
    elif ml_result.prediction == "suspicious":
        threat_name = f"ML.Suspicious.Behavior"
        risk_score = int(ml_result.confidence * 70)
    else:
        return None
    
    description = f"Machine learning classifier detected {ml_result.prediction} with {ml_result.confidence:.2f} confidence"
    
    return Detection(
        file_path=file_path,
        threat_name=threat_name,
        detection_type=DetectionType.HEURISTIC,  # ML is a form of heuristic detection
        risk_score=risk_score,
        description=description,
        confidence=ml_result.confidence
    )


def train_educational_model(training_data: List[Tuple[MLFeatures, str]]) -> EducationalMLModel:
    """Train an educational ML model (placeholder for real training)."""
    # In a real implementation, this would train an actual ML model
    # For educational purposes, we return the rule-based model
    print(f"Training educational model with {len(training_data)} samples...")
    print("Note: This is a simplified educational model for demonstration.")
    
    return EducationalMLModel()