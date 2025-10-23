#!/usr/bin/env python3
"""
Heuristic Detection Engine for Educational Antivirus Tool.

This module implements advanced heuristic analysis to detect unknown malware
based on behavioral patterns and suspicious characteristics.
"""
import os
import re
import struct
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import math

from core.models import Detection, DetectionType, FileInfo


@dataclass
class HeuristicResult:
    """Results from heuristic analysis."""
    file_path: str
    risk_score: int
    confidence: float
    suspicious_patterns: List[str]
    behavioral_indicators: Dict[str, Any]
    recommendations: List[str]
    analysis_time: datetime


class HeuristicEngine:
    """Advanced heuristic detection engine."""
    
    def __init__(self, config=None):
        """Initialize heuristic engine."""
        self.config = config
        self.suspicious_strings = self._load_suspicious_strings()
        self.api_patterns = self._load_api_patterns()
        self.packer_signatures = self._load_packer_signatures()
        
    def analyze_file(self, file_path: str, file_info: Optional[FileInfo] = None) -> HeuristicResult:
        """Perform comprehensive heuristic analysis on a file."""
        start_time = datetime.now()
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
        except Exception as e:
            return HeuristicResult(
                file_path=file_path,
                risk_score=0,
                confidence=0.0,
                suspicious_patterns=[f"File read error: {e}"],
                behavioral_indicators={},
                recommendations=["Unable to analyze file"],
                analysis_time=start_time
            )
        
        # Perform various heuristic checks
        results = {
            'entropy': self._analyze_entropy(file_data),
            'strings': self._analyze_suspicious_strings(file_data),
            'api_calls': self._analyze_api_patterns(file_data),
            'structure': self._analyze_file_structure(file_data, file_path),
            'packing': self._detect_packing(file_data),
            'obfuscation': self._detect_obfuscation(file_data),
            'network': self._analyze_network_indicators(file_data),
            'persistence': self._analyze_persistence_mechanisms(file_data),
            'evasion': self._detect_evasion_techniques(file_data)
        }
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(results)
        confidence = self._calculate_confidence(results)
        
        # Collect all suspicious patterns
        suspicious_patterns = []
        for category, result in results.items():
            if result.get('suspicious', False):
                suspicious_patterns.extend(result.get('patterns', []))
        
        # Generate recommendations
        recommendations = self._generate_recommendations(results, risk_score)
        
        return HeuristicResult(
            file_path=file_path,
            risk_score=risk_score,
            confidence=confidence,
            suspicious_patterns=suspicious_patterns,
            behavioral_indicators=results,
            recommendations=recommendations,
            analysis_time=start_time
        )
    
    def _analyze_entropy(self, data: bytes) -> Dict[str, Any]:
        """Analyze file entropy for packing/encryption detection."""
        if not data:
            return {'entropy': 0.0, 'suspicious': False, 'patterns': []}
        
        # Calculate Shannon entropy
        entropy = 0.0
        byte_counts = [0] * 256
        
        for byte in data:
            byte_counts[byte] += 1
        
        data_len = len(data)
        for count in byte_counts:
            if count == 0:
                continue
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        # High entropy indicates possible packing/encryption
        suspicious = entropy > 7.5
        patterns = []
        
        if suspicious:
            patterns.append(f"High entropy: {entropy:.2f} (possible packing/encryption)")
        
        # Analyze entropy distribution across file sections
        section_entropies = []
        section_size = max(1024, len(data) // 10)  # Analyze in 10 sections
        
        for i in range(0, len(data), section_size):
            section = data[i:i + section_size]
            if section:
                section_entropy = self._calculate_section_entropy(section)
                section_entropies.append(section_entropy)
        
        # Check for entropy variations (sign of packing)
        if section_entropies:
            entropy_variance = sum((e - entropy) ** 2 for e in section_entropies) / len(section_entropies)
            if entropy_variance > 1.0:
                patterns.append(f"High entropy variance: {entropy_variance:.2f} (possible packing)")
                suspicious = True
        
        return {
            'entropy': entropy,
            'section_entropies': section_entropies,
            'entropy_variance': entropy_variance if section_entropies else 0.0,
            'suspicious': suspicious,
            'patterns': patterns
        }
    
    def _calculate_section_entropy(self, data: bytes) -> float:
        """Calculate entropy for a data section."""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count == 0:
                continue
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _analyze_suspicious_strings(self, data: bytes) -> Dict[str, Any]:
        """Analyze file for suspicious strings and patterns."""
        suspicious = False
        patterns = []
        string_categories = {}
        
        try:
            # Convert to string for pattern matching
            text_data = data.decode('utf-8', errors='ignore')
        except:
            text_data = str(data)
        
        # Check for suspicious strings
        for category, string_list in self.suspicious_strings.items():
            matches = []
            for suspicious_string in string_list:
                if isinstance(suspicious_string, str):
                    if suspicious_string.lower() in text_data.lower():
                        matches.append(suspicious_string)
                else:  # regex pattern
                    regex_matches = re.findall(suspicious_string, text_data, re.IGNORECASE)
                    matches.extend(regex_matches)
            
            if matches:
                string_categories[category] = matches
                patterns.extend([f"{category}: {match}" for match in matches])
                suspicious = True
        
        # Check for encoded/obfuscated strings
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        base64_matches = base64_pattern.findall(text_data)
        if len(base64_matches) > 5:
            patterns.append(f"Multiple Base64 strings detected: {len(base64_matches)}")
            suspicious = True
        
        # Check for hex-encoded strings
        hex_pattern = re.compile(r'[0-9A-Fa-f]{40,}')
        hex_matches = hex_pattern.findall(text_data)
        if len(hex_matches) > 3:
            patterns.append(f"Multiple hex strings detected: {len(hex_matches)}")
            suspicious = True
        
        return {
            'suspicious': suspicious,
            'patterns': patterns,
            'categories': string_categories,
            'base64_count': len(base64_matches),
            'hex_count': len(hex_matches)
        }
    
    def _analyze_api_patterns(self, data: bytes) -> Dict[str, Any]:
        """Analyze for suspicious API call patterns."""
        suspicious = False
        patterns = []
        api_categories = {}
        
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except:
            text_data = str(data)
        
        # Check for suspicious API patterns
        for category, api_list in self.api_patterns.items():
            matches = []
            for api_pattern in api_list:
                if api_pattern.lower() in text_data.lower():
                    matches.append(api_pattern)
            
            if matches:
                api_categories[category] = matches
                patterns.extend([f"{category} API: {match}" for match in matches])
                suspicious = True
        
        # Check for API obfuscation techniques
        obfuscated_apis = re.findall(r'Get[A-Z][a-z]+Address|LoadLibrary[AW]?', text_data, re.IGNORECASE)
        if obfuscated_apis:
            patterns.append(f"Dynamic API loading detected: {len(obfuscated_apis)} calls")
            suspicious = True
        
        return {
            'suspicious': suspicious,
            'patterns': patterns,
            'categories': api_categories,
            'dynamic_loading': len(obfuscated_apis)
        }
    
    def _analyze_file_structure(self, data: bytes, file_path: str) -> Dict[str, Any]:
        """Analyze file structure for anomalies."""
        suspicious = False
        patterns = []
        structure_info = {}
        
        file_ext = Path(file_path).suffix.lower()
        
        # PE file analysis
        if file_ext in ['.exe', '.dll', '.scr']:
            pe_analysis = self._analyze_pe_structure(data)
            structure_info.update(pe_analysis)
            if pe_analysis.get('suspicious', False):
                suspicious = True
                patterns.extend(pe_analysis.get('patterns', []))
        
        # Check for file format mismatches
        magic_bytes = data[:4] if len(data) >= 4 else b''
        expected_magic = self._get_expected_magic_bytes(file_ext)
        
        if expected_magic and magic_bytes != expected_magic:
            patterns.append(f"File extension mismatch: {file_ext} with magic {magic_bytes.hex()}")
            suspicious = True
        
        # Check for embedded files
        embedded_files = self._detect_embedded_files(data)
        if embedded_files:
            patterns.append(f"Embedded files detected: {len(embedded_files)}")
            suspicious = True
            structure_info['embedded_files'] = embedded_files
        
        return {
            'suspicious': suspicious,
            'patterns': patterns,
            'structure_info': structure_info,
            'magic_bytes': magic_bytes.hex() if magic_bytes else '',
            'file_extension': file_ext
        }
    
    def _analyze_pe_structure(self, data: bytes) -> Dict[str, Any]:
        """Analyze PE file structure for anomalies."""
        suspicious = False
        patterns = []
        pe_info = {}
        
        try:
            # Check DOS header
            if len(data) < 64:
                return {'suspicious': False, 'patterns': ['File too small for PE']}
            
            dos_header = struct.unpack('<H', data[:2])[0]
            if dos_header != 0x5A4D:  # 'MZ'
                patterns.append("Invalid DOS header")
                suspicious = True
            
            # Get PE header offset
            pe_offset = struct.unpack('<L', data[60:64])[0]
            
            if pe_offset >= len(data) - 4:
                patterns.append("Invalid PE header offset")
                suspicious = True
                return {'suspicious': suspicious, 'patterns': patterns}
            
            # Check PE signature
            pe_signature = struct.unpack('<L', data[pe_offset:pe_offset + 4])[0]
            if pe_signature != 0x00004550:  # 'PE\0\0'
                patterns.append("Invalid PE signature")
                suspicious = True
            
            # Analyze sections
            sections_analysis = self._analyze_pe_sections(data, pe_offset)
            pe_info.update(sections_analysis)
            
            if sections_analysis.get('suspicious', False):
                suspicious = True
                patterns.extend(sections_analysis.get('patterns', []))
            
        except (struct.error, IndexError) as e:
            patterns.append(f"PE parsing error: {e}")
            suspicious = True
        
        return {
            'suspicious': suspicious,
            'patterns': patterns,
            'pe_info': pe_info
        }
    
    def _analyze_pe_sections(self, data: bytes, pe_offset: int) -> Dict[str, Any]:
        """Analyze PE sections for anomalies."""
        suspicious = False
        patterns = []
        sections_info = []
        
        try:
            # Skip to optional header
            optional_header_offset = pe_offset + 24
            
            if optional_header_offset + 2 > len(data):
                return {'suspicious': True, 'patterns': ['Invalid optional header offset']}
            
            # Get number of sections
            num_sections = struct.unpack('<H', data[pe_offset + 6:pe_offset + 8])[0]
            
            if num_sections > 20:  # Unusually high number of sections
                patterns.append(f"Suspicious number of sections: {num_sections}")
                suspicious = True
            
            # Calculate section table offset
            optional_header_size = struct.unpack('<H', data[pe_offset + 20:pe_offset + 22])[0]
            section_table_offset = pe_offset + 24 + optional_header_size
            
            # Analyze each section
            for i in range(min(num_sections, 20)):  # Limit to prevent excessive processing
                section_offset = section_table_offset + (i * 40)
                
                if section_offset + 40 > len(data):
                    break
                
                # Get section name
                section_name = data[section_offset:section_offset + 8].rstrip(b'\x00').decode('ascii', errors='ignore')
                
                # Get section characteristics
                characteristics = struct.unpack('<L', data[section_offset + 36:section_offset + 40])[0]
                
                section_info = {
                    'name': section_name,
                    'characteristics': characteristics,
                    'executable': bool(characteristics & 0x20000000),
                    'writable': bool(characteristics & 0x80000000),
                    'readable': bool(characteristics & 0x40000000)
                }
                
                sections_info.append(section_info)
                
                # Check for suspicious section characteristics
                if section_info['executable'] and section_info['writable']:
                    patterns.append(f"Executable and writable section: {section_name}")
                    suspicious = True
                
                # Check for suspicious section names
                suspicious_names = ['.packed', '.upx', '.aspack', '.petite', '.themida']
                if any(sus_name in section_name.lower() for sus_name in suspicious_names):
                    patterns.append(f"Suspicious section name: {section_name}")
                    suspicious = True
        
        except (struct.error, IndexError, UnicodeDecodeError) as e:
            patterns.append(f"Section analysis error: {e}")
            suspicious = True
        
        return {
            'suspicious': suspicious,
            'patterns': patterns,
            'sections': sections_info,
            'section_count': len(sections_info)
        }
    
    def _detect_packing(self, data: bytes) -> Dict[str, Any]:
        """Detect file packing/compression."""
        suspicious = False
        patterns = []
        packer_info = {}
        
        # Check for known packer signatures
        for packer_name, signatures in self.packer_signatures.items():
            for signature in signatures:
                if signature in data:
                    patterns.append(f"Packer detected: {packer_name}")
                    suspicious = True
                    packer_info[packer_name] = True
        
        # Check for high entropy (indication of packing)
        entropy = self._calculate_section_entropy(data)
        if entropy > 7.5:
            patterns.append(f"High entropy suggests packing: {entropy:.2f}")
            suspicious = True
        
        # Check for small import table (common in packed files)
        import_count = self._count_imports(data)
        if import_count < 5 and len(data) > 10000:  # Large file with few imports
            patterns.append(f"Suspiciously few imports: {import_count}")
            suspicious = True
        
        return {
            'suspicious': suspicious,
            'patterns': patterns,
            'detected_packers': packer_info,
            'import_count': import_count,
            'entropy': entropy
        }
    
    def _detect_obfuscation(self, data: bytes) -> Dict[str, Any]:
        """Detect code obfuscation techniques."""
        suspicious = False
        patterns = []
        
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except:
            text_data = str(data)
        
        # Check for string obfuscation
        obfuscated_strings = 0
        
        # Base64 encoded strings
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        base64_matches = len(base64_pattern.findall(text_data))
        if base64_matches > 10:
            patterns.append(f"Excessive Base64 encoding: {base64_matches} instances")
            suspicious = True
            obfuscated_strings += base64_matches
        
        # Hex encoded strings
        hex_pattern = re.compile(r'\\x[0-9A-Fa-f]{2}')
        hex_matches = len(hex_pattern.findall(text_data))
        if hex_matches > 20:
            patterns.append(f"Excessive hex encoding: {hex_matches} instances")
            suspicious = True
            obfuscated_strings += hex_matches
        
        # Unicode escapes
        unicode_pattern = re.compile(r'\\u[0-9A-Fa-f]{4}')
        unicode_matches = len(unicode_pattern.findall(text_data))
        if unicode_matches > 10:
            patterns.append(f"Excessive Unicode escapes: {unicode_matches} instances")
            suspicious = True
            obfuscated_strings += unicode_matches
        
        # Check for control flow obfuscation
        jmp_instructions = len(re.findall(r'jmp|jz|jnz|je|jne', text_data, re.IGNORECASE))
        if jmp_instructions > 100:
            patterns.append(f"Excessive jump instructions: {jmp_instructions}")
            suspicious = True
        
        return {
            'suspicious': suspicious,
            'patterns': patterns,
            'obfuscated_strings': obfuscated_strings,
            'jump_instructions': jmp_instructions
        }
    
    def _analyze_network_indicators(self, data: bytes) -> Dict[str, Any]:
        """Analyze for network-related suspicious indicators."""
        suspicious = False
        patterns = []
        network_info = {}
        
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except:
            text_data = str(data)
        
        # Check for IP addresses
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        ip_addresses = ip_pattern.findall(text_data)
        
        # Filter out common local/broadcast IPs
        suspicious_ips = [ip for ip in ip_addresses if not self._is_benign_ip(ip)]
        
        if suspicious_ips:
            patterns.append(f"Suspicious IP addresses: {len(suspicious_ips)}")
            suspicious = True
            network_info['suspicious_ips'] = suspicious_ips[:5]  # Limit output
        
        # Check for URLs
        url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
        urls = url_pattern.findall(text_data)
        
        if urls:
            patterns.append(f"URLs detected: {len(urls)}")
            if len(urls) > 5:
                suspicious = True
            network_info['urls'] = urls[:3]  # Limit output
        
        # Check for suspicious domains
        domain_pattern = re.compile(r'[a-zA-Z0-9.-]+\.(tk|ml|ga|cf|bit|onion)', re.IGNORECASE)
        suspicious_domains = domain_pattern.findall(text_data)
        
        if suspicious_domains:
            patterns.append(f"Suspicious domains: {len(suspicious_domains)}")
            suspicious = True
            network_info['suspicious_domains'] = suspicious_domains
        
        # Check for network API calls
        network_apis = ['socket', 'connect', 'send', 'recv', 'WSAStartup', 'InternetOpen']
        found_apis = [api for api in network_apis if api.lower() in text_data.lower()]
        
        if len(found_apis) > 3:
            patterns.append(f"Multiple network APIs: {len(found_apis)}")
            suspicious = True
            network_info['network_apis'] = found_apis
        
        return {
            'suspicious': suspicious,
            'patterns': patterns,
            'network_info': network_info,
            'ip_count': len(suspicious_ips),
            'url_count': len(urls)
        }
    
    def _analyze_persistence_mechanisms(self, data: bytes) -> Dict[str, Any]:
        """Analyze for persistence mechanism indicators."""
        suspicious = False
        patterns = []
        persistence_info = {}
        
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except:
            text_data = str(data)
        
        # Registry persistence
        registry_keys = [
            'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'SYSTEM\\CurrentControlSet\\Services',
            'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
        ]
        
        found_registry = [key for key in registry_keys if key.lower() in text_data.lower()]
        if found_registry:
            patterns.append(f"Registry persistence keys: {len(found_registry)}")
            suspicious = True
            persistence_info['registry_keys'] = found_registry
        
        # File system persistence
        persistence_paths = [
            'startup', 'system32', 'syswow64', 'temp', 'appdata'
        ]
        
        found_paths = [path for path in persistence_paths if path.lower() in text_data.lower()]
        if len(found_paths) > 2:
            patterns.append(f"Multiple system paths: {len(found_paths)}")
            suspicious = True
            persistence_info['system_paths'] = found_paths
        
        # Service installation
        service_apis = ['CreateService', 'OpenSCManager', 'StartService']
        found_service_apis = [api for api in service_apis if api.lower() in text_data.lower()]
        
        if found_service_apis:
            patterns.append(f"Service manipulation APIs: {len(found_service_apis)}")
            suspicious = True
            persistence_info['service_apis'] = found_service_apis
        
        return {
            'suspicious': suspicious,
            'patterns': patterns,
            'persistence_info': persistence_info
        }
    
    def _detect_evasion_techniques(self, data: bytes) -> Dict[str, Any]:
        """Detect anti-analysis and evasion techniques."""
        suspicious = False
        patterns = []
        evasion_info = {}
        
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except:
            text_data = str(data)
        
        # Anti-debugging
        debug_apis = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugString']
        found_debug_apis = [api for api in debug_apis if api.lower() in text_data.lower()]
        
        if found_debug_apis:
            patterns.append(f"Anti-debugging APIs: {len(found_debug_apis)}")
            suspicious = True
            evasion_info['debug_apis'] = found_debug_apis
        
        # VM detection
        vm_indicators = ['vmware', 'virtualbox', 'vbox', 'qemu', 'xen']
        found_vm_indicators = [vm for vm in vm_indicators if vm.lower() in text_data.lower()]
        
        if found_vm_indicators:
            patterns.append(f"VM detection indicators: {len(found_vm_indicators)}")
            suspicious = True
            evasion_info['vm_indicators'] = found_vm_indicators
        
        # Sandbox evasion
        sandbox_indicators = ['sleep', 'delay', 'wait', 'mouse', 'cursor']
        found_sandbox = [ind for ind in sandbox_indicators if ind.lower() in text_data.lower()]
        
        if len(found_sandbox) > 2:
            patterns.append(f"Sandbox evasion indicators: {len(found_sandbox)}")
            suspicious = True
            evasion_info['sandbox_indicators'] = found_sandbox
        
        return {
            'suspicious': suspicious,
            'patterns': patterns,
            'evasion_info': evasion_info
        }
    
    def _calculate_risk_score(self, results: Dict[str, Any]) -> int:
        """Calculate overall risk score from analysis results."""
        score = 0
        
        # Weight different categories
        weights = {
            'entropy': 15,
            'strings': 20,
            'api_calls': 25,
            'structure': 15,
            'packing': 30,
            'obfuscation': 25,
            'network': 20,
            'persistence': 35,
            'evasion': 30
        }
        
        for category, result in results.items():
            if result.get('suspicious', False):
                category_weight = weights.get(category, 10)
                pattern_count = len(result.get('patterns', []))
                score += category_weight + (pattern_count * 2)
        
        # Normalize to 0-100 scale
        return min(100, score)
    
    def _calculate_confidence(self, results: Dict[str, Any]) -> float:
        """Calculate confidence level in the analysis."""
        total_checks = len(results)
        successful_checks = sum(1 for result in results.values() if 'suspicious' in result)
        
        if total_checks == 0:
            return 0.0
        
        base_confidence = successful_checks / total_checks
        
        # Boost confidence if multiple categories are suspicious
        suspicious_categories = sum(1 for result in results.values() if result.get('suspicious', False))
        if suspicious_categories > 3:
            base_confidence = min(1.0, base_confidence + 0.2)
        
        return round(base_confidence, 2)
    
    def _generate_recommendations(self, results: Dict[str, Any], risk_score: int) -> List[str]:
        """Generate recommendations based on analysis results."""
        recommendations = []
        
        if risk_score > 70:
            recommendations.append("HIGH RISK: Quarantine immediately and perform detailed analysis")
        elif risk_score > 40:
            recommendations.append("MEDIUM RISK: Investigate further before execution")
        elif risk_score > 20:
            recommendations.append("LOW RISK: Monitor for suspicious behavior")
        else:
            recommendations.append("File appears benign based on heuristic analysis")
        
        # Specific recommendations based on findings
        if results.get('packing', {}).get('suspicious', False):
            recommendations.append("File appears packed - consider unpacking for deeper analysis")
        
        if results.get('network', {}).get('suspicious', False):
            recommendations.append("Network indicators found - monitor network traffic if executed")
        
        if results.get('persistence', {}).get('suspicious', False):
            recommendations.append("Persistence mechanisms detected - check system changes after execution")
        
        if results.get('evasion', {}).get('suspicious', False):
            recommendations.append("Anti-analysis techniques detected - use advanced analysis environment")
        
        return recommendations
    
    def _load_suspicious_strings(self) -> Dict[str, List[str]]:
        """Load suspicious string patterns for analysis."""
        return {
            'malware_families': [
                'trojan', 'backdoor', 'keylogger', 'rootkit', 'botnet',
                'ransomware', 'spyware', 'adware', 'worm', 'virus'
            ],
            'crypto_mining': [
                'stratum', 'mining', 'hashrate', 'cryptocurrency', 'bitcoin',
                'monero', 'ethereum', 'miner', 'pool'
            ],
            'credential_theft': [
                'password', 'credential', 'keylog', 'steal', 'harvest',
                'browser', 'cookie', 'token', 'login'
            ],
            'system_manipulation': [
                'disable', 'firewall', 'antivirus', 'defender', 'security',
                'registry', 'service', 'process', 'inject'
            ],
            'network_activity': [
                'download', 'upload', 'c2', 'command', 'control',
                'beacon', 'exfiltrate', 'tunnel'
            ]
        }
    
    def _load_api_patterns(self) -> Dict[str, List[str]]:
        """Load suspicious API call patterns."""
        return {
            'process_manipulation': [
                'CreateProcess', 'OpenProcess', 'TerminateProcess',
                'WriteProcessMemory', 'ReadProcessMemory', 'VirtualAlloc'
            ],
            'file_operations': [
                'CreateFile', 'WriteFile', 'DeleteFile', 'MoveFile',
                'CopyFile', 'SetFileAttributes'
            ],
            'registry_operations': [
                'RegCreateKey', 'RegSetValue', 'RegDeleteKey',
                'RegOpenKey', 'RegQueryValue'
            ],
            'network_operations': [
                'socket', 'connect', 'send', 'recv', 'WSAStartup',
                'InternetOpen', 'HttpSendRequest'
            ],
            'crypto_operations': [
                'CryptAcquireContext', 'CryptCreateHash', 'CryptEncrypt',
                'CryptDecrypt', 'CryptGenKey'
            ]
        }
    
    def _load_packer_signatures(self) -> Dict[str, List[bytes]]:
        """Load known packer signatures."""
        return {
            'UPX': [b'UPX!', b'UPX0', b'UPX1'],
            'ASPack': [b'aPLib', b'ASPack'],
            'PEtite': [b'petite', b'Petite'],
            'Themida': [b'Themida', b'WinLicense'],
            'VMProtect': [b'VMProtect', b'.vmp0', b'.vmp1'],
            'Armadillo': [b'Armadillo', b'Silicon Realms'],
            'ExePack': [b'ExePack', b'EXEPACK'],
            'MPRESS': [b'MPRESS', b'.MPRESS']
        }
    
    def _get_expected_magic_bytes(self, file_ext: str) -> Optional[bytes]:
        """Get expected magic bytes for file extension."""
        magic_bytes = {
            '.exe': b'MZ',
            '.dll': b'MZ',
            '.scr': b'MZ',
            '.pdf': b'%PDF',
            '.zip': b'PK',
            '.rar': b'Rar!',
            '.jpg': b'\xff\xd8\xff',
            '.png': b'\x89PNG',
            '.gif': b'GIF8'
        }
        return magic_bytes.get(file_ext)
    
    def _detect_embedded_files(self, data: bytes) -> List[Dict[str, Any]]:
        """Detect embedded files within the main file."""
        embedded_files = []
        
        # Common file signatures
        signatures = {
            'PE': b'MZ',
            'PDF': b'%PDF',
            'ZIP': b'PK\x03\x04',
            'RAR': b'Rar!',
            'JPEG': b'\xff\xd8\xff',
            'PNG': b'\x89PNG'
        }
        
        for file_type, signature in signatures.items():
            offset = 0
            while True:
                pos = data.find(signature, offset)
                if pos == -1:
                    break
                
                if pos > 0:  # Not at the beginning, so it's embedded
                    embedded_files.append({
                        'type': file_type,
                        'offset': pos,
                        'signature': signature.hex()
                    })
                
                offset = pos + 1
        
        return embedded_files
    
    def _count_imports(self, data: bytes) -> int:
        """Count the number of imported functions (rough estimate)."""
        try:
            text_data = data.decode('utf-8', errors='ignore')
            # Look for common import patterns
            import_patterns = [
                'kernel32.dll', 'user32.dll', 'ntdll.dll', 'advapi32.dll',
                'ws2_32.dll', 'wininet.dll', 'shell32.dll'
            ]
            
            import_count = 0
            for pattern in import_patterns:
                if pattern.lower() in text_data.lower():
                    import_count += 1
            
            return import_count
        except:
            return 0
    
    def _is_benign_ip(self, ip: str) -> bool:
        """Check if an IP address is likely benign (local, broadcast, etc.)."""
        parts = ip.split('.')
        if len(parts) != 4:
            return True
        
        try:
            octets = [int(part) for part in parts]
        except ValueError:
            return True
        
        # Local networks
        if octets[0] == 127:  # Loopback
            return True
        if octets[0] == 10:  # Private class A
            return True
        if octets[0] == 172 and 16 <= octets[1] <= 31:  # Private class B
            return True
        if octets[0] == 192 and octets[1] == 168:  # Private class C
            return True
        if octets[0] == 169 and octets[1] == 254:  # Link-local
            return True
        
        return False


def create_heuristic_detection(file_path: str, heuristic_result: HeuristicResult) -> Optional[Detection]:
    """Create a Detection object from heuristic analysis results."""
    if heuristic_result.risk_score < 30:  # Threshold for detection
        return None
    
    threat_name = f"Heuristic.Suspicious.{heuristic_result.risk_score}"
    description = f"Heuristic analysis detected suspicious patterns: {', '.join(heuristic_result.suspicious_patterns[:3])}"
    
    return Detection(
        file_path=file_path,
        threat_name=threat_name,
        detection_type=DetectionType.HEURISTIC,
        risk_score=heuristic_result.risk_score,
        description=description,
        confidence=heuristic_result.confidence
    )