#!/usr/bin/env python3
"""
Threat Intelligence Integration for Educational Antivirus Tool.

This module provides integration with various threat intelligence sources
including VirusTotal, MISP, and Open Threat Exchange (OTX) for educational purposes.
"""
import hashlib
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import urllib.request
import urllib.parse
import urllib.error

from core.models import Detection, DetectionType


@dataclass
class ThreatIntelResult:
    """Results from threat intelligence lookup."""
    file_hash: str
    source: str
    malicious: bool
    confidence: float
    threat_names: List[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    scan_results: Dict[str, Any]
    reputation_score: int
    additional_info: Dict[str, Any]


@dataclass
class ThreatIntelConfig:
    """Configuration for threat intelligence services."""
    virustotal_api_key: str = ""
    misp_url: str = ""
    misp_api_key: str = ""
    otx_api_key: str = ""
    enable_virustotal: bool = False
    enable_misp: bool = False
    enable_otx: bool = False
    cache_duration_hours: int = 24
    max_requests_per_minute: int = 4  # VirusTotal free tier limit


class ThreatIntelligenceManager:
    """Manager for threat intelligence operations."""
    
    def __init__(self, config: ThreatIntelConfig):
        """Initialize threat intelligence manager."""
        self.config = config
        self.cache = {}  # Simple in-memory cache
        self.request_timestamps = []  # Rate limiting
        
        # Initialize connectors
        self.connectors = {}
        
        if config.enable_virustotal and config.virustotal_api_key:
            self.connectors['virustotal'] = VirusTotalConnector(config.virustotal_api_key)
        
        if config.enable_misp and config.misp_url and config.misp_api_key:
            self.connectors['misp'] = MISPConnector(config.misp_url, config.misp_api_key)
        
        if config.enable_otx and config.otx_api_key:
            self.connectors['otx'] = OTXConnector(config.otx_api_key)
        
        print(f"🌐 Threat Intelligence initialized with {len(self.connectors)} sources")
    
    def lookup_file_hash(self, file_hash: str, hash_type: str = "sha256") -> List[ThreatIntelResult]:
        """Lookup file hash across all enabled threat intelligence sources."""
        results = []
        
        # Check cache first
        cache_key = f"{hash_type}:{file_hash}"
        if cache_key in self.cache:
            cached_result, timestamp = self.cache[cache_key]
            if datetime.now() - timestamp < timedelta(hours=self.config.cache_duration_hours):
                print(f"📋 Using cached result for {file_hash[:8]}...")
                return cached_result
        
        print(f"🔍 Looking up {hash_type.upper()} hash: {file_hash[:8]}...")
        
        # Query each enabled source
        for source_name, connector in self.connectors.items():
            try:
                # Rate limiting
                self._enforce_rate_limit()
                
                print(f"  📡 Querying {source_name}...")
                result = connector.lookup_hash(file_hash, hash_type)
                
                if result:
                    results.append(result)
                    print(f"  ✅ {source_name}: {'Malicious' if result.malicious else 'Clean'}")
                else:
                    print(f"  ❓ {source_name}: No data")
                
                # Small delay between requests
                time.sleep(1)
                
            except Exception as e:
                print(f"  ❌ {source_name} error: {e}")
                continue
        
        # Cache results
        self.cache[cache_key] = (results, datetime.now())
        
        return results
    
    def lookup_ip_address(self, ip_address: str) -> List[ThreatIntelResult]:
        """Lookup IP address reputation."""
        results = []
        
        print(f"🔍 Looking up IP address: {ip_address}")
        
        for source_name, connector in self.connectors.items():
            if hasattr(connector, 'lookup_ip'):
                try:
                    self._enforce_rate_limit()
                    result = connector.lookup_ip(ip_address)
                    
                    if result:
                        results.append(result)
                        print(f"  ✅ {source_name}: {'Malicious' if result.malicious else 'Clean'}")
                    
                    time.sleep(1)
                    
                except Exception as e:
                    print(f"  ❌ {source_name} error: {e}")
                    continue
        
        return results
    
    def lookup_domain(self, domain: str) -> List[ThreatIntelResult]:
        """Lookup domain reputation."""
        results = []
        
        print(f"🔍 Looking up domain: {domain}")
        
        for source_name, connector in self.connectors.items():
            if hasattr(connector, 'lookup_domain'):
                try:
                    self._enforce_rate_limit()
                    result = connector.lookup_domain(domain)
                    
                    if result:
                        results.append(result)
                        print(f"  ✅ {source_name}: {'Malicious' if result.malicious else 'Clean'}")
                    
                    time.sleep(1)
                    
                except Exception as e:
                    print(f"  ❌ {source_name} error: {e}")
                    continue
        
        return results
    
    def get_reputation_score(self, file_hash: str, hash_type: str = "sha256") -> Tuple[int, float]:
        """Get aggregated reputation score for a file hash."""
        results = self.lookup_file_hash(file_hash, hash_type)
        
        if not results:
            return 0, 0.0  # Unknown
        
        # Calculate weighted reputation score
        total_weight = 0
        weighted_score = 0
        
        for result in results:
            # Weight based on source reliability
            source_weight = self._get_source_weight(result.source)
            
            if result.malicious:
                score = -result.confidence * 100  # Negative for malicious
            else:
                score = result.confidence * 100   # Positive for clean
            
            weighted_score += score * source_weight
            total_weight += source_weight
        
        if total_weight == 0:
            return 0, 0.0
        
        final_score = int(weighted_score / total_weight)
        confidence = min(1.0, total_weight / len(self.connectors))
        
        return final_score, confidence
    
    def create_detection_from_intel(self, file_path: str, file_hash: str, 
                                  intel_results: List[ThreatIntelResult]) -> Optional[Detection]:
        """Create a Detection object from threat intelligence results."""
        malicious_results = [r for r in intel_results if r.malicious]
        
        if not malicious_results:
            return None
        
        # Get the most confident malicious result
        best_result = max(malicious_results, key=lambda r: r.confidence)
        
        # Create threat name from intelligence
        if best_result.threat_names:
            threat_name = best_result.threat_names[0]
        else:
            threat_name = f"ThreatIntel.Malicious.{best_result.source}"
        
        # Calculate risk score
        risk_score = min(100, int(best_result.confidence * 100))
        
        # Create description
        sources = [r.source for r in malicious_results]
        description = f"Threat intelligence indicates malicious file (Sources: {', '.join(sources)})"
        
        return Detection(
            file_path=file_path,
            threat_name=threat_name,
            detection_type=DetectionType.HEURISTIC,  # Threat intel is heuristic
            risk_score=risk_score,
            description=description,
            confidence=best_result.confidence
        )
    
    def _enforce_rate_limit(self):
        """Enforce rate limiting for API requests."""
        now = time.time()
        
        # Remove old timestamps
        self.request_timestamps = [ts for ts in self.request_timestamps if now - ts < 60]
        
        # Check if we're at the limit
        if len(self.request_timestamps) >= self.config.max_requests_per_minute:
            sleep_time = 60 - (now - self.request_timestamps[0])
            if sleep_time > 0:
                print(f"⏳ Rate limit reached, waiting {sleep_time:.1f} seconds...")
                time.sleep(sleep_time)
        
        # Record this request
        self.request_timestamps.append(now)
    
    def _get_source_weight(self, source: str) -> float:
        """Get reliability weight for a threat intelligence source."""
        weights = {
            'virustotal': 1.0,
            'misp': 0.8,
            'otx': 0.7,
            'local': 0.5
        }
        return weights.get(source.lower(), 0.5)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        return {
            'enabled_sources': list(self.connectors.keys()),
            'cache_entries': len(self.cache),
            'requests_last_minute': len([ts for ts in self.request_timestamps 
                                       if time.time() - ts < 60])
        }


class VirusTotalConnector:
    """VirusTotal API connector for educational purposes."""
    
    def __init__(self, api_key: str):
        """Initialize VirusTotal connector."""
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        
        # Note: This is a simplified educational implementation
        # Real VirusTotal integration would use their official API
    
    def lookup_hash(self, file_hash: str, hash_type: str = "sha256") -> Optional[ThreatIntelResult]:
        """Lookup file hash in VirusTotal (educational simulation)."""
        # This is a simulated response for educational purposes
        # In a real implementation, this would make actual API calls
        
        print(f"  📡 [SIMULATED] VirusTotal lookup for {file_hash[:8]}...")
        
        # Simulate different responses based on hash
        if "eicar" in file_hash.lower() or file_hash.startswith("44d88612"):
            # EICAR test file - simulate detection
            return ThreatIntelResult(
                file_hash=file_hash,
                source="virustotal",
                malicious=True,
                confidence=0.95,
                threat_names=["EICAR-Test-File"],
                first_seen=datetime.now() - timedelta(days=30),
                last_seen=datetime.now() - timedelta(days=1),
                scan_results={"positives": 58, "total": 70},
                reputation_score=-90,
                additional_info={"permalink": f"https://virustotal.com/file/{file_hash}"}
            )
        
        elif file_hash.startswith("a" * 8):
            # Simulate suspicious file
            return ThreatIntelResult(
                file_hash=file_hash,
                source="virustotal",
                malicious=True,
                confidence=0.75,
                threat_names=["Trojan.Generic.Suspicious"],
                first_seen=datetime.now() - timedelta(days=7),
                last_seen=datetime.now() - timedelta(hours=2),
                scan_results={"positives": 12, "total": 70},
                reputation_score=-60,
                additional_info={"permalink": f"https://virustotal.com/file/{file_hash}"}
            )
        
        else:
            # Simulate clean file
            return ThreatIntelResult(
                file_hash=file_hash,
                source="virustotal",
                malicious=False,
                confidence=0.90,
                threat_names=[],
                first_seen=datetime.now() - timedelta(days=100),
                last_seen=datetime.now() - timedelta(days=10),
                scan_results={"positives": 0, "total": 70},
                reputation_score=80,
                additional_info={"permalink": f"https://virustotal.com/file/{file_hash}"}
            )
    
    def lookup_ip(self, ip_address: str) -> Optional[ThreatIntelResult]:
        """Lookup IP address in VirusTotal (educational simulation)."""
        print(f"  📡 [SIMULATED] VirusTotal IP lookup for {ip_address}")
        
        # Simulate malicious IP detection
        if ip_address.startswith("192.168.") or ip_address.startswith("10."):
            # Private IP - clean
            return ThreatIntelResult(
                file_hash=ip_address,
                source="virustotal",
                malicious=False,
                confidence=0.95,
                threat_names=[],
                first_seen=None,
                last_seen=None,
                scan_results={"positives": 0, "total": 85},
                reputation_score=90,
                additional_info={"country": "Private Network"}
            )
        else:
            # Simulate some malicious IPs
            return ThreatIntelResult(
                file_hash=ip_address,
                source="virustotal",
                malicious=True,
                confidence=0.80,
                threat_names=["Malicious IP", "C&C Server"],
                first_seen=datetime.now() - timedelta(days=15),
                last_seen=datetime.now() - timedelta(hours=6),
                scan_results={"positives": 8, "total": 85},
                reputation_score=-70,
                additional_info={"country": "Unknown"}
            )
    
    def lookup_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """Lookup domain in VirusTotal (educational simulation)."""
        print(f"  📡 [SIMULATED] VirusTotal domain lookup for {domain}")
        
        # Simulate domain reputation
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return ThreatIntelResult(
                file_hash=domain,
                source="virustotal",
                malicious=True,
                confidence=0.70,
                threat_names=["Suspicious Domain", "Phishing"],
                first_seen=datetime.now() - timedelta(days=5),
                last_seen=datetime.now() - timedelta(hours=1),
                scan_results={"positives": 15, "total": 85},
                reputation_score=-65,
                additional_info={"registrar": "Unknown"}
            )
        else:
            return ThreatIntelResult(
                file_hash=domain,
                source="virustotal",
                malicious=False,
                confidence=0.85,
                threat_names=[],
                first_seen=datetime.now() - timedelta(days=365),
                last_seen=datetime.now() - timedelta(days=1),
                scan_results={"positives": 0, "total": 85},
                reputation_score=75,
                additional_info={"registrar": "Legitimate"}
            )


class MISPConnector:
    """MISP (Malware Information Sharing Platform) connector."""
    
    def __init__(self, misp_url: str, api_key: str):
        """Initialize MISP connector."""
        self.misp_url = misp_url
        self.api_key = api_key
    
    def lookup_hash(self, file_hash: str, hash_type: str = "sha256") -> Optional[ThreatIntelResult]:
        """Lookup file hash in MISP (educational simulation)."""
        print(f"  📡 [SIMULATED] MISP lookup for {file_hash[:8]}...")
        
        # Simulate MISP response
        if file_hash.startswith("bad"):
            return ThreatIntelResult(
                file_hash=file_hash,
                source="misp",
                malicious=True,
                confidence=0.85,
                threat_names=["APT.Malware.Sample"],
                first_seen=datetime.now() - timedelta(days=20),
                last_seen=datetime.now() - timedelta(days=3),
                scan_results={"events": 3, "attributes": 15},
                reputation_score=-80,
                additional_info={"misp_events": ["Event-123", "Event-456"]}
            )
        
        return None  # No data found


class OTXConnector:
    """Open Threat Exchange (OTX) connector."""
    
    def __init__(self, api_key: str):
        """Initialize OTX connector."""
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
    
    def lookup_hash(self, file_hash: str, hash_type: str = "sha256") -> Optional[ThreatIntelResult]:
        """Lookup file hash in OTX (educational simulation)."""
        print(f"  📡 [SIMULATED] OTX lookup for {file_hash[:8]}...")
        
        # Simulate OTX response
        if file_hash.startswith("evil"):
            return ThreatIntelResult(
                file_hash=file_hash,
                source="otx",
                malicious=True,
                confidence=0.75,
                threat_names=["Generic.Malware"],
                first_seen=datetime.now() - timedelta(days=10),
                last_seen=datetime.now() - timedelta(days=1),
                scan_results={"pulses": 5, "indicators": 25},
                reputation_score=-70,
                additional_info={"otx_pulses": ["Pulse-789", "Pulse-012"]}
            )
        
        return None  # No data found


class LocalThreatIntelDB:
    """Local threat intelligence database for offline operation."""
    
    def __init__(self, db_path: str = "data/threat_intel.json"):
        """Initialize local threat intelligence database."""
        self.db_path = db_path
        self.data = self._load_database()
    
    def _load_database(self) -> Dict[str, Any]:
        """Load threat intelligence database."""
        try:
            with open(self.db_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # Create default database
            default_data = {
                "hashes": {
                    # EICAR test file hashes
                    "44d88612fea8a8f36de82e1278abb02f": {
                        "malicious": True,
                        "threat_names": ["EICAR-Test-File"],
                        "confidence": 1.0,
                        "first_seen": "2024-01-01T00:00:00Z"
                    },
                    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
                        "malicious": True,
                        "threat_names": ["EICAR-Test-File"],
                        "confidence": 1.0,
                        "first_seen": "2024-01-01T00:00:00Z"
                    }
                },
                "ips": {},
                "domains": {},
                "last_updated": datetime.now().isoformat()
            }
            
            self._save_database(default_data)
            return default_data
    
    def _save_database(self, data: Dict[str, Any]):
        """Save threat intelligence database."""
        try:
            import os
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with open(self.db_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"❌ Failed to save threat intel database: {e}")
    
    def lookup_hash(self, file_hash: str, hash_type: str = "sha256") -> Optional[ThreatIntelResult]:
        """Lookup file hash in local database."""
        hash_data = self.data.get("hashes", {}).get(file_hash.lower())
        
        if hash_data:
            return ThreatIntelResult(
                file_hash=file_hash,
                source="local",
                malicious=hash_data.get("malicious", False),
                confidence=hash_data.get("confidence", 0.5),
                threat_names=hash_data.get("threat_names", []),
                first_seen=datetime.fromisoformat(hash_data.get("first_seen", datetime.now().isoformat())),
                last_seen=None,
                scan_results={},
                reputation_score=-90 if hash_data.get("malicious") else 80,
                additional_info={"source": "local_database"}
            )
        
        return None
    
    def add_hash(self, file_hash: str, malicious: bool, threat_names: List[str], confidence: float = 1.0):
        """Add hash to local database."""
        self.data.setdefault("hashes", {})[file_hash.lower()] = {
            "malicious": malicious,
            "threat_names": threat_names,
            "confidence": confidence,
            "first_seen": datetime.now().isoformat()
        }
        
        self.data["last_updated"] = datetime.now().isoformat()
        self._save_database(self.data)


def create_threat_intel_manager(config: Optional[ThreatIntelConfig] = None) -> ThreatIntelligenceManager:
    """Create a threat intelligence manager with default configuration."""
    if config is None:
        config = ThreatIntelConfig(
            # Educational configuration - no real API keys
            enable_virustotal=True,  # Will use simulation
            enable_misp=False,
            enable_otx=False,
            cache_duration_hours=24,
            max_requests_per_minute=4
        )
    
    return ThreatIntelligenceManager(config)


def calculate_file_hashes(file_path: str) -> Dict[str, str]:
    """Calculate multiple hash types for a file."""
    hashes = {}
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        hashes['md5'] = hashlib.md5(data).hexdigest()
        hashes['sha1'] = hashlib.sha1(data).hexdigest()
        hashes['sha256'] = hashlib.sha256(data).hexdigest()
        
    except Exception as e:
        print(f"❌ Error calculating hashes for {file_path}: {e}")
    
    return hashes


# Example usage and testing
if __name__ == "__main__":
    print("🧪 Testing Threat Intelligence Integration")
    
    # Create threat intel manager
    config = ThreatIntelConfig(enable_virustotal=True)
    manager = create_threat_intel_manager(config)
    
    # Test hash lookups
    test_hashes = [
        "44d88612fea8a8f36de82e1278abb02f",  # EICAR MD5
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",  # Simulated malicious
        "1234567890abcdef1234567890abcdef"   # Simulated clean
    ]
    
    for test_hash in test_hashes:
        print(f"\n🔍 Testing hash: {test_hash}")
        results = manager.lookup_file_hash(test_hash, "md5")
        
        for result in results:
            print(f"  Source: {result.source}")
            print(f"  Malicious: {result.malicious}")
            print(f"  Confidence: {result.confidence}")
            print(f"  Threat Names: {result.threat_names}")
        
        # Test reputation scoring
        score, confidence = manager.get_reputation_score(test_hash, "md5")
        print(f"  Reputation Score: {score} (confidence: {confidence:.2f})")
    
    # Test statistics
    stats = manager.get_statistics()
    print(f"\n📊 Statistics: {stats}")