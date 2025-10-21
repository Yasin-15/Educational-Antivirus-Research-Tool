"""
Pattern matching algorithms for signature detection.
"""
import re
from typing import List, Tuple, Iterator, Optional
from dataclasses import dataclass

from core.exceptions import SignatureError
from core.logging_config import get_logger
from .signature_models import Signature, SignatureMatch, SignatureType

logger = get_logger(__name__)


@dataclass
class MatchResult:
    """Result of a pattern match operation."""
    offset: int
    length: int
    confidence: float
    context_start: int
    context_end: int


class PatternMatcher:
    """Handles pattern matching for different signature types."""
    
    def __init__(self, sensitivity: int = 5):
        """Initialize pattern matcher.
        
        Args:
            sensitivity: Matching sensitivity (1-10, higher = more sensitive)
        """
        if not 1 <= sensitivity <= 10:
            raise SignatureError("Sensitivity must be between 1 and 10")
        
        self.sensitivity = sensitivity
        self.context_size = 32  # Bytes of context to capture around matches
    
    def match_signature(self, signature: Signature, file_data: bytes, file_path: str) -> List[SignatureMatch]:
        """Match a signature against file data.
        
        Args:
            signature: Signature to match
            file_data: File content as bytes
            file_path: Path to the file being scanned
            
        Returns:
            List of SignatureMatch objects for all matches found
        """
        matches = []
        
        try:
            if signature.signature_type == SignatureType.EXACT_MATCH:
                match_results = self._exact_match(signature.pattern, file_data)
            elif signature.signature_type == SignatureType.PATTERN_MATCH:
                match_results = self._pattern_match(signature.pattern, file_data)
            elif signature.signature_type == SignatureType.HASH_MATCH:
                match_results = self._hash_match(signature.pattern, file_data)
            elif signature.signature_type == SignatureType.EICAR:
                match_results = self._eicar_match(signature.pattern, file_data)
            else:
                logger.warning(f"Unknown signature type: {signature.signature_type}")
                return matches
            
            # Convert match results to SignatureMatch objects
            for match_result in match_results:
                context = self._extract_context(file_data, match_result.offset, match_result.length)
                
                signature_match = SignatureMatch(
                    signature=signature,
                    file_path=file_path,
                    match_offset=match_result.offset,
                    match_length=match_result.length,
                    confidence=match_result.confidence,
                    context=context
                )
                matches.append(signature_match)
            
            if matches:
                logger.info(f"Found {len(matches)} matches for signature '{signature.name}' in {file_path}")
            
        except Exception as e:
            logger.error(f"Error matching signature '{signature.signature_id}': {e}")
            raise SignatureError(f"Pattern matching failed: {e}")
        
        return matches
    
    def _exact_match(self, pattern: bytes, data: bytes) -> List[MatchResult]:
        """Perform exact byte sequence matching.
        
        Args:
            pattern: Exact byte pattern to match
            data: Data to search in
            
        Returns:
            List of MatchResult objects
        """
        matches = []
        start = 0
        
        while True:
            offset = data.find(pattern, start)
            if offset == -1:
                break
            
            # Calculate confidence based on pattern length and sensitivity
            confidence = min(1.0, (len(pattern) / 10.0) * (self.sensitivity / 10.0))
            confidence = max(0.1, confidence)  # Minimum confidence
            
            matches.append(MatchResult(
                offset=offset,
                length=len(pattern),
                confidence=confidence,
                context_start=max(0, offset - self.context_size),
                context_end=min(len(data), offset + len(pattern) + self.context_size)
            ))
            
            start = offset + 1  # Continue searching after this match
        
        return matches
    
    def _pattern_match(self, pattern: bytes, data: bytes) -> List[MatchResult]:
        """Perform regex pattern matching.
        
        Args:
            pattern: Regex pattern as bytes
            data: Data to search in
            
        Returns:
            List of MatchResult objects
        """
        matches = []
        
        try:
            # Convert bytes pattern to regex pattern
            # For educational purposes, we'll support simple wildcard patterns
            pattern_str = pattern.decode('latin-1', errors='ignore')
            
            # Convert simple wildcards to regex
            # ? = any single byte, * = any sequence of bytes
            regex_pattern = pattern_str.replace('?', '.').replace('*', '.*')
            
            # Compile regex with case-insensitive and multiline flags
            regex = re.compile(regex_pattern.encode('latin-1'), re.IGNORECASE | re.MULTILINE)
            
            for match in regex.finditer(data):
                # Calculate confidence based on match length and sensitivity
                match_length = match.end() - match.start()
                confidence = min(1.0, (match_length / 20.0) * (self.sensitivity / 10.0))
                confidence = max(0.1, confidence)
                
                matches.append(MatchResult(
                    offset=match.start(),
                    length=match_length,
                    confidence=confidence,
                    context_start=max(0, match.start() - self.context_size),
                    context_end=min(len(data), match.end() + self.context_size)
                ))
        
        except re.error as e:
            logger.warning(f"Invalid regex pattern: {e}")
        except UnicodeDecodeError as e:
            logger.warning(f"Pattern encoding error: {e}")
        
        return matches
    
    def _hash_match(self, pattern: bytes, data: bytes) -> List[MatchResult]:
        """Perform hash-based matching.
        
        Args:
            pattern: Hash value as bytes
            data: Data to compute hash from
            
        Returns:
            List of MatchResult objects
        """
        matches = []
        
        try:
            import hashlib
            
            # Support MD5 and SHA256 hashes
            if len(pattern) == 32:  # MD5 hex string
                file_hash = hashlib.md5(data).hexdigest().encode()
            elif len(pattern) == 64:  # SHA256 hex string
                file_hash = hashlib.sha256(data).hexdigest().encode()
            else:
                logger.warning(f"Unsupported hash length: {len(pattern)}")
                return matches
            
            if file_hash.lower() == pattern.lower():
                # Full file hash match
                confidence = 1.0  # Hash matches are always high confidence
                
                matches.append(MatchResult(
                    offset=0,
                    length=len(data),
                    confidence=confidence,
                    context_start=0,
                    context_end=min(len(data), self.context_size * 2)
                ))
        
        except Exception as e:
            logger.warning(f"Hash calculation error: {e}")
        
        return matches
    
    def _eicar_match(self, pattern: bytes, data: bytes) -> List[MatchResult]:
        """Perform EICAR test string matching.
        
        Args:
            pattern: EICAR pattern (should be the standard EICAR string)
            data: Data to search in
            
        Returns:
            List of MatchResult objects
        """
        # Standard EICAR test strings
        eicar_strings = [
            b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
            b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\x00'
        ]
        
        matches = []
        
        # Check for any EICAR variant
        for eicar_string in eicar_strings:
            start = 0
            while True:
                offset = data.find(eicar_string, start)
                if offset == -1:
                    break
                
                # EICAR matches are always high confidence
                confidence = 1.0
                
                matches.append(MatchResult(
                    offset=offset,
                    length=len(eicar_string),
                    confidence=confidence,
                    context_start=max(0, offset - self.context_size),
                    context_end=min(len(data), offset + len(eicar_string) + self.context_size)
                ))
                
                start = offset + 1
        
        return matches
    
    def _extract_context(self, data: bytes, offset: int, length: int) -> bytes:
        """Extract context bytes around a match.
        
        Args:
            data: Full file data
            offset: Match offset
            length: Match length
            
        Returns:
            Context bytes around the match
        """
        start = max(0, offset - self.context_size)
        end = min(len(data), offset + length + self.context_size)
        return data[start:end]
    
    def set_sensitivity(self, sensitivity: int) -> None:
        """Update matching sensitivity.
        
        Args:
            sensitivity: New sensitivity level (1-10)
        """
        if not 1 <= sensitivity <= 10:
            raise SignatureError("Sensitivity must be between 1 and 10")
        
        self.sensitivity = sensitivity
        logger.info(f"Pattern matcher sensitivity set to {sensitivity}")


class MultiPatternMatcher:
    """Optimized matcher for multiple patterns using efficient algorithms."""
    
    def __init__(self, signatures: List[Signature], sensitivity: int = 5):
        """Initialize multi-pattern matcher.
        
        Args:
            signatures: List of signatures to match
            sensitivity: Matching sensitivity (1-10)
        """
        self.signatures = signatures
        self.matcher = PatternMatcher(sensitivity)
        self._build_pattern_index()
    
    def _build_pattern_index(self) -> None:
        """Build an index of patterns for efficient matching."""
        self.exact_patterns = []
        self.regex_patterns = []
        self.hash_patterns = []
        self.eicar_patterns = []
        
        for signature in self.signatures:
            if not signature.enabled:
                continue
                
            if signature.signature_type == SignatureType.EXACT_MATCH:
                self.exact_patterns.append(signature)
            elif signature.signature_type == SignatureType.PATTERN_MATCH:
                self.regex_patterns.append(signature)
            elif signature.signature_type == SignatureType.HASH_MATCH:
                self.hash_patterns.append(signature)
            elif signature.signature_type == SignatureType.EICAR:
                self.eicar_patterns.append(signature)
    
    def match_all(self, file_data: bytes, file_path: str) -> List[SignatureMatch]:
        """Match all signatures against file data.
        
        Args:
            file_data: File content as bytes
            file_path: Path to the file being scanned
            
        Returns:
            List of all SignatureMatch objects found
        """
        all_matches = []
        
        # Process each signature type
        for signature in self.signatures:
            if not signature.enabled:
                continue
            
            try:
                matches = self.matcher.match_signature(signature, file_data, file_path)
                all_matches.extend(matches)
            except Exception as e:
                logger.error(f"Error matching signature {signature.signature_id}: {e}")
        
        # Sort matches by offset for consistent ordering
        all_matches.sort(key=lambda m: m.match_offset)
        
        return all_matches