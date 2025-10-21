"""
File analysis utilities for the Educational Antivirus Research Tool.

This module provides functions for file hash calculation, entropy analysis,
file type detection, and metadata extraction.
"""
import hashlib
import os
import stat
import math
import mimetypes
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from .models import FileInfo


def calculate_md5(file_path: str) -> str:
    """
    Calculate MD5 hash of a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        MD5 hash as hexadecimal string
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file cannot be read
    """
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
    except (FileNotFoundError, PermissionError) as e:
        raise e
    except Exception as e:
        raise IOError(f"Error reading file {file_path}: {e}")
    
    return hash_md5.hexdigest()


def calculate_sha256(file_path: str) -> str:
    """
    Calculate SHA256 hash of a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        SHA256 hash as hexadecimal string
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file cannot be read
    """
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
    except (FileNotFoundError, PermissionError) as e:
        raise e
    except Exception as e:
        raise IOError(f"Error reading file {file_path}: {e}")
    
    return hash_sha256.hexdigest()


def calculate_entropy(file_path: str) -> float:
    """
    Calculate Shannon entropy of a file.
    
    Higher entropy values (closer to 8.0) may indicate compressed or encrypted data,
    which could be suspicious in certain contexts.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Entropy value between 0.0 and 8.0
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file cannot be read
    """
    try:
        with open(file_path, "rb") as f:
            # Count frequency of each byte value (0-255)
            byte_counts = [0] * 256
            total_bytes = 0
            
            # Read file in chunks for memory efficiency
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                    
                for byte in chunk:
                    byte_counts[byte] += 1
                    total_bytes += 1
            
            if total_bytes == 0:
                return 0.0
            
            # Calculate Shannon entropy
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    probability = count / total_bytes
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
    except (FileNotFoundError, PermissionError) as e:
        raise e
    except Exception as e:
        raise IOError(f"Error calculating entropy for {file_path}: {e}")


def detect_file_type(file_path: str) -> str:
    """
    Detect file type using multiple methods.
    
    Args:
        file_path: Path to the file
        
    Returns:
        File type string (MIME type or extension-based guess)
    """
    # First try MIME type detection
    mime_type, _ = mimetypes.guess_type(file_path)
    if mime_type:
        return mime_type
    
    # Fallback to extension-based detection
    extension = Path(file_path).suffix.lower()
    
    # Common file type mappings
    extension_map = {
        '.exe': 'application/x-executable',
        '.dll': 'application/x-msdownload',
        '.bat': 'application/x-bat',
        '.cmd': 'application/x-cmd',
        '.scr': 'application/x-screensaver',
        '.com': 'application/x-msdos-program',
        '.pif': 'application/x-pif',
        '.vbs': 'application/x-vbscript',
        '.js': 'application/javascript',
        '.jar': 'application/java-archive',
        '.class': 'application/java-vm',
        '.py': 'text/x-python',
        '.pl': 'text/x-perl',
        '.sh': 'application/x-sh',
        '.ps1': 'application/x-powershell',
    }
    
    return extension_map.get(extension, 'application/octet-stream')


def get_file_permissions(file_path: str) -> str:
    """
    Get file permissions as a string.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Permission string in format like 'rwxr--r--'
        
    Raises:
        FileNotFoundError: If file doesn't exist
    """
    try:
        file_stat = os.stat(file_path)
        mode = file_stat.st_mode
        
        # Convert to rwx format
        permissions = []
        
        # Owner permissions
        permissions.append('r' if mode & stat.S_IRUSR else '-')
        permissions.append('w' if mode & stat.S_IWUSR else '-')
        permissions.append('x' if mode & stat.S_IXUSR else '-')
        
        # Group permissions
        permissions.append('r' if mode & stat.S_IRGRP else '-')
        permissions.append('w' if mode & stat.S_IWGRP else '-')
        permissions.append('x' if mode & stat.S_IXGRP else '-')
        
        # Other permissions
        permissions.append('r' if mode & stat.S_IROTH else '-')
        permissions.append('w' if mode & stat.S_IWOTH else '-')
        permissions.append('x' if mode & stat.S_IXOTH else '-')
        
        return ''.join(permissions)
        
    except FileNotFoundError as e:
        raise e
    except Exception as e:
        raise IOError(f"Error getting permissions for {file_path}: {e}")


def extract_file_metadata(file_path: str) -> FileInfo:
    """
    Extract comprehensive metadata from a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        FileInfo object containing all file metadata
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file cannot be accessed
    """
    try:
        # Get basic file stats
        file_stat = os.stat(file_path)
        
        # Extract all metadata
        size = file_stat.st_size
        creation_time = datetime.fromtimestamp(file_stat.st_ctime)
        modification_time = datetime.fromtimestamp(file_stat.st_mtime)
        permissions = get_file_permissions(file_path)
        file_type = detect_file_type(file_path)
        
        # Calculate hashes and entropy
        hash_md5 = calculate_md5(file_path)
        hash_sha256 = calculate_sha256(file_path)
        entropy = calculate_entropy(file_path)
        
        return FileInfo(
            path=file_path,
            size=size,
            file_type=file_type,
            entropy=entropy,
            creation_time=creation_time,
            modification_time=modification_time,
            permissions=permissions,
            hash_md5=hash_md5,
            hash_sha256=hash_sha256
        )
        
    except (FileNotFoundError, PermissionError) as e:
        raise e
    except Exception as e:
        raise IOError(f"Error extracting metadata from {file_path}: {e}")


def is_suspicious_file_type(file_path: str) -> bool:
    """
    Check if file type is commonly associated with malware.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if file type is potentially suspicious
    """
    suspicious_extensions = {
        '.exe', '.dll', '.bat', '.cmd', '.scr', '.com', '.pif',
        '.vbs', '.vbe', '.js', '.jse', '.jar', '.class', '.ps1'
    }
    
    extension = Path(file_path).suffix.lower()
    return extension in suspicious_extensions


def get_file_size_category(size: int) -> str:
    """
    Categorize file size for analysis purposes.
    
    Args:
        size: File size in bytes
        
    Returns:
        Size category string
    """
    if size == 0:
        return "empty"
    elif size < 1024:
        return "tiny"  # < 1KB
    elif size < 1024 * 1024:
        return "small"  # < 1MB
    elif size < 10 * 1024 * 1024:
        return "medium"  # < 10MB
    elif size < 100 * 1024 * 1024:
        return "large"  # < 100MB
    else:
        return "very_large"  # >= 100MB


def analyze_file_characteristics(file_info: FileInfo) -> Dict[str, Any]:
    """
    Analyze file characteristics for behavioral detection.
    
    Args:
        file_info: FileInfo object with file metadata
        
    Returns:
        Dictionary with analysis results
    """
    characteristics = {
        'is_executable': file_info.file_type.startswith('application/x-'),
        'is_suspicious_type': is_suspicious_file_type(file_info.path),
        'high_entropy': file_info.entropy > 7.5,
        'size_category': get_file_size_category(file_info.size),
        'is_hidden': Path(file_info.path).name.startswith('.'),
        'has_double_extension': len(Path(file_info.path).suffixes) > 1,
        'entropy_score': file_info.entropy,
        'size_bytes': file_info.size
    }
    
    return characteristics


# Compatibility aliases for other modules
def calculate_file_hash(file_path: str, algorithm: str = 'md5') -> str:
    """Calculate file hash (compatibility function)."""
    if algorithm.lower() == 'md5':
        return calculate_md5(file_path)
    elif algorithm.lower() == 'sha256':
        return calculate_sha256(file_path)
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def get_file_info(file_path: str) -> FileInfo:
    """Get file information (compatibility function)."""
    return extract_file_metadata(file_path)