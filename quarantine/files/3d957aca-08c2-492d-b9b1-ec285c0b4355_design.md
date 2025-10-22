# Educational Antivirus Research Tool - Design Document

## Overview

The Educational Antivirus Research Tool is a Python-based application designed to teach cybersecurity concepts through hands-on experience with antivirus detection mechanisms. The system provides a safe, controlled environment for learning about signature-based detection, behavioral analysis, quarantine management, and threat reporting using completely harmless test files.

## Architecture

The system follows a modular architecture with clear separation of concerns:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Interface │    │   Web Dashboard │    │  Configuration  │
│                 │    │    (Optional)   │    │    Manager      │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────┴───────────┐
                    │     Core Engine         │
                    │  - Scanner Controller   │
                    │  - Detection Manager    │
                    │  - Report Generator     │
                    └─────────────┬───────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
┌───────▼────────┐    ┌───────────▼──────────┐    ┌────────▼────────┐
│ Signature      │    │ Behavioral Analysis  │    │ Quarantine      │
│ Detection      │    │ Engine               │    │ Manager         │
│ Engine         │    │                      │    │                 │
└────────────────┘    └──────────────────────┘    └─────────────────┘
        │                         │                         │
┌───────▼────────┐    ┌───────────▼──────────┐    ┌────────▼────────┐
│ Signature      │    │ File Analysis        │    │ File System     │
│ Database       │    │ Utilities            │    │ Operations      │
└────────────────┘    └──────────────────────┘    └─────────────────┘
```

## Components and Interfaces

### 1. Core Engine (`core/engine.py`)
Central orchestrator that coordinates all scanning operations.

**Key Methods:**
- `scan_path(path: str, options: ScanOptions) -> ScanResult`
- `scan_file(file_path: str) -> FileResult`
- `get_scan_history() -> List[ScanResult]`

### 2. Signature Detection Engine (`detection/signature_engine.py`)
Handles signature-based detection using pattern matching.

**Key Methods:**
- `load_signatures(signature_db_path: str) -> bool`
- `scan_file_signatures(file_path: str) -> List[Detection]`
- `add_custom_signature(name: str, pattern: bytes, description: str) -> bool`

### 3. Behavioral Analysis Engine (`detection/behavioral_engine.py`)
Performs heuristic analysis based on file characteristics.

**Key Methods:**
- `analyze_file(file_path: str) -> BehavioralResult`
- `calculate_risk_score(file_info: FileInfo) -> int`
- `get_analysis_details(file_path: str) -> AnalysisDetails`

### 4. Test Sample Manager (`samples/sample_manager.py`)
Creates and manages harmless test malware samples.

**Key Methods:**
- `create_test_sample(sample_type: str, output_path: str) -> bool`
- `list_available_samples() -> List[SampleInfo]`
- `get_sample_metadata(sample_id: str) -> SampleMetadata`

### 5. Quarantine Manager (`quarantine/quarantine_manager.py`)
Handles safe isolation of detected files.

**Key Methods:**
- `quarantine_file(file_path: str, detection_info: Detection) -> bool`
- `list_quarantined_files() -> List[QuarantineEntry]`
- `restore_file(quarantine_id: str) -> bool`
- `delete_quarantined_file(quarantine_id: str) -> bool`

### 6. Report Generator (`reporting/report_generator.py`)
Creates detailed scan reports in multiple formats.

**Key Methods:**
- `generate_report(scan_result: ScanResult, format: str) -> str`
- `save_report(report: str, output_path: str) -> bool`
- `get_report_templates() -> List[str]`

## Data Models

### Core Data Structures

```python
@dataclass
class Detection:
    file_path: str
    detection_type: str  # 'signature' or 'behavioral'
    threat_name: str
    risk_score: int
    signature_id: Optional[str]
    timestamp: datetime
    details: Dict[str, Any]

@dataclass
class ScanResult:
    scan_id: str
    start_time: datetime
    end_time: datetime
    scanned_paths: List[str]
    total_files: int
    detections: List[Detection]
    errors: List[str]
    scan_options: ScanOptions

@dataclass
class FileInfo:
    path: str
    size: int
    file_type: str
    entropy: float
    creation_time: datetime
    modification_time: datetime
    permissions: str
    hash_md5: str
    hash_sha256: str

@dataclass
class SampleInfo:
    sample_id: str
    name: str
    sample_type: str
    description: str
    creation_date: datetime
    file_path: str
    signatures: List[str]
```

### Configuration Schema

```python
@dataclass
class Config:
    # Detection Settings
    signature_sensitivity: int = 5  # 1-10 scale
    behavioral_threshold: int = 7   # Risk score threshold
    max_file_size_mb: int = 100    # Skip files larger than this
    
    # Paths
    signature_db_path: str = "data/signatures.db"
    quarantine_path: str = "quarantine/"
    samples_path: str = "samples/"
    reports_path: str = "reports/"
    
    # Behavioral Analysis
    entropy_threshold: float = 7.5
    suspicious_extensions: List[str] = [".exe", ".scr", ".bat", ".cmd"]
    
    # Logging
    log_level: str = "INFO"
    log_file: str = "antivirus.log"
```

## Error Handling

### Exception Hierarchy
```python
class AntivirusError(Exception):
    """Base exception for antivirus operations"""
    pass

class ScanError(AntivirusError):
    """Raised when file scanning fails"""
    pass

class QuarantineError(AntivirusError):
    """Raised when quarantine operations fail"""
    pass

class SignatureError(AntivirusError):
    """Raised when signature operations fail"""
    pass

class ConfigurationError(AntivirusError):
    """Raised when configuration is invalid"""
    pass
```

### Error Handling Strategy
- **File Access Errors**: Log error, skip file, continue scanning
- **Permission Errors**: Attempt to request elevated permissions, fallback to read-only mode
- **Corrupted Signatures**: Load backup signature database, notify user
- **Quarantine Failures**: Log error, offer alternative actions (delete, ignore)
- **Configuration Errors**: Use default values, warn user about invalid settings

## Testing Strategy

### Unit Testing
- **Signature Engine**: Test pattern matching with known test signatures
- **Behavioral Engine**: Test risk scoring with controlled file samples
- **Quarantine Manager**: Test file isolation and restoration
- **Sample Manager**: Test creation and management of harmless samples

### Integration Testing
- **End-to-End Scanning**: Test complete scan workflow with test samples
- **Configuration Loading**: Test various configuration scenarios
- **Report Generation**: Test report creation in all supported formats

### Educational Test Samples
The system will include several categories of harmless test files:

1. **EICAR Test Files**: Standard antivirus test strings
2. **Custom Signature Tests**: Files with embedded harmless signatures
3. **Behavioral Test Files**: Files designed to trigger heuristic analysis
4. **Archive Tests**: Compressed files with nested test samples
5. **False Positive Tests**: Legitimate files that might trigger detection

### Security Considerations
- All test samples are completely harmless and contain no executable code
- Quarantine directory has restricted permissions
- File operations are sandboxed to prevent accidental system modification
- User confirmation required for potentially destructive operations
- Comprehensive logging for audit trails

### Performance Considerations
- Asynchronous file scanning for large directories
- Configurable file size limits to prevent memory issues
- Efficient signature matching using optimized algorithms
- Caching of file hashes to avoid redundant analysis
- Progress indicators for long-running operations

### Educational Features
- Interactive tutorials explaining detection methods
- Detailed explanations of why files were flagged
- Comparison of different detection techniques
- Historical analysis of scan results
- Customizable learning scenarios for different skill levels