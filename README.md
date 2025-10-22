# Educational Antivirus Research Tool

A Python-based educational antivirus tool designed for learning cybersecurity concepts, malware detection techniques, and antivirus development principles. This tool provides hands-on experience with signature-based detection, behavioral analysis, quarantine management, and security research methodologies.

## 🎯 Purpose

This tool is built for educational purposes to help students, researchers, and cybersecurity enthusiasts understand:

- How antivirus engines detect malware using signatures and behavioral analysis
- File analysis techniques including entropy calculation and pattern matching
- Quarantine systems and secure file isolation
- Security research methodologies and sample management
- Report generation and threat intelligence

## ✨ Features

### Core Detection Capabilities
- **Signature-based Detection**: Pattern matching against known malware signatures
- **Behavioral Analysis**: File entropy analysis, suspicious pattern detection, and risk scoring
- **Multi-engine Scanning**: Coordinated detection using multiple analysis methods
- **Configurable Sensitivity**: Adjustable detection thresholds and parameters

### Sample Management
- **Test Sample Generation**: Create harmless EICAR and custom test files
- **Sample Database**: Organized storage and metadata tracking for research samples
- **Educational Samples**: Pre-built samples for learning different detection techniques

### Quarantine System
- **Secure Isolation**: Safe quarantine of detected threats with restricted permissions
- **Quarantine Management**: List, restore, or permanently delete quarantined files
- **Metadata Tracking**: Detailed information about quarantined items

### Educational Features
- **Threat Information Database**: Educational descriptions of malware types and detection methods
- **Detection Explanations**: Learn why files were flagged and how detection works
- **Interactive Learning**: Hands-on experience with real antivirus concepts

### Reporting & Analysis
- **Multiple Report Formats**: JSON, CSV, and text-based reports
- **Scan Statistics**: Comprehensive analysis of scan results
- **Educational Content**: Detailed explanations and learning recommendations

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- PyYAML (automatically installed from requirements.txt)

### Installation

1. Clone or download this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Initialize the sample databases:
   ```bash
   python main.py init-samples
   ```

### Basic Usage

1. **Run a basic scan**:
   ```bash
   python main.py scan /path/to/scan
   ```

2. **View configuration**:
   ```bash
   python main.py config show
   ```

3. **Initialize with force reset** (recreate all databases):
   ```bash
   python main.py init-samples --force-reset
   ```

## 📋 Available Commands

### Sample Database Management
```bash
# Initialize sample databases
python main.py init-samples

# Force recreation of all databases
python main.py init-samples --force-reset

# Validate existing databases
python main.py init-samples --validate-only

# Repair corrupted databases
python main.py init-samples --repair
```

### Configuration Management
```bash
# Show all configuration settings
python main.py config show

# Show specific setting
python main.py config show signature_sensitivity
```

## ⚙️ Configuration

The tool uses a JSON configuration file with the following key settings:

```json
{
  "signature_sensitivity": 7,
  "behavioral_threshold": 6,
  "max_file_size_mb": 50,
  "entropy_threshold": 7.0,
  "suspicious_extensions": [".exe", ".scr", ".bat", ".cmd", ".vbs"],
  "log_level": "INFO",
  "recursive_scan": true,
  "follow_symlinks": false
}
```

### Key Configuration Options

- **signature_sensitivity**: Detection sensitivity level (1-10)
- **behavioral_threshold**: Behavioral analysis threshold (1-10)
- **entropy_threshold**: File entropy threshold for suspicious files
- **max_file_size_mb**: Maximum file size to scan
- **quarantine_path**: Directory for quarantined files
- **samples_path**: Directory for test samples

## 📁 Project Structure

```
├── core/                   # Core functionality modules
│   ├── config.py          # Configuration management
│   ├── models.py          # Data models and structures
│   ├── exceptions.py      # Custom exception classes
│   └── logging_config.py  # Logging configuration
├── detection/             # Detection engines
├── samples/               # Test sample management
├── quarantine/            # Quarantine system
├── reporting/             # Report generation
├── data/                  # Databases and signatures
├── main.py               # Main entry point
├── cli.py                # Command-line interface
└── config.json           # Configuration file
```

## 🔬 Educational Use Cases

### Learning Malware Detection
1. **Signature Analysis**: Study how pattern matching detects known threats
2. **Behavioral Analysis**: Understand entropy calculation and suspicious file characteristics
3. **False Positive Analysis**: Learn to distinguish between legitimate and malicious files

### Security Research
1. **Sample Management**: Organize and analyze malware samples safely
2. **Detection Testing**: Test detection capabilities against various file types
3. **Quarantine Procedures**: Practice secure malware handling

### Cybersecurity Training
1. **Hands-on Experience**: Work with real antivirus concepts in a safe environment
2. **Report Analysis**: Learn to interpret security scan results
3. **Threat Intelligence**: Understand malware classification and characteristics

## 🛡️ Safety Features

- **Educational Focus**: Designed for learning, not production malware detection
- **Harmless Samples**: Uses EICAR test files and custom educational samples
- **Secure Quarantine**: Proper isolation of detected files
- **No Network Activity**: Operates entirely offline for safety
jh
## 📊 Sample Reports

The tool generates detailed reports including:

- **Detection Summary**: Overview of scan results and findings
- **File Analysis**: Detailed analysis of each scanned file
- **Educational Content**: Explanations of detection methods and threat types
- **Recommendations**: Learning suggestions based on scan results

## 🤝 Contributing

This is an educational tool. Contributions that enhance learning value are welcome:

- Additional educational samples and explanations
- Improved detection algorithms for learning purposes
- Better documentation and tutorials
- Enhanced reporting features

## ⚠️ Disclaimer

This tool is designed for educational purposes only. It should not be used as a production antivirus solution. Always use proper, commercial-grade antivirus software for actual malware protection.

## 📚 Learning Resources

- Study the source code to understand antivirus implementation
- Experiment with different configuration settings
- Analyze the generated reports to learn about detection methods
- Use the sample management system to practice malware handling

## 🔧 Troubleshooting

### Common Issues

1. **Database initialization fails**: Run `python main.py init-samples --repair`
2. **Configuration errors**: Check `config.json` syntax and values
3. **Permission errors**: Ensure write access to quarantine and samples directories

### Getting Help

- Check the verbose output: Add `--verbose` to any command
- Review the log file: `antivirus.log`
- Validate configuration: `python main.py config show`

---

**Educational Antivirus Research Tool** - Learn cybersecurity through hands-on experience with antivirus development concepts.