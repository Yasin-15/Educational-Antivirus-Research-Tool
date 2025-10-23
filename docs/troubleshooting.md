# Troubleshooting Guide

This comprehensive troubleshooting guide helps resolve common issues with the Educational Antivirus Research Tool.

## 🚨 Critical Issues

### Database Initialization Fails

**Symptoms:**
- Error messages about database creation or access
- "Database initialization failed" errors
- Missing or corrupted database files

**Solutions:**
1. **Check disk space:**
   ```bash
   # Windows
   dir C:\
   
   # Linux/Mac
   df -h
   ```

2. **Verify permissions:**
   ```bash
   # Run with elevated privileges
   # Windows: Run as Administrator
   # Linux/Mac: Use sudo if necessary
   ```

3. **Force database recreation:**
   ```bash
   python main.py init-samples --force-reset
   ```

4. **Repair existing databases:**
   ```bash
   python main.py init-samples --repair
   ```

**Prevention:**
- Ensure adequate disk space (at least 100MB free)
- Run with appropriate user permissions
- Avoid forcefully terminating the application
- Regular database validation: `python main.py init-samples --validate-only`

### Configuration Loading Errors

**Symptoms:**
- "Configuration could not be loaded" errors
- JSON syntax errors in config.json
- Missing configuration values

**Solutions:**
1. **Validate JSON syntax:**
   - Use online JSON validators
   - Check for missing commas, brackets, or quotes
   - Ensure proper escaping of backslashes in paths

2. **Reset to default configuration:**
   ```bash
   # Backup current config
   copy config.json config.json.backup
   
   # Delete corrupted config (will recreate with defaults)
   del config.json
   
   # Verify new configuration
   python main.py config show
   ```

3. **Check file permissions:**
   ```bash
   # Windows
   icacls config.json
   
   # Linux/Mac
   ls -la config.json
   ```

**Example valid configuration:**
```json
{
  "signature_sensitivity": 7,
  "behavioral_threshold": 6,
  "max_file_size_mb": 50,
  "entropy_threshold": 7.0,
  "suspicious_extensions": [".exe", ".scr", ".bat", ".cmd", ".vbs"],
  "log_level": "INFO",
  "recursive_scan": true,
  "follow_symlinks": false,
  "quarantine_path": "quarantine/",
  "samples_path": "samples/",
  "reports_path": "reports/"
}
```

## ⚠️ Common Issues

### Import/Module Errors

**Symptoms:**
- "ModuleNotFoundError" or "ImportError"
- Missing Python packages
- Version compatibility issues

**Solutions:**
1. **Install required packages:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Verify Python version:**
   ```bash
   python --version
   # Should be 3.7 or higher
   ```

3. **Check virtual environment:**
   ```bash
   # Activate virtual environment if using one
   # Windows
   venv\Scripts\activate
   
   # Linux/Mac
   source venv/bin/activate
   ```

4. **Reinstall dependencies:**
   ```bash
   pip uninstall -r requirements.txt -y
   pip install -r requirements.txt
   ```

### Permission Denied Errors

**Symptoms:**
- "Permission denied" when accessing files
- Cannot create or modify files
- Antivirus blocking operations

**Solutions:**
1. **Run with elevated privileges:**
   - Windows: Right-click → "Run as Administrator"
   - Linux/Mac: Use `sudo` if necessary

2. **Check file/directory permissions:**
   ```bash
   # Windows
   icacls samples\
   icacls quarantine\
   
   # Linux/Mac
   ls -la samples/
   ls -la quarantine/
   ```

3. **Configure antivirus exclusions:**
   - Add tool directory to antivirus exclusions
   - Temporarily disable real-time protection for testing

4. **Check for file locks:**
   - Close other applications using the files
   - Restart the system if necessary

### Sample Management Issues

**Symptoms:**
- Cannot create test samples
- Sample metadata inconsistencies
- Missing sample files

**Solutions:**
1. **Reinitialize sample system:**
   ```bash
   python main.py init-samples --force-reset
   ```

2. **Check sample directory structure:**
   ```bash
   # Verify directory exists and is writable
   python -c "import os; print(os.access('samples/', os.W_OK))"
   ```

3. **Clean up orphaned files:**
   ```python
   from samples.sample_manager import SampleManager
   manager = SampleManager()
   cleaned = manager.cleanup_orphaned_files()
   print(f"Cleaned up {len(cleaned)} orphaned files")
   ```

4. **Validate sample metadata:**
   ```python
   from samples.sample_manager import SampleManager
   manager = SampleManager()
   validation = manager.validate_samples()
   print(f"Valid: {len(validation['valid'])}")
   print(f"Missing files: {len(validation['missing_files'])}")
   print(f"Corrupted metadata: {len(validation['corrupted_metadata'])}")
   ```

## 🔧 Performance Issues

### Slow Scanning Performance

**Symptoms:**
- Scanning takes excessive time
- High CPU or memory usage
- System becomes unresponsive

**Solutions:**
1. **Adjust file size limits:**
   ```json
   {
     "max_file_size_mb": 10
   }
   ```

2. **Reduce detection sensitivity:**
   ```json
   {
     "signature_sensitivity": 5,
     "behavioral_threshold": 5
   }
   ```

3. **Exclude unnecessary directories:**
   - Avoid scanning system directories
   - Skip large media files
   - Exclude temporary directories

4. **Process files in batches:**
   ```python
   # For large directories, process in smaller batches
   import os
   from pathlib import Path
   
   files = list(Path("large_directory").rglob("*"))
   batch_size = 100
   
   for i in range(0, len(files), batch_size):
       batch = files[i:i+batch_size]
       # Process batch
   ```

### Memory Usage Issues

**Symptoms:**
- High memory consumption
- Out of memory errors
- System slowdown

**Solutions:**
1. **Reduce concurrent operations:**
   - Process files sequentially instead of in parallel
   - Limit the number of files processed at once

2. **Clear caches periodically:**
   ```python
   # Clear internal caches if available
   import gc
   gc.collect()
   ```

3. **Monitor memory usage:**
   ```python
   import psutil
   process = psutil.Process()
   print(f"Memory usage: {process.memory_info().rss / 1024 / 1024:.2f} MB")
   ```

## 🐛 Debugging Tips

### Enable Verbose Logging

```bash
# Run commands with verbose output
python main.py --verbose init-samples
python main.py --verbose config show
```

### Check Log Files

```bash
# View recent log entries
tail -f antivirus.log

# Search for specific errors
grep -i error antivirus.log
grep -i warning antivirus.log
```

### Validate System State

```bash
# Check overall system status
python main.py init-samples --validate-only

# Verify configuration
python main.py config show

# Test basic functionality
python main.py examples beginner
```

### Debug Python Environment

```python
import sys
print("Python version:", sys.version)
print("Python path:", sys.path)

import pkg_resources
installed_packages = [d for d in pkg_resources.working_set]
for package in sorted(installed_packages, key=lambda x: x.project_name):
    print(f"{package.project_name}: {package.version}")
```

## 📞 Getting Additional Help

### Interactive Help System

```bash
# Launch interactive help
python main.py help-system

# Interactive troubleshooting assistant
python main.py troubleshoot

# Run comprehensive system diagnostics
python main.py troubleshoot --check-all

# Attempt automatic fixes for common issues
python main.py troubleshoot --fix-common

# View usage examples
python examples/usage_examples.py

# Run educational workflows
python main.py examples beginner
```

### Self-Diagnosis

```bash
# Run comprehensive system check
python -c "
from core.config import ConfigManager
from core.sample_initialization import SampleInitializationManager

try:
    config = ConfigManager().get_config()
    print('✓ Configuration loaded successfully')
    
    manager = SampleInitializationManager(config)
    status = manager.get_initialization_status()
    
    if status.get('databases_initialized', False):
        print('✓ Databases are initialized')
        print(f'  Samples: {status.get(\"sample_count\", 0)}')
        print(f'  Threats: {status.get(\"threat_count\", 0)}')
    else:
        print('✗ Databases need initialization')
        
except Exception as e:
    print(f'✗ System check failed: {e}')
"
```

### Common Error Patterns

| Error Pattern | Likely Cause | Quick Fix |
|---------------|--------------|-----------|
| `Permission denied` | Insufficient privileges | Run as administrator |
| `No such file or directory` | Missing files/paths | Check file paths and existence |
| `JSON decode error` | Invalid configuration | Validate and fix config.json |
| `Module not found` | Missing dependencies | Run `pip install -r requirements.txt` |
| `Database locked` | Concurrent access | Close other instances |
| `Disk space` | Insufficient storage | Free up disk space |

### Recovery Procedures

#### Complete System Reset
```bash
# Backup important data
copy config.json config.json.backup

# Remove all generated data
rmdir /s quarantine
rmdir /s samples
rmdir /s reports
del antivirus.log

# Reinitialize from scratch
python main.py init-samples --force-reset
```

#### Partial Recovery
```bash
# Keep configuration, reset databases only
python main.py init-samples --force-reset

# Keep samples, reset configuration only
del config.json
python main.py config show
```

## 📋 Preventive Measures

### Regular Maintenance

1. **Weekly checks:**
   ```bash
   python main.py init-samples --validate-only
   ```

2. **Monthly cleanup:**
   ```bash
   # Clean up old log files
   # Validate sample integrity
   # Check disk space usage
   ```

3. **Before important work:**
   ```bash
   # Backup configuration
   copy config.json config_backup_$(date +%Y%m%d).json
   
   # Verify system status
   python main.py init-samples --validate-only
   ```

### Best Practices

- Always run the tool with appropriate permissions
- Keep regular backups of configuration and important data
- Monitor log files for early warning signs
- Use the educational workflows to learn proper usage
- Test changes in a safe environment first
- Keep the tool and dependencies updated

### Environment Setup

```bash
# Recommended directory structure
educational-antivirus/
├── config.json
├── main.py
├── cli.py
├── requirements.txt
├── samples/
├── quarantine/
├── reports/
├── data/
└── logs/
```

## 🎓 Educational Usage Guidance

### Getting Started with Learning

**First-Time Users:**
1. **Complete Initial Setup:**
   ```bash
   # Install dependencies
   pip install -r requirements.txt
   
   # Initialize educational databases
   python main.py init-samples
   
   # Verify setup
   python main.py config show
   ```

2. **Start with Beginner Workflow:**
   ```bash
   python main.py examples beginner
   ```

3. **Use Interactive Help:**
   ```bash
   python main.py help-system
   ```

### Learning Progression

**Beginner Level:**
- Focus on basic scanning operations
- Learn about different malware types
- Understand detection methods
- Practice with safe sample files

**Intermediate Level:**
- Explore behavioral analysis
- Experiment with detection tuning
- Learn quarantine operations
- Understand false positive management

**Advanced Level:**
- Custom signature creation
- Performance optimization
- Batch processing techniques
- Integration with other security tools

### Common Learning Scenarios

**Scenario 1: Understanding Detection Methods**
```bash
# Run detection comparison
python main.py examples scenarios

# View detection details
python main.py examples intermediate
```

**Scenario 2: Tuning Detection Sensitivity**
```bash
# Test with different sensitivity levels
python -c "
from core.config import ConfigManager
config = ConfigManager().get_config()
config.signature_sensitivity = 5  # More sensitive
# Test scanning with new settings
"
```

**Scenario 3: Analyzing False Positives**
```bash
# Scan known clean files
python main.py examples advanced

# Review detection results and adjust settings
```

### Interactive Learning Features

**Help System Navigation:**
- Use number keys to navigate menus
- Type 'back' to return to previous menu
- Type 'exit' to quit help system
- Use 'search <term>' to find specific topics

**Workflow Interruption:**
- Press Ctrl+C to pause workflows
- Workflows save progress automatically
- Resume with the same command

**Progress Tracking:**
- Workflows track completion status
- View progress with status commands
- Reset progress if needed

## 🔧 Advanced Troubleshooting

### System Integration Issues

**Antivirus Software Conflicts:**
```bash
# Check for real-time protection interference
# Add tool directory to antivirus exclusions
# Temporarily disable real-time scanning for testing
```

**Network and Firewall Issues:**
```bash
# If using network features (future versions)
# Check firewall settings
# Verify network connectivity
```

### Development and Customization

**Adding Custom Signatures:**
```python
# Example custom signature addition
from core.signature_manager import SignatureManager
manager = SignatureManager()
manager.add_custom_signature("custom_threat", pattern_data)
```

**Performance Profiling:**
```python
# Profile scanning performance
import cProfile
cProfile.run('scan_operation()', 'profile_results.prof')
```

### Database Management

**Advanced Database Operations:**
```bash
# Export sample database
python -c "
from samples.sample_manager import SampleManager
manager = SampleManager()
manager.export_database('backup.json')
"

# Import sample database
python -c "
from samples.sample_manager import SampleManager
manager = SampleManager()
manager.import_database('backup.json')
"
```

**Database Optimization:**
```bash
# Optimize database performance
python -c "
from core.sample_initialization import SampleInitializationManager
from core.config import ConfigManager
config = ConfigManager().get_config()
manager = SampleInitializationManager(config)
manager.optimize_databases()
"
```

### Logging and Monitoring

**Enhanced Logging:**
```json
{
  "log_level": "DEBUG",
  "log_file": "antivirus_debug.log",
  "enable_performance_logging": true
}
```

**Real-time Monitoring:**
```bash
# Monitor log file in real-time
tail -f antivirus.log

# Filter for specific events
grep -i "error\|warning" antivirus.log
```

## 📊 Performance Optimization Guide

### Memory Usage Optimization

**Large File Handling:**
```json
{
  "max_file_size_mb": 10,
  "enable_streaming_analysis": true,
  "memory_limit_mb": 512
}
```

**Batch Processing:**
```python
# Process files in smaller batches
batch_size = 50
for i in range(0, len(files), batch_size):
    batch = files[i:i+batch_size]
    process_batch(batch)
```

### CPU Usage Optimization

**Multi-threading Configuration:**
```json
{
  "max_worker_threads": 4,
  "enable_parallel_scanning": true,
  "thread_pool_size": 8
}
```

**Detection Algorithm Tuning:**
```json
{
  "signature_sensitivity": 6,
  "behavioral_threshold": 5,
  "entropy_threshold": 6.5,
  "enable_heuristic_analysis": false
}
```

### Disk I/O Optimization

**Temporary File Management:**
```json
{
  "temp_directory": "/tmp/antivirus",
  "cleanup_temp_files": true,
  "max_temp_file_age_hours": 24
}
```

**Database Caching:**
```json
{
  "enable_database_caching": true,
  "cache_size_mb": 128,
  "cache_expiry_minutes": 60
}
```

## 🚨 Emergency Recovery Procedures

### Complete System Recovery

**Full Reset (Nuclear Option):**
```bash
# Backup important data first
cp config.json config.json.emergency_backup
cp -r samples/ samples_backup/

# Complete reset
rm