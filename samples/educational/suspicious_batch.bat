@echo off
REM Educational Batch Script - HARMLESS
REM This script contains patterns that might be flagged as suspicious
REM but performs no harmful actions

REM Suspicious pattern: File deletion commands (but not actually deleting)
echo This would delete files: del /q /s *.tmp
echo This would delete directories: rmdir /s /q temp_folder

REM Suspicious pattern: Registry modification (but not actually modifying)
echo This would modify registry: reg add HKCU\Software\Test

REM Suspicious pattern: Network activity (but not actually connecting)
echo This would download: powershell -command "& {some download command}"

REM Educational output
echo This is an educational batch script
echo It contains suspicious patterns but performs no harmful actions
echo All dangerous commands are only echoed, not executed

pause
