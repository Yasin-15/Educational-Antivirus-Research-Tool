@echo off
REM Persistence Mechanism Demonstration - EDUCATIONAL ONLY
REM This batch file demonstrates persistence techniques
REM It contains NO executable code and is completely harmless

echo Educational Persistence Mechanism Demo
echo =====================================

REM 1. Registry Run Keys (DEMONSTRATION ONLY)
echo Demonstrating Registry Run Key persistence:
echo reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "MalwareDemo" /t REG_SZ /d "C:\demo\malware.exe"
echo (This command is NOT executed - for educational purposes only)

REM 2. Scheduled Tasks (DEMONSTRATION ONLY)  
echo.
echo Demonstrating Scheduled Task persistence:
echo schtasks /create /tn "MalwareTask" /tr "C:\demo\malware.exe" /sc onlogon
echo (This command is NOT executed - for educational purposes only)

REM 3. Service Installation (DEMONSTRATION ONLY)
echo.
echo Demonstrating Service persistence:
echo sc create "MalwareService" binPath= "C:\demo\malware.exe" start= auto
echo (This command is NOT executed - for educational purposes only)

REM 4. Startup Folder (DEMONSTRATION ONLY)
echo.
echo Demonstrating Startup Folder persistence:
echo copy "malware.exe" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
echo (This command is NOT executed - for educational purposes only)

REM 5. WMI Event Subscription (DEMONSTRATION ONLY)
echo.
echo Demonstrating WMI persistence:
echo wmic /namespace:"\\root\subscription" PATH __EventFilter CREATE Name="MalwareFilter", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"
echo (This command is NOT executed - for educational purposes only)

echo.
echo Educational Notes:
echo - Real malware uses these techniques to survive reboots
echo - Detection requires monitoring these persistence locations
echo - Regular system audits can identify unauthorized persistence
echo - Behavioral analysis can detect persistence establishment

echo.
echo This demonstration helps understand malware persistence methods
echo All commands shown are for educational purposes only
pause
