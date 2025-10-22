# Educational PowerShell Script - HARMLESS
# This script contains patterns that might be flagged as suspicious
# but performs no harmful actions

# Suspicious pattern: DownloadString (but not actually downloading)
$webClient = "System.Net.WebClient would be used here"
$downloadString = "DownloadString method would be called here"

# Suspicious pattern: Hidden window execution
$windowStyle = "Hidden"

# Suspicious pattern: Base64 content (harmless)
$encodedCommand = "VGhpcyBpcyBqdXN0IGEgdGVzdCBzdHJpbmc="  # "This is just a test string"

# Educational output
Write-Host "This is an educational PowerShell script"
Write-Host "It contains suspicious patterns but performs no harmful actions"
Write-Host "Decoded message: This is just a test string"
