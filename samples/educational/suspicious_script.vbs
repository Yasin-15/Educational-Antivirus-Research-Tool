' Educational VBScript - HARMLESS
' This script contains patterns that might be flagged as suspicious
' but performs no harmful actions

' Suspicious pattern: Shell object creation (but not actually creating)
Dim shellObject
' Set shellObject = CreateObject("WScript.Shell")

' Suspicious pattern: File system object (but not actually creating)
Dim fso
' Set fso = CreateObject("Scripting.FileSystemObject")

' Suspicious pattern: HTTP request object (but not actually creating)
Dim http
' Set http = CreateObject("MSXML2.XMLHTTP")

' Educational output
MsgBox "This is an educational VBScript"
MsgBox "It contains suspicious patterns but performs no harmful actions"
MsgBox "All object creation is commented out for safety"
