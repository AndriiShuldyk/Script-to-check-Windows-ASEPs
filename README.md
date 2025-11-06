# Script-to-check-Windows-ASEPs
This PowerShell script checks Windows Auto-Start Extension Points.

It helps identify programs or scripts configured to automatically start with Windows, which is a common method for malware or legitimate applications to maintain persistence.

The script combines multiple detection modules into one tool and allows you to run individual checks or all at once.

It checks:
1. HKLM Run Keys
2. HKCU Run Keys
3. Startup Folders
4. Scheduled Tasks
5. Services
6. Shortcuts Manipulation
7. Image File Execution Options
8. Extension Hijacking (HKLM)
9. Extension Hijacking (HKCU)
10. Trojanized System Binaries
11. Browser Helper Objects
12. Winlogon
13. AppInit DLLs
14. Active Setup (HKLM)
15. Active Setup (HKCU)

Main file is asepChecking.ps1
