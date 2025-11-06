# =================================================================
# Windows ASEP Check - Shortcuts Manipulation
# Enumerates .lnk and .url files in Startup and Desktop locations,
# resolves targets and collects file metadata (timestamps, signature, hash)
# =================================================================

# Locations to scan (non-recursive by default, but script will recurse inside each path)
$pathsToScan = @(
    # All users Startup
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    # Current user Startup
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    # All users Desktop
    "$env:Public\Desktop",
    # Current user Desktop
    "$env:USERPROFILE\Desktop"
)

# You can add other folders if you want, for example common program folders:
# $pathsToScan += "$env:ProgramFiles"  # if you want to search wider (not recommended by default)

# Prepare results array
$results = @()

# Create COM object for resolving .lnk files
$shell = New-Object -ComObject WScript.Shell

# Helper: parse .url (internet shortcut) contents
function Get-UrlShortcutTarget {
    param($filePath)
    try {
        $content = Get-Content -Path $filePath -ErrorAction Stop
        foreach ($line in $content) {
            if ($line -match '^\s*URL\s*=\s*(.+)$') {
                return $matches[1].Trim()
            }
        }
    } catch {
        return $null
    }
    return $null
}

# Iterate locations
foreach ($base in $pathsToScan) {
    if (-not (Test-Path -Path $base)) {
        Write-Verbose "Path not found: $base"
        continue
    }

    try {
        $items = Get-ChildItem -Path $base -Include *.lnk, *.url -File -Recurse -ErrorAction Stop
    } catch {
        # If recursion fails in protected folders, fallback to non-recursive
        $items = Get-ChildItem -Path $base -Include *.lnk, *.url -File -ErrorAction SilentlyContinue
    }

    foreach ($it in $items) {
        $target = $null
        $arguments = $null
        $workingDir = $null
        $iconLocation = $null
        $isUrl = $false

        try {
            if ($it.Extension -ieq ".lnk") {
                # Resolve using COM Shell Link
                $shortcut = $shell.CreateShortcut($it.FullName)
                $target = $shortcut.TargetPath
                $arguments = $shortcut.Arguments
                $workingDir = $shortcut.WorkingDirectory
                $iconLocation = $shortcut.IconLocation
            } elseif ($it.Extension -ieq ".url") {
                $isUrl = $true
                $target = Get-UrlShortcutTarget -filePath $it.FullName
                # .url files do not have arguments/working dir in the same way
            }
        } catch {
            # swallow resolution errors but record them
            $target = $null
        }

        # If target seems quoted in the file name or contains exe twice, try heuristics
        if (-not $target -and $it.Extension -ieq ".lnk") {
            # As fallback, sometimes shortcut target is embedded in the file properties - we've already tried COM, so leave null
            $target = $null
        }

        # File metadata about the shortcut file itself and about the target if it exists
        $shortcutExists = $true
        $shortcutLastWrite = $it.LastWriteTime
        $shortcutCreation = $it.CreationTime

        $targetFileExists = $false
        $targetLastWrite = $null
        $targetCreation = $null
        $targetPublisher = $null
        $targetSHA256 = $null

        if ($target) {
            # If the target is a file path, check it; if it's a URL, leave file checks unpopulated
            if ($target -match '^[a-zA-Z]:(\\|/)' -or $target -match '^\\\\') {
                # Normalize path
                $normTarget = $target -replace '/', '\'
                # Remove surrounding quotes
                if ($normTarget -match '^\s*"(.*)"\s*$') { $normTarget = $matches[1] }
                # If there are arguments appended (rare), strip them heuristically
                if ($normTarget -match '^(.*?\.exe)\s+.*$') { $normTarget = $matches[1] }

                if (Test-Path $normTarget) {
                    $targetFileExists = $true
                    try {
                        $tItem = Get-Item -LiteralPath $normTarget -ErrorAction Stop
                        $targetLastWrite = $tItem.LastWriteTime
                        $targetCreation = $tItem.CreationTime

                        $sig = Get-AuthenticodeSignature -FilePath $normTarget -ErrorAction SilentlyContinue
                        if ($sig.SignerCertificate) {
                            $targetPublisher = $sig.SignerCertificate.Subject
                        } else {
                            $targetPublisher = "Unsigned or Unknown"
                        }

                        $h = Get-FileHash -Path $normTarget -Algorithm SHA256 -ErrorAction SilentlyContinue
                        $targetSHA256 = $h.Hash
                    } catch {
                        # ignore file metadata retrieval errors
                    }
                }
            }
        }

        $entry = [PSCustomObject]@{
            ScanBasePath        = $base
            ShortcutFullPath    = $it.FullName
            ShortcutName        = $it.Name
            ShortcutExtension   = $it.Extension
            ShortcutLastWrite   = $shortcutLastWrite
            ShortcutCreation    = $shortcutCreation
            IsUrlShortcut       = $isUrl
            ResolvedTarget      = $target
            Arguments           = $arguments
            WorkingDirectory    = $workingDir
            IconLocation        = $iconLocation
            TargetFileExists    = $targetFileExists
            TargetLastWriteTime = $targetLastWrite
            TargetCreationTime  = $targetCreation
            TargetPublisher     = $targetPublisher
            TargetSHA256        = $targetSHA256
        }

        $results += $entry
    }
}

# Output: full details (no truncation)
$results | Sort-Object ScanBasePath, ShortcutName | Format-List

# Optionally export:
# $results | Export-Csv -Path ".\ASEP_Shortcuts.csv" -NoTypeInformation
# Or for JSON:
# $results | ConvertTo-Json -Depth 6 | Out-File ".\ASEP_Shortcuts.json" -Encoding utf8

# SIG # Begin signature block
# MIII1QYJKoZIhvcNAQcCoIIIxjCCCMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU7XHASGz8QTB11p9Lq28zN3Hk
# 0tKgggYoMIIGJDCCBQygAwIBAgITEwAAAOoKFpTrnDcwtAAEAAAA6jANBgkqhkiG
# 9w0BAQsFADBfMRMwEQYKCZImiZPyLGQBGRYDYml6MRcwFQYKCZImiZPyLGQBGRYH
# a29ua29yZDEWMBQGCgmSJomT8ixkARkWBm9mZmljZTEXMBUGA1UEAxMOb2ZmaWNl
# LVI3MjAtQ0EwHhcNMjUwOTA4MDkwMjU2WhcNMjYwOTA4MDkwMjU2WjCBgjETMBEG
# CgmSJomT8ixkARkWA2JpejEXMBUGCgmSJomT8ixkARkWB2tvbmtvcmQxFjAUBgoJ
# kiaJk/IsZAEZFgZvZmZpY2UxDDAKBgNVBAsTA0FETTEsMCoGA1UEAwwj0JDQvdC0
# 0YDRltC5INCu0YDRltC50L7QstC40YcgKEFETSkwggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQCoAzLpVTmagvdCRJmBY7K2QABWT+0p+9KlXDZjKZwRKO+E
# UI6yok9dIMwCwMLWchS/tLYH3UJzdeQpThzKh9+4bUugRpcVrDBZmkc/AfCMNoW8
# DsYULz1PSY4QFqZ2EHTtpL97CW9lq1QATAqWaxR/XeFlGh0PfNURoESp/nS0rJVD
# mwOnws4ck6IwFDCiRf5Q6ByBT4kbUidJY2yq+XXKRB3ZvZo3qMSH25afRJjLCe8j
# u9fCXp9tPH4Asy/m5TI2byt+/QZi4ZoqfuKg8X4qTXDpZU0t/RSVsBDmT+z3yna0
# pVaWt7g4IypOb7Czoq5pyQGMhSp8v/N7s1kK0jX1AgMBAAGjggKzMIICrzAlBgkr
# BgEEAYI3FAIEGB4WAEMAbwBkAGUAUwBpAGcAbgBpAG4AZzATBgNVHSUEDDAKBggr
# BgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFJa2oHB+hpagFmYAV/CX
# kJ6pRVgkMB8GA1UdIwQYMBaAFMKXhnBVVeG2Z57kEq/GVt+xtHvNMIHWBgNVHR8E
# gc4wgcswgciggcWggcKGgb9sZGFwOi8vL0NOPW9mZmljZS1SNzIwLUNBKDQpLENO
# PXI3MjAsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
# Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9b2ZmaWNlLERDPWtvbmtvcmQsREM9Yml6
# P2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxE
# aXN0cmlidXRpb25Qb2ludDCBygYIKwYBBQUHAQEEgb0wgbowgbcGCCsGAQUFBzAC
# hoGqbGRhcDovLy9DTj1vZmZpY2UtUjcyMC1DQSxDTj1BSUEsQ049UHVibGljJTIw
# S2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1v
# ZmZpY2UsREM9a29ua29yZCxEQz1iaXo/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVj
# dENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwKgYDVR0RBCMwIaAfBgorBgEE
# AYI3FAIDoBEMD2F5c0Brb25rb3JkLmJpejBPBgkrBgEEAYI3GQIEQjBAoD4GCisG
# AQQBgjcZAgGgMAQuUy0xLTUtMjEtMjc5NTcwNjM3Ni0yMTE4MTg1MzA1LTMxMjA1
# NjYwNjMtMzI4ODANBgkqhkiG9w0BAQsFAAOCAQEAQj+PmmWBVDKjP334TvudZsor
# LXQ4b2EvHe1r7korzNQ+L4KzBcqt6UiVciHlmhOdjd3yGDF1Z88nWedGkvMpf9jm
# e5cW0c4ruiVAn6BkDrpnnaZpUs7vOorqdSvjBR//TWBR0bylNKtyAz3f5otR6Gk/
# ZBDrrtUD60SzieLuSaxnuxnL3IAyB2UQyg/E/WpUBR7CvunWpyGnlIKuobiqiLg5
# 3ya1EFO86s0M5ZHCRIDz9p2QzUlgHpunOEMfr32cdQIIbWdwlNiio8fGL/Q2XoJ3
# q8YJeASm1adDuqgDYPnEXP6zLyeyu7S2xAcxqSD2U30SxdcTGE3THX3lBnTfLTGC
# AhcwggITAgEBMHYwXzETMBEGCgmSJomT8ixkARkWA2JpejEXMBUGCgmSJomT8ixk
# ARkWB2tvbmtvcmQxFjAUBgoJkiaJk/IsZAEZFgZvZmZpY2UxFzAVBgNVBAMTDm9m
# ZmljZS1SNzIwLUNBAhMTAAAA6goWlOucNzC0AAQAAADqMAkGBSsOAwIaBQCgeDAY
# BgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEW
# BBQo0otx7ggu8mI9B9w1WztcjjGj1zANBgkqhkiG9w0BAQEFAASCAQBIxCgJ+8b6
# N1R/SRzW0eCy7b4lnJlOtJMuiedEB5WTGdAMFcZODCi7ibyKD9MrIBYZouFBAu6y
# mTjoyla6lYiKeLt5Ty/0T/Sb9JQaa3DrWa4HMAp50beHUB3c3kegljd+WzX+qwQa
# LMWE5yXJELeSeK37dMHGAbKyA4uGN6uy7joTGrCcrmv2YLL3f6Zx8+Yhb1TZCMN+
# aXMPdgReYvrOAzbsiH2H1zQwBqTSdKYHEv6Uq4N9VCU+UWS9GjyNspiB+WQgHWLG
# gs353G2c4D46ps0vao32oqsPHqoixxPH6j3t0ubyd2xKIoLVf8N6tZwK84FjcydM
# c8kyJKDvm//t
# SIG # End signature block
