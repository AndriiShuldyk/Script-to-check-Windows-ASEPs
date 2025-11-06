# =================================================================
# Windows ASEP Check - Services
# Lists all Windows services and gathers file metadata
# =================================================================

# Collect all services
$services = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue

$results = @()

foreach ($svc in $services) {
    $exePath = $null
    $fileExists = $false
    $fileLastWrite = $null
    $fileCreation = $null
    $publisher = $null
    $hash = $null

    # Try to extract executable path from PathName (remove quotes and args)
    if ($svc.PathName -match '\"([^"]+\.exe)\"') {
        $exePath = $matches[1]
    } elseif ($svc.PathName -match '(^\S+\.exe)') {
        $exePath = $matches[1]
    }

    # Gather metadata if file exists
    if ($exePath -and (Test-Path $exePath)) {
        $fileExists = $true
        $fileItem = Get-Item $exePath -ErrorAction SilentlyContinue
        $fileLastWrite = $fileItem.LastWriteTime
        $fileCreation = $fileItem.CreationTime

        $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
        if ($sig.SignerCertificate) {
            $publisher = $sig.SignerCertificate.Subject
        } else {
            $publisher = "Unsigned or Unknown"
        }

        $hashObj = Get-FileHash -Path $exePath -Algorithm SHA256 -ErrorAction SilentlyContinue
        $hash = $hashObj.Hash
    }

    # Create result object
    $entry = [PSCustomObject]@{
        Name              = $svc.Name
        DisplayName       = $svc.DisplayName
        StartMode         = $svc.StartMode
        State             = $svc.State
        PathName          = $svc.PathName
        FileExists        = $fileExists
        FileLastWriteTime = $fileLastWrite
        FileCreationTime  = $fileCreation
        FilePublisher     = $publisher
        SHA256Hash        = $hash
    }

    $results += $entry
}

# --- Output control ---
# Full console output (no truncation)
$results | Sort-Object Name | Format-List

# Optionally export to CSV for detailed review
# $results | Export-Csv -Path ".\ASEP_Services.csv" -NoTypeInformation

# SIG # Begin signature block
# MIII1QYJKoZIhvcNAQcCoIIIxjCCCMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUWolNaQAPrC0T7KBZLSHY/aLg
# tkCgggYoMIIGJDCCBQygAwIBAgITEwAAAOoKFpTrnDcwtAAEAAAA6jANBgkqhkiG
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
# BBSjahRSx+6ttzCObQOSFCRUM5UUxDANBgkqhkiG9w0BAQEFAASCAQAWZsJVrxd4
# kAZCxhISa37nAQz1RdfdnGhSLhaBmDgCSpvvwwxzeCCi/LzeYeWbrj/YGf6PAn5y
# Gph1EXWawb0mj8lHiDPlGtfkydJEy+Az9MP9GyuQ2pPK4BF6dMjjiDq26UH9FO7v
# TlMMNVL5jTRZLxIeBJcmWCaZ0PfKyyh2l64LrkhOzsvPmvt2sSvPtfeh5vdWRt26
# guBNPdVa9u9gKrkvo14IstQqz3cx/xUHtKOHILt1d4+8OsC6xTqJW3A6EONrE1d2
# hBtqyYD5jxym3c+YFQFDKt3mKuyJmbTDtq2AYLZr5DkvXM9FruNPVvb7Vre1iG/r
# 4gRNBIEr1TAi
# SIG # End signature block
