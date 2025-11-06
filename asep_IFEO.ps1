# =================================================================
# Windows ASEP Check - Image File Execution Options (IFEO)
# Cleaner output: only include file-related fields if present
# =================================================================

$ifeoPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
)

$results = @()

foreach ($basePath in $ifeoPaths) {
    if (-not (Test-Path $basePath)) {
        Write-Verbose "IFEO base key not found: $basePath"
        continue
    }

    $subKeys = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue

    foreach ($subKey in $subKeys) {
        $values = Get-ItemProperty -Path $subKey.PSPath -ErrorAction SilentlyContinue

        # Build a simple hashtable of values (exclude PS* props)
        $valueTable = @{}
        foreach ($p in $values.PSObject.Properties) {
            if ($p.Name -notmatch '^PS') { $valueTable[$p.Name] = $p.Value }
        }

        $debugger = $null
        if ($valueTable.ContainsKey('Debugger')) { $debugger = $valueTable['Debugger'] }

        # Prepare file-related vars (may remain $null)
        $debuggerExe = $null
        $fileExists = $false
        $fileLastWrite = $null
        $fileCreation = $null
        $publisher = $null
        $hash = $null

        if ($debugger) {
            if ($debugger -match '\"([^"]+\.exe)\"') {
                $debuggerExe = $matches[1]
            } elseif ($debugger -match '(^\S+\.exe)') {
                $debuggerExe = $matches[1]
            }

            if ($debuggerExe) {
                $debuggerExe = [Environment]::ExpandEnvironmentVariables($debuggerExe)
                if (Test-Path $debuggerExe) {
                    $fileExists = $true
                    $fileItem = Get-Item -Path $debuggerExe -ErrorAction SilentlyContinue
                    if ($fileItem) {
                        $fileLastWrite = $fileItem.LastWriteTime
                        $fileCreation = $fileItem.CreationTime
                    }
                    $sig = Get-AuthenticodeSignature -FilePath $debuggerExe -ErrorAction SilentlyContinue
                    if ($sig -and $sig.SignerCertificate) { $publisher = $sig.SignerCertificate.Subject } else { $publisher = "Unsigned or Unknown" }
                    $hashObj = Get-FileHash -Path $debuggerExe -Algorithm SHA256 -ErrorAction SilentlyContinue
                    if ($hashObj) { $hash = $hashObj.Hash }
                }
            }
        }

        # Build output object dynamically: include only relevant fields
        $props = [ordered]@{
            IFEO_BasePath    = $basePath
            SubKey           = $subKey.PSChildName
            RegistryFullPath = $subKey.PSPath
        }

        if ($debugger) { $props['DebuggerValue'] = $debugger }

        # Only include OtherValues if there are other keys
        $otherKeys = $valueTable.Keys | Where-Object { $_ -ne 'Debugger' }
        if ($otherKeys.Count -gt 0) {
            $props['OtherValues'] = ($otherKeys | ForEach-Object { "$_=`"$($valueTable[$_])`"" }) -join '; '
        }

        # Only include file-related info when we actually resolved a debugger exe
        if ($debuggerExe) { $props['DebuggerExePath'] = $debuggerExe }
        if ($debuggerExe) { $props['FileExists'] = $fileExists }
        if ($fileLastWrite) { $props['FileLastWriteTime'] = $fileLastWrite }
        if ($fileCreation) { $props['FileCreationTime'] = $fileCreation }
        if ($publisher) { $props['FilePublisher'] = $publisher }
        if ($hash) { $props['SHA256Hash'] = $hash }

        $entry = New-Object PSObject -Property $props
        $results += $entry
    }
}

if ($results.Count -eq 0) {
    Write-Output "No IFEO entries found under the scanned paths."
} else {
    # Print each result fully (no truncation)
    $results | Sort-Object IFEO_BasePath, SubKey | Format-List
}

# Optional: export to CSV/JSON for offline analysis
# $results | Export-Csv -Path ".\ASEP_IFEO_Results_Clean.csv" -NoTypeInformation
# $results | ConvertTo-Json -Depth 5 | Out-File ".\ASEP_IFEO_Results_Clean.json" -Encoding UTF8

# SIG # Begin signature block
# MIII1QYJKoZIhvcNAQcCoIIIxjCCCMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUfH5OoOAw2M2r5TYFV3tdOw0S
# r7OgggYoMIIGJDCCBQygAwIBAgITEwAAAOoKFpTrnDcwtAAEAAAA6jANBgkqhkiG
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
# BBSZ+a/f2BYALZpgta6mBKWXSbnJZjANBgkqhkiG9w0BAQEFAASCAQBK+rYOewya
# mQf8M+JmMvPrTtjlL4D6+hYz3h6E7TdLwCp5mTat9G7YnIfVB17c23YHKng5mQcP
# HMnxDOElBn1cK1KhCHtYjiSxjhftgXUE/bE2avu/K+tRrFDHS9HVKEguohG4H7/j
# AMHezibphKxxhU9Qi+YRE+6t+Vg/x0jTD+IfJX9wHJVFkZ9+nIel18wzJAZIcVFf
# 7dkfDfYVyiVWl54Feu1KUWTiRUa3ttK4CMS5F7WNhr5XS2l115Bl/2+9Z+PeSji0
# gIVJ/HOx1wdXUqWolS4GSmG8rcPW4N1O2VV6cCThE49wjLiqcr3yD1mFVevmvkKC
# PvGIuM8XV9na
# SIG # End signature block
