# =================================================================
# Windows ASEP Check - Browser Helper Objects (BHOs) - Fixed
# Enumerates BHO CLSIDs from HKLM/HKCU (including WOW6432Node) and
# resolves the COM server path; collects file metadata only when present.
# =================================================================

function Get-FileMetadataIfExists {
    param($path)
    if (-not $path) { return $null }

    $expanded = [Environment]::ExpandEnvironmentVariables($path)
    # Remove any surrounding quotes
    $expanded = $expanded.Trim('"')

    if (-not (Test-Path $expanded)) { return $null }

    $fi = Get-Item -Path $expanded -ErrorAction SilentlyContinue
    if (-not $fi) { return $null }

    $last = $fi.LastWriteTime
    $creation = $fi.CreationTime

    $sig = Get-AuthenticodeSignature -FilePath $expanded -ErrorAction SilentlyContinue
    if ($sig -and $sig.SignerCertificate) {
        $pub = $sig.SignerCertificate.Subject
    } else {
        $pub = "Unsigned or Unknown"
    }

    $h = Get-FileHash -Path $expanded -Algorithm SHA256 -ErrorAction SilentlyContinue
    $hash = if ($h) { $h.Hash } else { $null }

    return [PSCustomObject]@{
        ResolvedPath       = $expanded
        FileExists         = $true
        FileLastWriteTime  = $last
        FileCreationTime   = $creation
        FilePublisher      = $pub
        SHA256Hash         = $hash
    }
}

# Registry BHO locations to check
$bhoRoots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
)

$results = @()

foreach ($root in $bhoRoots) {
    if (-not (Test-Path $root)) {
        continue
    }

    $clsidKeys = Get-ChildItem -Path $root -ErrorAction SilentlyContinue
    foreach ($k in $clsidKeys) {
        $clsid = $k.PSChildName
        $bhoKeyPath = $k.PSPath

        # Try to read any descriptive default value under the CLSID key
        $displayName = $null
        try {
            $displayName = (Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue).''
            # If the default value retrieval above returns empty, try explicit '(default)' key name
            if (-not $displayName) {
                $displayName = (Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue)."(default)" 2>$null
            }
        } catch {
            $displayName = $null
        }

        # Resolve COM server path: prefer HKCR (Classes) then SOFTWARE\Classes then HKCU\Software\Classes
        $serverPath = $null

        $clsidLookupPaths = @(
            "HKCR:\CLSID\$clsid",
            "HKLM:\SOFTWARE\Classes\CLSID\$clsid",
            "HKCU:\Software\Classes\CLSID\$clsid"
        )

        foreach ($clPath in $clsidLookupPaths) {
            if (Test-Path $clPath) {
                # Look for InprocServer32 (DLL) or LocalServer32 (EXE)
                $inproc = Join-Path $clPath 'InprocServer32'
                $local  = Join-Path $clPath 'LocalServer32'

                if (Test-Path $inproc) {
                    $val = (Get-ItemProperty -Path $inproc -ErrorAction SilentlyContinue).''
                    if (-not $val) {
                        $val = (Get-ItemProperty -Path $inproc -ErrorAction SilentlyContinue)."(default)" 2>$null
                    }
                    if ($val) { $serverPath = $val; break }
                }

                if (Test-Path $local) {
                    $val = (Get-ItemProperty -Path $local -ErrorAction SilentlyContinue).''
                    if (-not $val) {
                        $val = (Get-ItemProperty -Path $local -ErrorAction SilentlyContinue)."(default)" 2>$null
                    }
                    if ($val) { $serverPath = $val; break }
                }
            }
        }

        # Also check the Classes root fallback under WOW6432Node (32-bit) for completeness
        if ((-not $serverPath)) {
            $alt = "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID\$clsid"
            if (Test-Path $alt) {
                $inproc = Join-Path $alt 'InprocServer32'
                $local  = Join-Path $alt 'LocalServer32'

                if (Test-Path $inproc) {
                    $val = (Get-ItemProperty -Path $inproc -ErrorAction SilentlyContinue).''
                    if (-not $val) {
                        $val = (Get-ItemProperty -Path $inproc -ErrorAction SilentlyContinue)."(default)" 2>$null
                    }
                    if ($val) { $serverPath = $val }
                }

                if ((-not $serverPath) -and (Test-Path $local)) {
                    $val = (Get-ItemProperty -Path $local -ErrorAction SilentlyContinue).''
                    if (-not $val) {
                        $val = (Get-ItemProperty -Path $local -ErrorAction SilentlyContinue)."(default)" 2>$null
                    }
                    if ($val) { $serverPath = $val }
                }
            }
        }

        # Gather file metadata only if serverPath resolved and file exists
        $fileMeta = $null
        if ($serverPath) {
            # Extract quoted path or first token if needed (handles "path" -arg style)
            $candidate = $null
            if ($serverPath -match '"([^"]+\.(dll|exe))"') {
                $candidate = $matches[1]
            } elseif ($serverPath -match '(^\S+\.(dll|exe))') {
                $candidate = $matches[1]
            } else {
                $candidate = $serverPath
            }

            if ($candidate) {
                # Expand env vars and trim quotes inside Get-FileMetadataIfExists
                $fileMeta = Get-FileMetadataIfExists -path $candidate
            }
        }

        # Build output object, include file-related fields only when present
        $props = [ordered]@{
            BHO_RootRegistryPath = $root
            BHO_CLSID_Key        = $bhoKeyPath
            BHO_CLSID            = $clsid
        }
        if ($displayName)    { $props['BHO_DisplayName']        = $displayName }
        if ($serverPath)     { $props['COM_ServerRegistryValue'] = $serverPath }

        if ($fileMeta) {
            $props['ResolvedPath']      = $fileMeta.ResolvedPath
            $props['FileExists']        = $fileMeta.FileExists
            $props['FileLastWriteTime'] = $fileMeta.FileLastWriteTime
            $props['FileCreationTime']  = $fileMeta.FileCreationTime
            $props['FilePublisher']     = $fileMeta.FilePublisher
            $props['SHA256Hash']        = $fileMeta.SHA256Hash
        }

        $results += New-Object PSObject -Property $props
    }
}

if ($results.Count -eq 0) {
    Write-Output "No BHO entries found in checked registry locations."
} else {
    $results | Sort-Object BHO_CLSID | Format-List
    # Optional exports:
    # $results | Export-Csv -Path ".\ASEP_BHOs.csv" -NoTypeInformation
    # $results | ConvertTo-Json -Depth 5 | Out-File ".\ASEP_BHOs.json" -Encoding UTF8
}

# SIG # Begin signature block
# MIII1QYJKoZIhvcNAQcCoIIIxjCCCMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUAysdI3mUejQuxP8/GG1JaYvx
# 5OegggYoMIIGJDCCBQygAwIBAgITEwAAAOoKFpTrnDcwtAAEAAAA6jANBgkqhkiG
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
# BBTYD5hpWjAo4mkuiXFh0tv2Nb/FKzANBgkqhkiG9w0BAQEFAASCAQBRhM0qWwGZ
# ePr/L+nxu68eNHaEeJJKqOXHEZvmwLYj5ts7ULq9ZwV2gFEWXaTe2Ubht4l5/FnA
# 4FCoOxRXaZ1zaqd+mNUedfU3E6KCXJpMNC+6zKXYu5FxnlnNIPJVJQ7oS1RF8fSi
# TP1vyHlvcrR+omZedjMYvntkLaGBNMhEPyjy++YmAoZwdDS3uQfZ2C8+UFJk44OA
# altI6qxPShRX20ITZ4G6a6JCD5ZlcAoJbQHvPLR5tAoGH9s23qUTbo5unO/fT4Zt
# l1Fq1JsIDGJZNqOpi1p01lM/qlf0eB878kdD2PMGGzZ4AV3cB8lCs/y3MTxEi7g5
# OqehwFUBCMHS
# SIG # End signature block
