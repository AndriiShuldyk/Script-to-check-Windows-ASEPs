# =================================================================
# Windows ASEP Check - Winlogon
# Enumerates HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
# and Winlogon\Notify subkeys, resolves DLL/EXE references and
# gathers file metadata only when files exist.
# =================================================================

function Resolve-PathFromString {
    param($s)
    if (-not $s) { return $null }

    # Expand environment variables
    $s = [Environment]::ExpandEnvironmentVariables($s.ToString())

    # Try to find a quoted path first (exe or dll)
    if ($s -match '"([^"]+\.(exe|dll))"') {
        return $matches[1]
    }

    # Try to match an absolute path token
    if ($s -match '([A-Za-z]:\\[^,\s"]+\.(exe|dll))') {
        return $matches[1]
    }

    # Try to match a bare filename
    if ($s -match '(^\S+\.(exe|dll))') {
        $candidate = $matches[1]

        # If candidate has no path, try resolving in common locations
        if ($candidate -notmatch '^[A-Za-z]:\\') {
            $searchPaths = @(
                (Join-Path $env:windir "System32\$candidate"),
                (Join-Path $env:windir "SysWOW64\$candidate"),
                (Join-Path $env:windir $candidate),
                (Join-Path $env:ProgramFiles $candidate)
            )

            # Add ProgramFiles(x86) if different
            if ($env:ProgramFiles -ne ${env:ProgramFiles(x86)}) {
                $searchPaths += (Join-Path ${env:ProgramFiles(x86)} $candidate)
            }

            foreach ($path in $searchPaths) {
                if (Test-Path $path) {
                    return (Resolve-Path $path).ProviderPath
                }
            }

            return $candidate  # fallback
        }
        else {
            return $candidate
        }
    }

    return $null
}

# Path to Winlogon key
$winlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

if (-not (Test-Path $winlogonPath)) {
    Write-Output "Winlogon registry key not found: $winlogonPath"
    return
}

$winlogon = Get-ItemProperty -Path $winlogonPath -ErrorAction SilentlyContinue

$results = @()

# Values we are specifically interested in (but we will also capture others)
$interestingValues = @('Userinit','Shell','GinaDLL','VmApplet')

# Process each value under Winlogon
foreach ($prop in $winlogon.PSObject.Properties) {
    if ($prop.Name -match '^PS') { continue }

    $name = $prop.Name
    $value = $prop.Value

    # If the value is multi-entry (e.g., Userinit can be "C:\Windows\system32\userinit.exe,") handle as string
    if ($null -eq $value) {
        # still include the key name even if empty
        $props = [ordered]@{
            RegistryPath = $winlogonPath
            ValueName    = $name
        }
        $results += New-Object PSObject -Property $props
        continue
    }

    # Some values may contain multiple possible paths (comma separated). Split and handle each token.
    $tokens = @()
    if ($value -is [string] -and $value -match ',') {
        # split on comma and whitespace, keep non-empty
        $tokens = ($value -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    } else {
        $tokens = ,$value.ToString()
    }

    foreach ($token in $tokens) {
        $resolved = Resolve-PathFromString -s $token

        # gather file metadata only if resolved path exists on disk
        $fileExists = $false; $fileLastWrite = $null; $fileCreation = $null; $publisher = $null; $hash = $null

        if ($resolved) {
            # If resolved is a filename (no drive), Expand to candidate path (function already tried common dirs)
            $expanded = [Environment]::ExpandEnvironmentVariables($resolved)

            # If path is not absolute but exists in working dir, Resolve-Path may find it
            try {
                if (Test-Path $expanded) {
                    $fileExists = $true
                    $fi = Get-Item -Path $expanded -ErrorAction SilentlyContinue
                    if ($fi) {
                        $fileLastWrite = $fi.LastWriteTime
                        $fileCreation = $fi.CreationTime
                    }
                    $sig = Get-AuthenticodeSignature -FilePath $expanded -ErrorAction SilentlyContinue
                    if ($sig -and $sig.SignerCertificate) { $publisher = $sig.SignerCertificate.Subject } else { $publisher = "Unsigned or Unknown" }
                    $hashObj = Get-FileHash -Path $expanded -Algorithm SHA256 -ErrorAction SilentlyContinue
                    if ($hashObj) { $hash = $hashObj.Hash }
                }
            } catch {
                # ignore path resolution errors
            }
        }

        # Build output object dynamically (only include file-related fields if present)
        $props = [ordered]@{
            RegistryPath = $winlogonPath
            ValueName    = $name
            ValueData    = $value
            Token        = $token
        }

        if ($resolved) { $props['ResolvedPath'] = $resolved }
        if ($fileExists) { $props['FileExists'] = $fileExists }
        if ($fileLastWrite) { $props['FileLastWriteTime'] = $fileLastWrite }
        if ($fileCreation) { $props['FileCreationTime'] = $fileCreation }
        if ($publisher) { $props['FilePublisher'] = $publisher }
        if ($hash) { $props['SHA256Hash'] = $hash }

        $results += New-Object PSObject -Property $props
    }
}

# Now enumerate Winlogon\Notify subkeys and inspect their values (commonly DLL names)
$notifyBase = Join-Path $winlogonPath "Notify"
if (Test-Path $notifyBase) {
    $notifySubkeys = Get-ChildItem -Path $notifyBase -ErrorAction SilentlyContinue
    foreach ($nk in $notifySubkeys) {
        $nkProps = Get-ItemProperty -Path $nk.PSPath -ErrorAction SilentlyContinue
        $vals = @{}
        foreach ($p in $nkProps.PSObject.Properties) {
            if ($p.Name -notmatch '^PS') { $vals[$p.Name] = $p.Value }
        }

        # Look for values that look like DLL paths or names
        foreach ($vName in $vals.Keys) {
            $vValue = $vals[$vName]
            if ($vValue -and $vValue.ToString() -match '\.(dll|exe)\b') {
                $token = $vValue.ToString()
                $resolved = Resolve-PathFromString -s $token

                $fileExists = $false; $fileLastWrite = $null; $fileCreation = $null; $publisher = $null; $hash = $null
                if ($resolved -and (Test-Path $resolved)) {
                    $fileExists = $true
                    $fi = Get-Item -Path $resolved -ErrorAction SilentlyContinue
                    if ($fi) {
                        $fileLastWrite = $fi.LastWriteTime
                        $fileCreation = $fi.CreationTime
                    }
                    $sig = Get-AuthenticodeSignature -FilePath $resolved -ErrorAction SilentlyContinue
                    if ($sig -and $sig.SignerCertificate) { $publisher = $sig.SignerCertificate.Subject } else { $publisher = "Unsigned or Unknown" }
                    $hashObj = Get-FileHash -Path $resolved -Algorithm SHA256 -ErrorAction SilentlyContinue
                    if ($hashObj) { $hash = $hashObj.Hash }
                }

                $props = [ordered]@{
                    RegistryPath = $nk.PSPath
                    NotifySubKey = $nk.PSChildName
                    ValueName    = $vName
                    ValueData    = $vValue
                }
                if ($resolved) { $props['ResolvedPath'] = $resolved }
                if ($fileExists) { $props['FileExists'] = $fileExists }
                if ($fileLastWrite) { $props['FileLastWriteTime'] = $fileLastWrite }
                if ($fileCreation) { $props['FileCreationTime'] = $fileCreation }
                if ($publisher) { $props['FilePublisher'] = $publisher }
                if ($hash) { $props['SHA256Hash'] = $hash }

                $results += New-Object PSObject -Property $props
            } else {
                # non-dll value - still useful to output minimally
                $props = [ordered]@{
                    RegistryPath = $nk.PSPath
                    NotifySubKey = $nk.PSChildName
                    ValueName    = $vName
                    ValueData    = $vValue
                }
                $results += New-Object PSObject -Property $props
            }
        }
    }
}

# Final output (full, non-truncated)
if ($results.Count -eq 0) {
    Write-Output "No Winlogon values or Notify entries discovered."
} else {
    $results | Format-List
}

# Optional exports:
# $results | Export-Csv -Path ".\ASEP_Winlogon.csv" -NoTypeInformation
# $results | ConvertTo-Json -Depth 6 | Out-File ".\ASEP_Winlogon.json" -Encoding UTF8

# SIG # Begin signature block
# MIII1QYJKoZIhvcNAQcCoIIIxjCCCMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU4am4O4yoeiZ8RbXbH/W2HXB6
# 3nugggYoMIIGJDCCBQygAwIBAgITEwAAAOoKFpTrnDcwtAAEAAAA6jANBgkqhkiG
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
# BBRhveoDunDhmHB3yusPoqbubHcpijANBgkqhkiG9w0BAQEFAASCAQAm63PROEUC
# GRxW1jVIz8kNw8P3hQ78nhJj3efOr7saabxinzw+dGiISRV/2XfF76hr3iIhRlpX
# du2mfMVTlOqwViPXMj/C4ljPSpXx9A1uqJLXANV5cOttprL4XW5feyToED5VdULO
# eoJcj7Aj8DEgYcOQ9SrKjyXvZqLU8lp5ncyB+COtFI/48qPRfKtdzop1wyMXsvS0
# EkIMyA89KLB3XHkBHDoLcXudOxlZI2bf3ajlTfiPrWphTHMbiT4i86bM8Lz+sPsT
# bNhUcpRYsDLmwoFnGdp3sBe+NJiLLP30ZjmWgcGWJ+6mjbJNWk6+XrzX+M8ssech
# xExYTfkfyAzo
# SIG # End signature block
