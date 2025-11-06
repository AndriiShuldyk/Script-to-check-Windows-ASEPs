# =================================================================
# Windows ASEP Check - Active Setup (HKLM)
# Scans HKLM Active Setup Installed Components and gathers metadata
# File metadata (timestamps, publisher, hash) are included only when the file exists.
# =================================================================

function Resolve-PathFromString {
    param($s)
    if (-not $s) { return $null }

    # Expand environment variables and convert to string
    $s = [Environment]::ExpandEnvironmentVariables($s.ToString())

    # Try quoted path first (exe or dll)
    if ($s -match '"([^"]+\.(exe|dll))"') {
        return $matches[1]
    }

    # Try absolute path tokens
    if ($s -match '([A-Za-z]:\\[^,\s"]+\.(exe|dll))') {
        return $matches[1]
    }

    # Try rundll32 pattern
    if ($s -match '(?i)rundll32(?:\.exe)?\s+\"?([A-Za-z]:\\[^"\s,]+\.dll)\"?') {
        return $matches[1]
    }

    # Try first token containing .exe or .dll
    if ($s -match '(^\S+\.(exe|dll))') {
        $candidate = $matches[1]
        # If candidate is filename-only, try typical resolution locations
        if ($candidate -notmatch '^[A-Za-z]:\\') {
            $sys32 = Join-Path $env:windir "System32\$candidate"
            $syswow = Join-Path $env:windir "SysWOW64\$candidate"
            $win = Join-Path $env:windir $candidate
            $pf = Join-Path $env:ProgramFiles $candidate
            $pf86 = $null
            if ($env:ProgramFiles -ne ${env:ProgramFiles(x86)}) {
                $pf86 = Join-Path ${env:ProgramFiles(x86)} $candidate
            }

            if (Test-Path $candidate) { return (Resolve-Path $candidate).ProviderPath }
            if (Test-Path $sys32) { return (Resolve-Path $sys32).ProviderPath }
            if (Test-Path $syswow) { return (Resolve-Path $syswow).ProviderPath }
            if (Test-Path $win) { return (Resolve-Path $win).ProviderPath }
            if ($pf -and (Test-Path $pf)) { return (Resolve-Path $pf).ProviderPath }
            if ($pf86 -and (Test-Path $pf86)) { return (Resolve-Path $pf86).ProviderPath }

            return $candidate
        } else {
            return $candidate
        }
    }

    return $null
}

# Paths to scan (HKLM and 32-bit WOW6432Node view)
$activeSetupPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components"
)

$results = @()

foreach ($basePath in $activeSetupPaths) {
    if (-not (Test-Path $basePath)) {
        Write-Verbose "Active Setup base key not found: $basePath"
        continue
    }

    $components = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue
    foreach ($comp in $components) {
        $vals = Get-ItemProperty -Path $comp.PSPath -ErrorAction SilentlyContinue
        $valueTable = @{}
        foreach ($p in $vals.PSObject.Properties) {
            if ($p.Name -notmatch '^PS') { $valueTable[$p.Name] = $p.Value }
        }

        $version = $valueTable['Version']
        $stubPath = $valueTable['StubPath']

        # Resolve possible executable/DLL from StubPath (if present)
        $resolved = $null
        $fileExists = $false; $fileLastWrite = $null; $fileCreation = $null; $publisher = $null; $hash = $null

        if ($stubPath) {
            $resolved = Resolve-PathFromString -s $stubPath
            if ($resolved) {
                $expanded = [Environment]::ExpandEnvironmentVariables($resolved)
                if (Test-Path $expanded) {
                    $fileExists = $true
                    try {
                        $fi = Get-Item -Path $expanded -ErrorAction SilentlyContinue
                        if ($fi) {
                            $fileLastWrite = $fi.LastWriteTime
                            $fileCreation = $fi.CreationTime
                        }
                        $sig = Get-AuthenticodeSignature -FilePath $expanded -ErrorAction SilentlyContinue
                        if ($sig -and $sig.SignerCertificate) {
                            $publisher = $sig.SignerCertificate.Subject
                        } else {
                            $publisher = "Unsigned or Unknown"
                        }
                        $hashObj = Get-FileHash -Path $expanded -Algorithm SHA256 -ErrorAction SilentlyContinue
                        if ($hashObj) { $hash = $hashObj.Hash }
                    } catch { }
                }
            }
        }

        # Compose dynamic output object: include file-related fields only when present
        $props = [ordered]@{
            ActiveSetupBase       = $basePath
            ComponentKeyName      = $comp.PSChildName
            ComponentRegistryPath = $comp.PSPath
        }

        if ($valueTable.ContainsKey('DisplayName')) { $props['DisplayName'] = $valueTable['DisplayName'] }
        if ($version) { $props['Version'] = $version }
        if ($valueTable.ContainsKey('Locale')) { $props['Locale'] = $valueTable['Locale'] }
        if ($stubPath) { $props['StubPath'] = $stubPath }
        if ($resolved) { $props['ResolvedPath'] = $resolved }
        if ($fileExists) { $props['FileExists'] = $fileExists }
        if ($fileLastWrite) { $props['FileLastWriteTime'] = $fileLastWrite }
        if ($fileCreation) { $props['FileCreationTime'] = $fileCreation }
        if ($publisher) { $props['FilePublisher'] = $publisher }
        if ($hash) { $props['SHA256Hash'] = $hash }

        $results += New-Object PSObject -Property $props
    }
}

if ($results.Count -eq 0) {
    Write-Output "No Active Setup entries found under the scanned HKLM paths."
} else {
    $results | Sort-Object ActiveSetupBase, ComponentKeyName | Format-List
}

# Optional export
# $results | Export-Csv -Path ".\ASEP_ActiveSetup_HKLM.csv" -NoTypeInformation
# $results | ConvertTo-Json -Depth 6 | Out-File ".\ASEP_ActiveSetup_HKLM.json" -Encoding UTF8

# SIG # Begin signature block
# MIII1QYJKoZIhvcNAQcCoIIIxjCCCMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUjeHCxBdRrHiBlpa3BvH81+MU
# vbWgggYoMIIGJDCCBQygAwIBAgITEwAAAOoKFpTrnDcwtAAEAAAA6jANBgkqhkiG
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
# BBRglaa4FX8ZjDoqZ28RIMPftXVtQzANBgkqhkiG9w0BAQEFAASCAQBaRAghjrEE
# 4wPbyqhB05O8e/gzGQfG7APrmEMoIG3+271v0ncWQs+DuApSYh12+IrJptAw8SvE
# 5ug6c2mr9NO3h6ulmrBioljwawc3B+jc3PmPFLXbpFjrdquAIiLiw14BUTHIK7qX
# SNwHBnaEADT85ggvrEjf92nfueOTbUuBMkCKHsh0YHUEGAmFMrR0RY9N/P+kCd5V
# /H8zroW6cjurpPlRjvKHcS1LRsrSeV7YZ1ThR9GRFQbRNSGYPlILLR2+rM7BFMpP
# 1PuDXdPW7/SmFG6GVf9iVe72+08JvWzelrGajn5XC3C14OwJwrp3X8yU4sGjbIzU
# nuXqXPJbUzXL
# SIG # End signature block
