# =================================================================
# Windows ASEP Check - Active Setup (HKCU)
# Scans HKCU:\Software\Microsoft\Active Setup\Installed Components
# Gathers Version, StubPath and file metadata (only when file exists).
# =================================================================

function Resolve-PathFromCommand {
    param($cmd)
    if (-not $cmd) { return $null }

    # Expand environment variables
    $s = [Environment]::ExpandEnvironmentVariables($cmd.ToString())

    # Quoted exe/dll path
    if ($s -match '"([^"]+\.(exe|dll))"') { return $matches[1] }

    # Unquoted absolute exe/dll path
    if ($s -match '([A-Za-z]:\\[^,\s"]+\.(exe|dll))') { return $matches[1] }

    # First token ends with .exe/.dll — try resolving
    if ($s -match '(^\S+\.(exe|dll))') {
        $candidate = $matches[1]

        # Try common locations
        $tryPaths = @(
            (Join-Path $env:windir ("System32\$candidate")),
            (Join-Path $env:windir ("SysWOW64\$candidate")),
            (Join-Path $env:windir $candidate),
            (Join-Path $env:ProgramFiles $candidate)
        )

        if ($env:ProgramFiles -ne ${env:ProgramFiles(x86)}) {
            $tryPaths += (Join-Path ${env:ProgramFiles(x86)} $candidate)
        }

        foreach ($p in $tryPaths) {
            if (Test-Path $p) { return (Resolve-Path $p).ProviderPath }
        }

        return $candidate
    }

    return $null
}

function Get-FileMetadataIfExists {
    param($path)
    if (-not $path) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($path)
    $meta = [ordered]@{}
    try {
        if (Test-Path $expanded) {
            $fi = Get-Item -Path $expanded -ErrorAction SilentlyContinue
            if ($fi) {
                $meta.FileExists = $true
                $meta.FileLastWriteTime = $fi.LastWriteTime
                $meta.FileCreationTime  = $fi.CreationTime
            }
            $sig = Get-AuthenticodeSignature -FilePath $expanded -ErrorAction SilentlyContinue
            if ($sig -and $sig.SignerCertificate) { 
                $meta.FilePublisher = $sig.SignerCertificate.Subject 
            } else { 
                $meta.FilePublisher = "Unsigned or Unknown" 
            }
            $hashObj = Get-FileHash -Path $expanded -Algorithm SHA256 -ErrorAction SilentlyContinue
            if ($hashObj) { $meta.SHA256Hash = $hashObj.Hash }
        } else {
            $meta.FileExists = $false
        }
    } catch {}
    return $meta
}

$baseHKCU = "HKCU:\Software\Microsoft\Active Setup\Installed Components"
$baseHKLM = "HKLM:\Software\Microsoft\Active Setup\Installed Components"
$results = @()

if (-not (Test-Path $baseHKCU)) {
    Write-Output "No per-user Active Setup key found at $baseHKCU"
} else {
    $subKeys = Get-ChildItem -Path $baseHKCU -ErrorAction SilentlyContinue
    foreach ($sk in $subKeys) {
        $guid = $sk.PSChildName
        $fullPath = $sk.PSPath
        $vals = Get-ItemProperty -Path $fullPath -ErrorAction SilentlyContinue

        $valueTable = @{}
        foreach ($p in $vals.PSObject.Properties) {
            if ($p.Name -notmatch '^PS') { $valueTable[$p.Name] = $p.Value }
        }

        $version = $valueTable['Version']
        $stub = $valueTable['StubPath']

        # HKLM comparison
        $hkLMVersion = $null
        $hkLMKey = Join-Path $baseHKLM $guid
        if (Test-Path $hkLMKey) {
            $hkVals = Get-ItemProperty -Path $hkLMKey -ErrorAction SilentlyContinue
            foreach ($p in $hkVals.PSObject.Properties) {
                if ($p.Name -ieq 'Version') { $hkLMVersion = $p.Value }
            }
        }

        # Resolve stub path
        $resolvedPath = $null
        $fileMeta = $null
        if ($stub) {
            $resolvedPath = Resolve-PathFromCommand -cmd $stub
            if ($resolvedPath) { $fileMeta = Get-FileMetadataIfExists -path $resolvedPath }
        }

        # Build output
        $props = [ordered]@{
            HKCU_KeyPath = $fullPath
            GUID         = $guid
        }
        if ($version) { $props['HKCU_Version'] = $version }
        if ($stub) { $props['HKCU_StubPath'] = $stub }
        if ($hkLMVersion) { $props['HKLM_Version'] = $hkLMVersion }
        if ($resolvedPath) { $props['ResolvedPath'] = $resolvedPath }

        if ($fileMeta) {
            foreach ($k in $fileMeta.Keys) {
                $props[$k] = $fileMeta[$k]
            }
        }

        $otherKeys = $valueTable.Keys | Where-Object { $_ -notin @('Version','StubPath') }
        if ($otherKeys.Count -gt 0) {
            $props['OtherValues'] = ($otherKeys | ForEach-Object { "$_=`"$($valueTable[$_])`"" }) -join '; '
        }

        $results += New-Object PSObject -Property $props
    }
}

if ($results.Count -eq 0) {
    Write-Output "No Active Setup entries found under HKCU."
} else {
    $results | Sort-Object GUID | Format-List
}

# Optional exports
# $results | Export-Csv -Path ".\ASEP_ActiveSetup_HKCU.csv" -NoTypeInformation
# $results | ConvertTo-Json -Depth 6 | Out-File ".\ASEP_ActiveSetup_HKCU.json" -Encoding UTF8

# SIG # Begin signature block
# MIII1QYJKoZIhvcNAQcCoIIIxjCCCMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJuCd3J+rPnXThxEjxBmN4YXA
# S9qgggYoMIIGJDCCBQygAwIBAgITEwAAAOoKFpTrnDcwtAAEAAAA6jANBgkqhkiG
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
# BBR0RzEHuiCy+BSWO+dj2QzygXGCqzANBgkqhkiG9w0BAQEFAASCAQAwbkAmYKlZ
# oVJezRxasmM2JzSDerI7H/Izth48g9ETn6jTaaeJS+1hbNOlvLdJ6z8Y3RprcYyW
# TJjxzAefykfGHFK5VUWwZfkc1x48EdFPreK8h7GNUI22KrZ52+Bp93q+0aI3UrRa
# ZJVeftp3ln4J4w4TInjRmU5TNMExGMFpqezqSi8JzLAhXHJ1pf6Y78HUIh7slFtp
# +LJqRQQqfPy47XP9hKpIqXGsMdNsFZn04IODLCrwfVIAvzEEMdFIJhQUx69YS6YZ
# 1nYoWNO4JQiWa96VAiC4Lg4hZ9hbHYYdJBU5i1U1wyJoKsuHlWFIb3ioEYo/3u8J
# 3CMN7yKQAmor
# SIG # End signature block
