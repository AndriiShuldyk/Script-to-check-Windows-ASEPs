# =================================================================
# Windows ASEP Check - AppInit DLLs
# Enumerates AppInit DLL configuration and gathers file metadata
# Only includes file-related properties when the file actually exists.
# =================================================================

function Resolve-PathFromToken {
    param($token)
    if (-not $token) { return $null }

    $tok = $token.ToString().Trim()
    $tok = [Environment]::ExpandEnvironmentVariables($tok)

    # If quoted path, return inner quoted path
    if ($tok -match '"([^"]+\.dll)"') { return $matches[1] }

    # Absolute path?
    if ($tok -match '^[A-Za-z]:\\.+\.dll$') { return $tok }

    # If only filename (no path), try common locations
    if ($tok -match '^[^\\\/]+\.dll$') {
        $candidates = @(
            Join-Path $env:windir ("System32\$tok"),
            Join-Path $env:windir ("SysWOW64\$tok"),
            Join-Path $env:windir $tok,
            Join-Path $env:ProgramFiles $tok,
            Join-Path ${env:ProgramFiles(x86)} $tok
        ) | Where-Object { $_ -ne $null } 

        foreach ($c in $candidates) {
            if (Test-Path $c) { return (Resolve-Path $c).ProviderPath }
        }

        # fallback: return filename (unresolved)
        return $tok
    }

    # Mixed or relative tokens - return expanded token as-is
    return $tok
}

# Registry base paths to check (regular and WOW6432Node)
$paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
)

$results = @()

foreach ($p in $paths) {
    if (-not (Test-Path $p)) { continue }

    $props = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue

    # Collect values of interest
    $appInitValue = $null
    $loadFlag = $null
    $requireSigned = $null

    if ($props.PSObject.Properties.Name -contains 'AppInit_DLLs') { $appInitValue = $props.AppInit_DLLs }
    if ($props.PSObject.Properties.Name -contains 'LoadAppInit_DLLs') { $loadFlag = $props.LoadAppInit_DLLs }
    if ($props.PSObject.Properties.Name -contains 'RequireSignedAppInit_DLLs') { $requireSigned = $props.RequireSignedAppInit_DLLs }

    # Build base object
    $baseProps = [ordered]@{
        RegistryPath = $p
    }
    if ($appInitValue) { $baseProps['AppInit_DLLs'] = $appInitValue }
    if ($null -ne $loadFlag) { $baseProps['LoadAppInit_DLLs'] = $loadFlag }
    if ($null -ne $requireSigned) { $baseProps['RequireSignedAppInit_DLLs'] = $requireSigned }

    # If there are no AppInit DLLs configured, output the base info and continue
    if (-not $appInitValue) {
        $results += New-Object PSObject -Property $baseProps
        continue
    }

    # Parse the AppInit_DLLs string into tokens (separators: semicolon, comma, space)
    $tokens = $appInitValue -split '[;,\s]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

    foreach ($t in $tokens) {
        $resolved = Resolve-PathFromToken -token $t

        # File metadata placeholders
        $fileExists = $false; $fileLastWrite = $null; $fileCreation = $null; $publisher = $null; $hash = $null

        if ($resolved) {
            # If path appears to exist on disk, collect metadata
            try {
                if (Test-Path $resolved) {
                    $fileExists = $true
                    $fi = Get-Item -Path $resolved -ErrorAction SilentlyContinue
                    if ($fi) {
                        $fileLastWrite = $fi.LastWriteTime
                        $fileCreation = $fi.CreationTime
                    }

                    $sig = Get-AuthenticodeSignature -FilePath $resolved -ErrorAction SilentlyContinue
                    if ($sig -and $sig.SignerCertificate) {
                        $publisher = $sig.SignerCertificate.Subject
                    } elseif ($sig) {
                        $publisher = "Unsigned or Unknown"
                    }

                    $hashObj = Get-FileHash -Path $resolved -Algorithm SHA256 -ErrorAction SilentlyContinue
                    if ($hashObj) { $hash = $hashObj.Hash }
                }
            } catch {
                # ignore file access errors
            }
        }

        # Build dynamic output (file fields only when present)
        $entryProps = $baseProps.Clone()
        $entryProps['DLL_Token'] = $t
        if ($resolved) { $entryProps['ResolvedPath'] = $resolved }
        if ($fileExists) { $entryProps['FileExists'] = $fileExists }
        if ($fileLastWrite) { $entryProps['FileLastWriteTime'] = $fileLastWrite }
        if ($fileCreation) { $entryProps['FileCreationTime'] = $fileCreation }
        if ($publisher) { $entryProps['FilePublisher'] = $publisher }
        if ($hash) { $entryProps['SHA256Hash'] = $hash }

        $results += New-Object PSObject -Property $entryProps
    }
}

# Output
if ($results.Count -eq 0) {
    Write-Output "No AppInit DLLs configuration found under the scanned registry paths."
} else {
    $results | Sort-Object RegistryPath, DLL_Token | Format-List
}

# Optional exports:
# $results | Export-Csv -Path ".\ASEP_AppInitDLLs.csv" -NoTypeInformation
# $results | ConvertTo-Json -Depth 5 | Out-File ".\ASEP_AppInitDLLs.json" -Encoding UTF8

# End of script

# SIG # Begin signature block
# MIII1QYJKoZIhvcNAQcCoIIIxjCCCMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUx0X9U6HP4QWXbHFyI6IgSqin
# BfigggYoMIIGJDCCBQygAwIBAgITEwAAAOoKFpTrnDcwtAAEAAAA6jANBgkqhkiG
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
# BBQFySitJhqg1Iq553HDip8jH0J1DTANBgkqhkiG9w0BAQEFAASCAQCRZK/N/S8p
# L9oal6Ab1B1gC5pvsWsLAsn3tmhahBcy2nEkVGsDy+yUN4hlD9yrhPCVer/FpbFD
# xDlQ8ZIuCiKXCSQsvNOZIgIrQh8lnZaHFnNs2ULoArPumo/InnM4fKC084qq7gKy
# p5aJKmYuuasdCgMpIDELd/8dm1CrYra6LH/srw6NDBSxNTqCu17LCCu7nr9sVFXZ
# EM6/TCyyC8WQyNHBcctQVhMfGIURuTkJBuHHKHWY5GFH1hee7tWo2mct0areIDpt
# x82+7d3AJk3j5D2xw2FiR8FidaQjleBroPEhADeHJo/vLwtHYunP6Yg2/4d3Jd/E
# vYF6X473GLMa
# SIG # End signature block
