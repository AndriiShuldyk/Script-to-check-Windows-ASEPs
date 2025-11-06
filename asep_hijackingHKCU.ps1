# =================================================================
# Windows ASEP Check - Extension Hijacking (HKCU)
# Scans HKCU:\Software\Classes for file extensions and resolves
# ProgID -> Shell\Open\Command and ProgID -> CLSID -> InprocServer32/LocalServer32
# Gathers file metadata only when a file path is resolved and exists.
# =================================================================

function Resolve-ExeFromCommand {
    param($command)
    if (-not $command) { return $null }

    # Try quoted path first
    if ($command -match '\"([^"]+\.exe|[^"]+\.dll)\"') {
        return [Environment]::ExpandEnvironmentVariables($matches[1])
    }

    # Try first token containing .exe or .dll
    if ($command -match '(^\S+\.(exe|dll))') {
        return [Environment]::ExpandEnvironmentVariables($matches[1])
    }

    return $null
}

$baseHKCU = 'HKCU:\Software\Classes'
$results = @()

# Get extension keys in HKCU (names starting with a dot)
$extKeys = Get-ChildItem -Path $baseHKCU -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\.' }

foreach ($extKey in $extKeys) {
    $extName = $extKey.PSChildName
    $extFullPath = $extKey.PSPath

    # Read default value => ProgID
    $progId = $null
    try {
        $progId = (Get-ItemProperty -Path $extFullPath -ErrorAction SilentlyContinue).'(default)'
    } catch {
        # fall back to registry provider behavior
        $progId = (Get-ItemProperty -Path $extFullPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty '(default)' -ErrorAction SilentlyContinue)
    }

    # Also capture other values under the extension key (e.g., PerceivedType, OpenWithProgids)
    $extValues = @{}
    $extProps = Get-ItemProperty -Path $extFullPath -ErrorAction SilentlyContinue
    foreach ($p in $extProps.PSObject.Properties) {
        if ($p.Name -notmatch '^PS') { $extValues[$p.Name] = $p.Value }
    }

    # Prepare container for resolved handler info
    $handlers = @()

    # 1) If ProgID is present, examine ProgID\Shell\Open\Command
    if ($progId) {
        $progPathHKCU = Join-Path $baseHKCU $progId

        # Shell command
        $openCommandPath = Join-Path $progPathHKCU 'Shell\Open\Command'
        $openCommand = $null
        if (Test-Path $openCommandPath) {
            $openCommand = (Get-ItemProperty -Path $openCommandPath -ErrorAction SilentlyContinue).'(default)'
        } else {
            # sometimes default action is directly under ProgID\shell
            $defaultShellPath = Join-Path $progPathHKCU 'shell'
            if (Test-Path $defaultShellPath) {
                # try the default verb
                $defaultVerb = (Get-ItemProperty -Path $progPathHKCU -ErrorAction SilentlyContinue).'(default)'
                if ($defaultVerb) {
                    $cmdPath = Join-Path $progPathHKCU ("shell\$defaultVerb\command")
                    if (Test-Path $cmdPath) {
                        $openCommand = (Get-ItemProperty -Path $cmdPath -ErrorAction SilentlyContinue).'(default)'
                    }
                }
            }
        }

        if ($openCommand) {
            $exe = Resolve-ExeFromCommand -command $openCommand
            $handlers += [PSCustomObject]@{ HandlerType='ShellCommand'; Location = $openCommandPath; Command = $openCommand; ResolvedPath = $exe }
        }

        # ProgID\CLSID
        $clsidVal = $null
        $clsidPath = Join-Path $progPathHKCU 'CLSID'
        if (Test-Path $clsidPath) {
            $clsidVal = (Get-ItemProperty -Path $clsidPath -ErrorAction SilentlyContinue).'(default)'
        }

        if ($clsidVal) {
            # Look up the CLSID registration under HKCU:\Software\Classes\CLSID\{...}
            $clsidRegPath = Join-Path (Join-Path $baseHKCU 'CLSID') $clsidVal
            if (Test-Path $clsidRegPath) {
                # Check InprocServer32 and LocalServer32
                $inproc = Join-Path $clsidRegPath 'InprocServer32'
                $local = Join-Path $clsidRegPath 'LocalServer32'

                if (Test-Path $inproc) {
                    $inprocCmd = (Get-ItemProperty -Path $inproc -ErrorAction SilentlyContinue).'(default)'
                    $exe = Resolve-ExeFromCommand -command $inprocCmd
                    $handlers += [PSCustomObject]@{ HandlerType='COM-Inproc'; Location=$inproc; Command=$inprocCmd; ResolvedPath=$exe; CLSID=$clsidVal }
                }
                if (Test-Path $local) {
                    $localCmd = (Get-ItemProperty -Path $local -ErrorAction SilentlyContinue).'(default)'
                    $exe = Resolve-ExeFromCommand -command $localCmd
                    $handlers += [PSCustomObject]@{ HandlerType='COM-Local'; Location=$local; Command=$localCmd; ResolvedPath=$exe; CLSID=$clsidVal }
                }
            } else {
                # CLSID not present under HKCU\Classes\CLSID - still record the CLSID value
                $handlers += [PSCustomObject]@{ HandlerType='COM-CLSID-Reference'; Location=$clsidPath; Command=$clsidVal; ResolvedPath=$null; CLSID=$clsidVal }
            }
        }

        # Additionally, check ProgID\Shell\Open\Command under HKLM fallback if not in HKCU
        if (-not $openCommand) {
            $progPathHKLM = "HKLM:\SOFTWARE\Classes\$progId"
            if (Test-Path $progPathHKLM) {
                $openCommandPath2 = Join-Path $progPathHKLM 'Shell\Open\Command'
                if (Test-Path $openCommandPath2) {
                    $openCommand2 = (Get-ItemProperty -Path $openCommandPath2 -ErrorAction SilentlyContinue).'(default)'
                    if ($openCommand2) {
                        $exe = Resolve-ExeFromCommand -command $openCommand2
                        $handlers += [PSCustomObject]@{ HandlerType='ShellCommand-HKLM'; Location = $openCommandPath2; Command = $openCommand2; ResolvedPath = $exe }
                    }
                }
            }
        }
    }

    # 2) If no ProgID or in addition, check if extension key itself defines a Shell\Open\Command
    $extShellCmdPath = Join-Path $extFullPath 'Shell\Open\Command'
    if (Test-Path $extShellCmdPath) {
        $extShellCmd = (Get-ItemProperty -Path $extShellCmdPath -ErrorAction SilentlyContinue).'(default)'
        if ($extShellCmd) {
            $exe = Resolve-ExeFromCommand -command $extShellCmd
            $handlers += [PSCustomObject]@{ HandlerType='ExtensionShellCommand'; Location = $extShellCmdPath; Command = $extShellCmd; ResolvedPath = $exe }
        }
    }

    # 3) Collect metadata per handler (only when ResolvedPath exists and file exists)
    foreach ($h in $handlers) {
        $resolved = $h.ResolvedPath
        $fileExists = $false; $fileLastWrite = $null; $fileCreation = $null; $publisher = $null; $hash = $null

        if ($resolved) {
            $expanded = [Environment]::ExpandEnvironmentVariables($resolved)
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
        }

        # Build output object dynamically
        $props = [ordered]@{
            ExtensionKeyPath = $extFullPath
            Extension        = $extName
        }

        if ($progId) { $props['ProgID'] = $progId }
        if ($extValues.Keys.Count -gt 0) { $props['ExtensionValues'] = ($extValues.Keys | ForEach-Object { "$_=`"$($extValues[$_])`"" }) -join '; ' }

        $props['HandlerType'] = $h.HandlerType
        $props['HandlerRegistryPath'] = $h.Location
        if ($h.Command) { $props['HandlerCommand'] = $h.Command }
        if ($h.CLSID) { $props['HandlerCLSID'] = $h.CLSID }
        if ($h.ResolvedPath) { $props['ResolvedPath'] = $h.ResolvedPath }
        if ($resolved -and $fileExists) { $props['FileExists'] = $fileExists }
        if ($fileLastWrite) { $props['FileLastWriteTime'] = $fileLastWrite }
        if ($fileCreation) { $props['FileCreationTime'] = $fileCreation }
        if ($publisher) { $props['FilePublisher'] = $publisher }
        if ($hash) { $props['SHA256Hash'] = $hash }

        $results += New-Object PSObject -Property $props
    }

    # If no handlers discovered, still output the extension key and ProgID for visibility
    if ($handlers.Count -eq 0) {
        $props = [ordered]@{
            ExtensionKeyPath = $extFullPath
            Extension        = $extName
        }
        if ($progId) { $props['ProgID'] = $progId }
        if ($extValues.Keys.Count -gt 0) { $props['ExtensionValues'] = ($extValues.Keys | ForEach-Object { "$_=`"$($extValues[$_])`"" }) -join '; ' }
        $results += New-Object PSObject -Property $props
    }
}

# Output results (full, non-truncated)
if ($results.Count -eq 0) {
    Write-Output "No HKCU extension handlers found under $baseHKCU."
} else {
    $results | Sort-Object Extension, HandlerType | Format-List
}

# Optional exports:
# $results | Export-Csv -Path ".\ASEP_ExtHijack_HKCU.csv" -NoTypeInformation
# $results | ConvertTo-Json -Depth 6 | Out-File ".\ASEP_ExtHijack_HKCU.json" -Encoding UTF8

# SIG # Begin signature block
# MIII1QYJKoZIhvcNAQcCoIIIxjCCCMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUTc4MxzD5L2hWXM3yKx0ukKbT
# gdGgggYoMIIGJDCCBQygAwIBAgITEwAAAOoKFpTrnDcwtAAEAAAA6jANBgkqhkiG
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
# BBS2iEkVpEtEhlCLnGGP3AL0tp4HCTANBgkqhkiG9w0BAQEFAASCAQBLgToHf6HF
# Plt3ssGSlCKhBVeOjyoLI9i+YYQJa2UFmPf1EyA3uDOfm+s+U7zecw60pzJljmP6
# hbehiipeQjEIBwMInqQ7nmg1oTf+x8m0dGL7+xIjRhX3zVIbfzXTvyu+jE1YLofW
# SvJx4h/bU3ZM4Jn1IOHfQ41KK/jpj7oEJRBGJ7Q0/+u3hjV5S1tMxKFiG2lULLtc
# JkuusHXNBDUJTCzbw7bIn+AXuBeVfZw17+S9q5t4gnIuQgtCvesieSWUsPn+YpBF
# mh36LbTuvFZyoFOUafkQisRUk26nRVEzOuqUsJbS7D9V/7skykmbMI1HxhlUKm2p
# i0BYp1SKe3ie
# SIG # End signature block
