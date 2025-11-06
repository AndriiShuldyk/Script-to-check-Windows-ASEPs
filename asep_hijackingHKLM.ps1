# =================================================================
# Windows ASEP Check - Extension Hijacking (HKLM)
# Checks file-extension handlers and gathers file metadata
# =================================================================

$basePath = "HKLM:\Software\Classes"

$results = @()

# Get all keys that look like file extensions (e.g., ".txt", ".exe")
$extKeys = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\.' }

foreach ($extKey in $extKeys) {
    $defaultHandler = (Get-ItemProperty -Path $extKey.PSPath -ErrorAction SilentlyContinue).'(default)'

    if (-not $defaultHandler) { continue }

    # Try to resolve the open command
    $commandPath = Join-Path -Path $basePath -ChildPath "$defaultHandler\shell\open\command"

    $command = $null
    if (Test-Path $commandPath) {
        $command = (Get-ItemProperty -Path $commandPath -ErrorAction SilentlyContinue).'(default)'
    }

    # --- Extract executable path from command ---
    $exePath = $null
    if ($command -match '\"([^"]+\.exe)\"') {
        $exePath = $matches[1]
    } elseif ($command -match '(^\S+\.exe)') {
        $exePath = $matches[1]
    }

    # --- Gather file metadata only if the file exists ---
    $fileExists = $false
    $fileLastWrite = $null
    $fileCreation = $null
    $publisher = $null
    $hash = $null

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

    # --- Build dynamic object with only meaningful fields ---
    $props = [ordered]@{
        ExtensionKey          = $extKey.PSChildName
        ExtensionRegistryPath = $extKey.PSPath
        DefaultHandler        = $defaultHandler
    }

    if ($command) { $props['OpenCommand'] = $command }
    if ($exePath)  { $props['ExePath'] = $exePath }
    if ($fileExists) { $props['FileExists'] = $fileExists }
    if ($fileLastWrite) { $props['FileLastWriteTime'] = $fileLastWrite }
    if ($fileCreation)  { $props['FileCreationTime'] = $fileCreation }
    if ($publisher)     { $props['FilePublisher'] = $publisher }
    if ($hash)          { $props['SHA256Hash'] = $hash }

    $results += New-Object PSObject -Property $props
}

if ($results.Count -eq 0) {
    Write-Output "No HKLM extension hijacks or unusual handlers found."
} else {
    $results | Sort-Object ExtensionKey | Format-List
}

# Optional export
# $results | Export-Csv -Path ".\ASEP_ExtensionHijacking_HKLM.csv" -NoTypeInformation

# SIG # Begin signature block
# MIII1QYJKoZIhvcNAQcCoIIIxjCCCMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU4rpUiPnSv+rpa8BRkEvIwFvx
# ox6gggYoMIIGJDCCBQygAwIBAgITEwAAAOoKFpTrnDcwtAAEAAAA6jANBgkqhkiG
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
# BBRQjNF59hJE+Lsrn+AViLWVqBMcjTANBgkqhkiG9w0BAQEFAASCAQCY0RUcSLzK
# WBxKIgJTfqYYhKppRkKOcvcz/yLUrKpQvrHx0IHsmioWzYeshOciynGD/znQhqt4
# skc81cInqJ6X1Os3lYUhUWyzGbBzsEucCRRjAL2okmx1kchM5lL62Me+FxjQNx6r
# fxzsg2dYX6vsbQzcNpXzX3rDoDSsrL16lIud53DciPJg5Gk4/oPpeXa3B9sJ5K8C
# o4EUVhWTemaWHj5RxDWbTclh6zpAuuA+vJr+W1q14sLcbyWWcuQGKqEsYaZ1HiRX
# g8VT9Vbzow17rQ9aGuILykBIea8Nw3ssCtmmT19VpAn1m9Ia0ND7a1OaO/huRSP0
# DY9b3RnmQYYs
# SIG # End signature block
