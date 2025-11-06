# =================================================================
# Windows ASEP Check - Startup Folders (All Users + Current User)
# =================================================================

# Define startup folder paths
$startupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",  # All Users
    "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup"       # Current User
)

$results = @()

foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        $items = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue

        foreach ($item in $items) {
            $targetPath = $item.FullName
            $fileExists = $false
            $fileLastWrite = $null
            $fileCreation = $null
            $publisher = $null
            $hash = $null

            # --- Resolve shortcut target if it's a .lnk file ---
            if ($item.Extension -eq ".lnk") {
                $shell = New-Object -ComObject WScript.Shell
                $shortcut = $shell.CreateShortcut($item.FullName)
                $targetPath = $shortcut.TargetPath
            }

            # --- If target exists, gather metadata ---
            if ($targetPath -and (Test-Path $targetPath)) {
                $fileExists = $true
                $fileItem = Get-Item $targetPath -ErrorAction SilentlyContinue
                $fileLastWrite = $fileItem.LastWriteTime
                $fileCreation = $fileItem.CreationTime

                $sig = Get-AuthenticodeSignature -FilePath $targetPath -ErrorAction SilentlyContinue
                if ($sig.SignerCertificate) {
                    $publisher = $sig.SignerCertificate.Subject
                } else {
                    $publisher = "Unsigned or Unknown"
                }

                $hashObj = Get-FileHash -Path $targetPath -Algorithm SHA256 -ErrorAction SilentlyContinue
                $hash = $hashObj.Hash
            }

            $entry = [PSCustomObject]@{
                StartupFolder     = $folder
                Name              = $item.Name
                ShortcutPath      = $item.FullName
                TargetPath        = $targetPath
                FileExists        = $fileExists
                FileLastWriteTime = $fileLastWrite
                FileCreationTime  = $fileCreation
                FilePublisher     = $publisher
                SHA256Hash        = $hash
            }

            $results += $entry
        }
    } else {
        Write-Verbose "Startup folder not found: $folder"
    }
}

# --- Output options ---
# Full readable console output
$results | Format-List

# Optionally export for review
# $results | Export-Csv -Path ".\ASEP_StartupFolders.csv" -NoTypeInformation

# SIG # Begin signature block
# MIII1QYJKoZIhvcNAQcCoIIIxjCCCMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUfBXBnYH6cbhlod5N97wHlfvX
# pMigggYoMIIGJDCCBQygAwIBAgITEwAAAOoKFpTrnDcwtAAEAAAA6jANBgkqhkiG
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
# BBSL04BtaHK9IT01RE8bZn4J9JwlJjANBgkqhkiG9w0BAQEFAASCAQAIJ7uuv2zD
# Sl6idfCIBsclDHk+6kw4LNhvVlGF5FN4s5tie9bq+NPKrPm/HimdFYnGPgKqVCIt
# PbJBQLoAvKjZU6oQ5jB6aB9eoeW/B4Y0Sh9h3L8FHVOECKXb30nxgTgp8rXG8rEv
# Li3wjnfjuFOO6Udws5cEE8Z3Et37Rkg0jQ5hRg4YSDRZNEL72I8YKTPduJQ9byeI
# m+wuUgiy4KtsJHaxLs5bZwyj/kNz4Ksj73ezefgEAkSFJfhpnwJYq+aC3lXI6sM0
# MWGPI1sqqkwCO5MZSjuiuoAybVXCEDEUNrKDcLwodxZR7Sux7gPkdlY+hYG4PPa/
# H6gF9Ja+XiJv
# SIG # End signature block
