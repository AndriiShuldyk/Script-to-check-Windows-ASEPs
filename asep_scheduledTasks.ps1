# =================================================================
# Windows ASEP Check - Scheduled Tasks (robust path extraction)
# Lists scheduled tasks and extracts command + file metadata
# =================================================================

function Resolve-ExePathFromString {
    param([string]$s)

    if (-not $s) { return $null }

    # 1) If there's a quoted path that ends with .exe, use it
    if ($s -match '"([^"]+\.exe)"') {
        return $matches[1].Trim()
    }

    # 2) Try to find a windows absolute path (C:\...\.exe) as first match
    # Allow spaces inside path only if quoted (handled above). This will match until whitespace or a quote.
    if ($s -match '([A-Za-z]:\\[^"\s<>|]+?\.exe)') {
        $path = $matches[1].Trim()
        # Clean trailing punctuation that could be attached (e.g. '":String' or trailing commas)
        $path = $path -replace '[\)\]\}",;:]+$',''
        return $path
    }

    # 3) Some tasks use program names only (e.g. powershell.exe); return that token if it looks like *.exe
    if ($s -match '(^\S+\.exe)') {
        $path = $matches[1].Trim()
        $path = $path -replace '[\)\]\}",;:]+$',''
        return $path
    }

    return $null
}

$results = @()

# Get all tasks (requires PS 3+). Some system tasks may hide details when not elevated.
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue

foreach ($task in $tasks) {
    $taskInfo = $null
    try {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
    } catch {}

    foreach ($action in $task.Actions) {
        # Each action may have Execute and Arguments properties, but sometimes Execute contains combined info.
        $rawExecute = $action.Execute
        $rawArgs    = $action.Arguments

        # Try to resolve a clean executable path
        $exePath = Resolve-ExePathFromString -s $rawExecute

        # If exePath is null but arguments start with an exe-like token, try to parse from arguments (edge cases)
        if (-not $exePath -and $rawArgs) {
            $exePath = Resolve-ExePathFromString -s $rawArgs
        }

        $fileExists = $false
        $filePublisher = $null
        $hash = $null
        $fileLastWrite = $null
        $fileCreation = $null

        if ($exePath) {
            # Some returned paths may still be relative or point to environment variables;
            # attempt to expand environment variables and normalize.
            try {
                $exePathExpanded = [Environment]::ExpandEnvironmentVariables($exePath)
            } catch {
                $exePathExpanded = $exePath
            }

            # Ensure we don't pass invalid paths to Test-Path
            if ($exePathExpanded -and ($exePathExpanded -notmatch '[\x00-\x1F]')) {
                if (Test-Path $exePathExpanded) {
                    $fileExists = $true
                    $fileItem = Get-Item $exePathExpanded -ErrorAction SilentlyContinue
                    if ($fileItem) {
                        $fileLastWrite = $fileItem.LastWriteTime
                        $fileCreation = $fileItem.CreationTime
                    }

                    # Authenticode signature (may be slow on many files)
                    try {
                        $sig = Get-AuthenticodeSignature -FilePath $exePathExpanded -ErrorAction SilentlyContinue
                        if ($sig -and $sig.SignerCertificate) {
                            $filePublisher = $sig.SignerCertificate.Subject
                        } else {
                            $filePublisher = "Unsigned or Unknown"
                        }
                    } catch {
                        $filePublisher = "SignatureCheckError"
                    }

                    try {
                        $hashObj = Get-FileHash -Path $exePathExpanded -Algorithm SHA256 -ErrorAction SilentlyContinue
                        $hash = $hashObj.Hash
                    } catch {
                        $hash = $null
                    }
                }
            }
        }

        $entry = [PSCustomObject]@{
            TaskName       = $task.TaskName
            TaskPath       = $task.TaskPath
            Author         = $task.Principal.UserId
            RunAsUser      = $task.Principal.LogonType
            RawExecute     = $rawExecute
            RawArguments   = $rawArgs
            ResolvedExe    = $exePath
            LastRunTime    = $taskInfo.LastRunTime
            NextRunTime    = $taskInfo.NextRunTime
            FileExists     = $fileExists
            FileLastWrite  = $fileLastWrite
            FileCreation   = $fileCreation
            FilePublisher  = $filePublisher
            SHA256Hash     = $hash
        }

        $results += $entry
    }
}

# Output: full details (no truncation)
$results | Sort-Object TaskPath, TaskName | Format-List

# Optional export for deeper analysis
# $results | Export-Csv -Path ".\ASEP_ScheduledTasks_Details.csv" -NoTypeInformation -Encoding UTF8

# SIG # Begin signature block
# MIII1QYJKoZIhvcNAQcCoIIIxjCCCMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUltgE5E5ig+JHJLtM+Qg8LRrY
# 6JOgggYoMIIGJDCCBQygAwIBAgITEwAAAOoKFpTrnDcwtAAEAAAA6jANBgkqhkiG
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
# BBQK7ExSNKz8i//KK5dIzd9E+m5LBTANBgkqhkiG9w0BAQEFAASCAQAs0aLV4k9k
# KlLwIkgCk2inI/Ru0C1KJ4QsU5c5TlmGQjlXRDw8CeUxKcTQ8ovALG8jvW2awcqf
# zyC60Rr+aB6cWKlsPP7A4t/bOV1ScyoGct6Qi+ZGwU5zOwcbuS+iyUAgAiHQDtmp
# mAN6hpdmaszkCwT4vQTuaabQIqdtL6tk5vFrEEiDONTh13l6b7UMcLBrN/BFCkJ5
# ju+uFNYWpTNyxCMEgB4QYOG4BIadhbveMhz8eurHXDQBySlR63yyRxucaQaZdno+
# QqZ8+fr4gldwsp6oPeFdgRW8d1wryFO7AmI/+FocL5viONM7udBFLKMsM88aobbw
# YE8FvE66sbHf
# SIG # End signature block
