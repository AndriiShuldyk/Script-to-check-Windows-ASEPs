# =================================================================
# Windows ASEP Check - Trojanized System Binaries
# Finds files outside system folders that share names with system executables
# and collects metadata (only when file exists)
# =================================================================

# --- Configuration: places to search for suspicious copies ---
$windowsDir = $env:windir
$system32 = Join-Path $windowsDir "System32"
$syswow64 = Join-Path $windowsDir "SysWOW64"

# High-risk, user-writable locations to scan (customize as needed)
$searchPaths = @()
if ($env:APPDATA)        { $searchPaths += $env:APPDATA }
if ($env:LOCALAPPDATA)   { $searchPaths += $env:LOCALAPPDATA }
if ($env:TEMP)           { $searchPaths += $env:TEMP }
if ($env:USERPROFILE)    { $searchPaths += (Join-Path $env:USERPROFILE "Downloads") }
$searchPaths += "C:\Users\Public"
$searchPaths += $env:ProgramData

# Also include non-system PATH entries (files earlier in PATH can shadow system binaries)
$pathEntries = ($env:Path -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not ($_.TrimEnd('\') -ieq $system32.TrimEnd('\')) -and -not ($_.TrimEnd('\') -ieq $syswow64.TrimEnd('\')) -and -not ($_.TrimEnd('\') -ieq $windowsDir.TrimEnd('\')) } 
$searchPaths += $pathEntries

# Deduplicate and keep only existing directories
$searchPaths = $searchPaths | Sort-Object -Unique | Where-Object { Test-Path $_ -PathType Container } 

# --- Build canonical system executable name set ---
$systemExeNames = @{}
foreach ($dir in @($system32, $syswow64)) {
    if (Test-Path $dir) {
        try {
            Get-ChildItem -Path $dir -Filter '*.exe' -File -ErrorAction SilentlyContinue | ForEach-Object {
                $systemExeNames[$_.Name.ToLower()] = $_.FullName
            }
        } catch { }
    }
}

# If no system exe found (unlikely), bail
if ($systemExeNames.Count -eq 0) {
    Write-Warning "Could not enumerate system executables in $system32 or $syswow64. Aborting."
    return
}

# --- Scan searchPaths for .exe files and check if their filename matches a system exe ---
$results = @()
foreach ($sp in $searchPaths) {
    # Use -Recurse carefully; exclude large folders if necessary (customize ExcludePaths if desired)
    try {
        $files = Get-ChildItem -Path $sp -Filter '*.exe' -File -Recurse -ErrorAction SilentlyContinue
    } catch {
        # If recursion fails (permissions or too many files), fallback to top-level
        try { $files = Get-ChildItem -Path $sp -Filter '*.exe' -File -ErrorAction SilentlyContinue } catch { $files = @() }
    }

    foreach ($f in $files) {
        $name = $f.Name.ToLower()
        if ($systemExeNames.ContainsKey($name)) {
            # It's a file that uses a system executable name but is located outside system folder
            $origSystemPath = $systemExeNames[$name]

            # Gather file metadata
            $filePath = $f.FullName
            $fileSize = $f.Length
            $fileLastWrite = $f.LastWriteTime
            $fileCreation = $f.CreationTime

            # Publisher (Authenticode)
            $publisher = $null
            $sig = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction SilentlyContinue
            if ($sig -and $sig.SignerCertificate) { $publisher = $sig.SignerCertificate.Subject } else { $publisher = "Unsigned or Unknown" }

            # Hash
            $hash = $null
            $hashObj = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction SilentlyContinue
            if ($hashObj) { $hash = $hashObj.Hash }

            # Build report object (file-related fields always present here)
            $props = [ordered]@{
                SuspiciousCopyPath      = $filePath
                SuspiciousFileName      = $f.Name
                OriginalSystemPath      = $origSystemPath
                FileSizeBytes           = $fileSize
                FileLastWriteTime       = $fileLastWrite
                FileCreationTime        = $fileCreation
                FilePublisher           = $publisher
                SHA256Hash              = $hash
                SearchPathScannedFrom   = $sp
            }

            $results += New-Object PSObject -Property $props
        }
    }
}

# --- Additionally: check system copies for signature / publisher info (flag if not Microsoft) ---
$systemChecks = @()
foreach ($kv in $systemExeNames.GetEnumerator()) {
    $sysPath = $kv.Value
    $pub = $null
    $hash = $null
    if (Test-Path $sysPath) {
        $si = Get-AuthenticodeSignature -FilePath $sysPath -ErrorAction SilentlyContinue
        if ($si -and $si.SignerCertificate) { $pub = $si.SignerCertificate.Subject } else { $pub = "Unsigned or Unknown" }
        $h = Get-FileHash -Path $sysPath -Algorithm SHA256 -ErrorAction SilentlyContinue
        if ($h) { $hash = $h.Hash }
        # Only include system items that are unsigned or not clearly Microsoft (reduce noise)
        if ($pub -and ($pub -notmatch 'Microsoft' -and $pub -ne 'Unsigned or Unknown')) {
            # benign third-party signed system executables are rare; include as informative
            $systemChecks += [PSCustomObject]@{
                SystemFile = $sysPath
                FilePublisher = $pub
                SHA256 = $hash
            }
        } elseif ($pub -eq 'Unsigned or Unknown') {
            # include unsigned system binaries — could indicate tampering (but also possible on some systems)
            $systemChecks += [PSCustomObject]@{
                SystemFile = $sysPath
                FilePublisher = $pub
                SHA256 = $hash
            }
        }
    }
}

# --- Output ---
if ($results.Count -eq 0) {
    Write-Output "No suspicious system-named copies found in scanned locations."
} else {
    Write-Output "`n== Suspicious copies of system binaries found =="
    $results | Sort-Object SuspiciousFileName, SuspiciousCopyPath | Format-List
    # Optional export:
    # $results | Export-Csv -Path ".\Trojanized_System_Binaries_Found.csv" -NoTypeInformation
}

if ($systemChecks.Count -gt 0) {
    Write-Output "`n== System file signature anomalies (unsigned/not-Microsoft) =="
    $systemChecks | Sort-Object SystemFile | Format-List
}

# --- End of script ---

# SIG # Begin signature block
# MIII1QYJKoZIhvcNAQcCoIIIxjCCCMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUbjRmi4hCiBBAu833g7bGKBTI
# aFygggYoMIIGJDCCBQygAwIBAgITEwAAAOoKFpTrnDcwtAAEAAAA6jANBgkqhkiG
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
# BBTx5MUafETGUux7bGRKXuBPnYiQOjANBgkqhkiG9w0BAQEFAASCAQCD3Wy3SwH/
# 0lLdWQ8foALYuisxserXUA+9yLTO4G42GOOSpHy3zxzBdfy8dY845/cPO24Ur8D/
# DSXp9WRRLvAnX7b2Vskyg11BeDj+uy/5KGKBMiEMYV74Yp7yYZMO9PWOQAt9sFs4
# 4kBvo5gJGBzoYKJm1YpsB6+vUWNg8CV3vMJ59AwHnkz3YLGquXpUYN928HsOz2Ax
# Svv5ScEF0BNVqkBBZq1NkEySc5Kbie1q8etongdNrudhikZA5nLdk4jgqFQmsoqA
# GThp+kzKxNHSCYHl6RQPbe6aHMVC21l1d94/aBjk0DbXsDn//2Jfn3zbnzlAm+vL
# DaxvXtz+iyqn
# SIG # End signature block
