# =================================================================
# Windows ASEP Check - Combined ASEP Modules
# Includes: Run Keys (HKLM/HKCU), Startup Folders, Scheduled Tasks,
# Services, Shortcuts Manipulation
# =================================================================

param (
    [switch]$HKLM,
    [switch]$HKCU,
    [switch]$Startup,
    [switch]$Tasks,
    [switch]$Services,
    [switch]$Shortcuts, 
    [switch]$IFEO, 
    [switch]$HijackingHKLM,
    [switch]$HijackingHKCU,
    [switch]$Trojanized,
    [switch]$BHO,
    [switch]$Winlogon,
    [switch]$AppInit, 
    [switch]$ASHKLM,
    [switch]$ASHKCU,
    [switch]$All
)

# Initialize a global results collector
$global:AllResults = @()

# ================================================================
# MODULE 1 - Run Key Scanner (HKLM / HKCU)
# ================================================================
function Get-AsepRunKeys {
    param ([string]$RootHive)
    Write-Host "`n========== [$RootHive Run Keys] ==========" -ForegroundColor Cyan
    $runKeyPaths = @()
    if ($RootHive -eq "HKLM") {
        $runKeyPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        )
    }
    elseif ($RootHive -eq "HKCU") {
        $runKeyPaths = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            "HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        )
    }

    $results = @()
    foreach ($keyPath in $runKeyPaths) {
        if (Test-Path $keyPath) {
            $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -notmatch '^PS') {
                    $cmd = $p.Value
                    $exePath = $null
                    if ($cmd -match '\"([^"]+\.exe)\"') { $exePath = $matches[1] }
                    elseif ($cmd -match '(^\S+\.exe)') { $exePath = $matches[1] }

                    $exists = $false; $lastWrite=$null; $creation=$null; $publisher=$null; $hash=$null
                    if ($exePath -and (Test-Path $exePath)) {
                        $exists=$true
                        $fi=Get-Item $exePath -ErrorAction SilentlyContinue
                        $lastWrite=$fi.LastWriteTime; $creation=$fi.CreationTime
                        $sig=Get-AuthenticodeSignature $exePath -ErrorAction SilentlyContinue
                        $publisher=if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{"Unsigned or Unknown"}
                        $hashObj=Get-FileHash $exePath -Algorithm SHA256 -ErrorAction SilentlyContinue
                        $hash=$hashObj.Hash
                    }

                    $results += [PSCustomObject]@{
                        Category="$RootHive Run Key"
                        RegistryPath=$keyPath
                        Name=$p.Name
                        Command=$cmd
                        FileExists=$exists
                        FileLastWriteTime=$lastWrite
                        FileCreationTime=$creation
                        FilePublisher=$publisher
                        SHA256Hash=$hash
                    }
                }
            }
        }
    }
    $results | Sort-Object RegistryPath,Name | Format-List
    $global:AllResults += $results

}

# ================================================================
# MODULE 2 - Startup Folder Scanner
# ================================================================
function Get-AsepStartupFolders {
    Write-Host "`n========== [Startup Folders] ==========" -ForegroundColor Cyan
    $folders=@(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    $results=@()
    foreach($f in $folders){
        if(Test-Path $f){
            $items=Get-ChildItem $f -File -ErrorAction SilentlyContinue
            foreach($it in $items){
                $target=$it.FullName
                if($it.Extension -eq ".lnk"){
                    $sh=New-Object -ComObject WScript.Shell
                    $sc=$sh.CreateShortcut($it.FullName)
                    $target=$sc.TargetPath
                }
                $exists=$false;$lw=$null;$cr=$null;$pub=$null;$hash=$null
                if($target -and (Test-Path $target)){
                    $exists=$true
                    $fi=Get-Item $target -ErrorAction SilentlyContinue
                    $lw=$fi.LastWriteTime;$cr=$fi.CreationTime
                    $sig=Get-AuthenticodeSignature $target -ErrorAction SilentlyContinue
                    $pub=if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{"Unsigned or Unknown"}
                    $hashObj=Get-FileHash $target -Algorithm SHA256 -ErrorAction SilentlyContinue
                    $hash=$hashObj.Hash
                }
                $results+=[PSCustomObject]@{
                    Category="Startup Folder"
                    StartupFolder=$f
                    Name=$it.Name
                    TargetPath=$target
                    FileExists=$exists
                    FileLastWriteTime=$lw
                    FileCreationTime=$cr
                    FilePublisher=$pub
                    SHA256Hash=$hash
                }
            }
        }
    }
    $results | Format-List
    $global:AllResults += $results

}

# ================================================================
# MODULE 3 - Scheduled Tasks
# ================================================================
function Get-AsepScheduledTasks {
    Write-Host "`n========== [Scheduled Tasks] ==========" -ForegroundColor Cyan
    function Resolve-ExePathFromString($s){
        if(-not $s){return $null}
        if($s -match '"([^"]+\.exe)"'){return $matches[1].Trim()}
        if($s -match '([A-Za-z]:\\[^"\s<>|]+?\.exe)'){return $matches[1].Trim()}
        if($s -match '(^\S+\.exe)'){return $matches[1].Trim()}
        return $null
    }
    $tasks=Get-ScheduledTask -ErrorAction SilentlyContinue
    $results=@()
    foreach($t in $tasks){
        $info=Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
        foreach($a in $t.Actions){
            $exe=Resolve-ExePathFromString $a.Execute
            if(-not $exe -and $a.Arguments){$exe=Resolve-ExePathFromString $a.Arguments}
            $exists=$false;$pub=$null;$hash=$null;$lw=$null;$cr=$null
            if($exe -and (Test-Path $exe)){
                $exists=$true
                $fi=Get-Item $exe -ErrorAction SilentlyContinue
                $lw=$fi.LastWriteTime;$cr=$fi.CreationTime
                $sig=Get-AuthenticodeSignature $exe -ErrorAction SilentlyContinue
                $pub=if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{"Unsigned or Unknown"}
                $hashObj=Get-FileHash $exe -Algorithm SHA256 -ErrorAction SilentlyContinue
                $hash=$hashObj.Hash
            }
            $results+=[PSCustomObject]@{
                Category="Scheduled Task"
                TaskName=$t.TaskName
                TaskPath=$t.TaskPath
                RawExecute=$a.Execute
                RawArguments=$a.Arguments
                ResolvedExe=$exe
                LastRunTime=$info.LastRunTime
                NextRunTime=$info.NextRunTime
                FileExists=$exists
                FileLastWrite=$lw
                FileCreation=$cr
                FilePublisher=$pub
                SHA256Hash=$hash
            }
        }
    }
    $results | Sort-Object TaskPath,TaskName | Format-List
    $global:AllResults += $results
}

# ================================================================
# MODULE 4 - Services
# ================================================================
function Get-AsepServices {
    Write-Host "`n========== [Services] ==========" -ForegroundColor Cyan
    $svcs=Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue
    $results=@()
    foreach($svc in $svcs){
        $exe=$null
        if($svc.PathName -match '\"([^"]+\.exe)\"'){$exe=$matches[1]}
        elseif($svc.PathName -match '(^\S+\.exe)'){$exe=$matches[1]}
        $exists=$false;$lw=$null;$cr=$null;$pub=$null;$hash=$null
        if($exe -and (Test-Path $exe)){
            $exists=$true
            $fi=Get-Item $exe -ErrorAction SilentlyContinue
            $lw=$fi.LastWriteTime;$cr=$fi.CreationTime
            $sig=Get-AuthenticodeSignature $exe -ErrorAction SilentlyContinue
            $pub=if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{"Unsigned or Unknown"}
            $hashObj=Get-FileHash $exe -Algorithm SHA256 -ErrorAction SilentlyContinue
            $hash=$hashObj.Hash
        }
        $results+=[PSCustomObject]@{
            Category="Service"
            Name=$svc.Name
            DisplayName=$svc.DisplayName
            StartMode=$svc.StartMode
            State=$svc.State
            PathName=$svc.PathName
            FileExists=$exists
            FileLastWriteTime=$lw
            FileCreationTime=$cr
            FilePublisher=$pub
            SHA256Hash=$hash
        }
    }
    $results | Sort-Object Name | Format-List
    $global:AllResults += $results
}

# ================================================================
# MODULE 5 - Shortcuts Manipulation
# ================================================================
function Get-AsepShortcutsManipulation {
    Write-Host "`n========== [Shortcuts Manipulation] ==========" -ForegroundColor Cyan
    $paths=@(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:Public\Desktop",
        "$env:USERPROFILE\Desktop"
    )
    $results=@()
    $shell=New-Object -ComObject WScript.Shell
    function Get-UrlShortcutTarget($file){
        try{
            foreach($l in (Get-Content $file -ErrorAction Stop)){
                if($l -match '^\s*URL\s*=\s*(.+)$'){return $matches[1].Trim()}
            }
        }catch{}
        return $null
    }
    foreach($base in $paths){
        if(-not (Test-Path $base)){continue}
        try{$items=Get-ChildItem $base -Include *.lnk,*.url -File -Recurse -ErrorAction Stop}
        catch{$items=Get-ChildItem $base -Include *.lnk,*.url -File -ErrorAction SilentlyContinue}
        foreach($it in $items){
            $target=$null;$args=$null;$wd=$null;$icon=$null;$isUrl=$false
            try{
                if($it.Extension -ieq ".lnk"){
                    $s=$shell.CreateShortcut($it.FullName)
                    $target=$s.TargetPath;$args=$s.Arguments;$wd=$s.WorkingDirectory;$icon=$s.IconLocation
                }elseif($it.Extension -ieq ".url"){
                    $isUrl=$true;$target=Get-UrlShortcutTarget $it.FullName
                }
            }catch{}
            $shLW=$it.LastWriteTime;$shCR=$it.CreationTime
            $tExists=$false;$tLW=$null;$tCR=$null;$tPub=$null;$tHash=$null
            if($target -and ($target -match '^[A-Za-z]:\\|^\\\\')){
                $norm=$target -replace '/','\'
                if($norm -match '^\s*"(.*)"\s*$'){$norm=$matches[1]}
                if($norm -match '^(.*?\.exe)\s+.*$'){$norm=$matches[1]}
                if(Test-Path $norm){
                    $tExists=$true
                    $fi=Get-Item $norm -ErrorAction SilentlyContinue
                    $tLW=$fi.LastWriteTime;$tCR=$fi.CreationTime
                    $sig=Get-AuthenticodeSignature $norm -ErrorAction SilentlyContinue
                    $tPub=if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{"Unsigned or Unknown"}
                    $hashObj=Get-FileHash $norm -Algorithm SHA256 -ErrorAction SilentlyContinue
                    $tHash=$hashObj.Hash
                }
            }
            $results+=[PSCustomObject]@{
                Category="Shortcut Manipulation"
                ScanBasePath=$base
                ShortcutFullPath=$it.FullName
                ShortcutName=$it.Name
                ShortcutExtension=$it.Extension
                ShortcutLastWrite=$shLW
                ShortcutCreation=$shCR
                IsUrlShortcut=$isUrl
                ResolvedTarget=$target
                Arguments=$args
                WorkingDirectory=$wd
                IconLocation=$icon
                TargetFileExists=$tExists
                TargetLastWriteTime=$tLW
                TargetCreationTime=$tCR
                TargetPublisher=$tPub
                TargetSHA256=$tHash
            }
        }
    }
    $results | Sort-Object ScanBasePath,ShortcutName | Format-List
    $global:AllResults += $results
}

# ================================================================
# MODULE 6 - Image File Execution Options
# ================================================================
function Get-IFEO {
Write-Host "`n========== [Image File Execution Options] ==========" -ForegroundColor Cyan
$ifeoPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
)

$results = @()

foreach ($basePath in $ifeoPaths) {
    if (-not (Test-Path $basePath)) {
        Write-Verbose "IFEO base key not found: $basePath"
        continue
    }

    $subKeys = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue

    foreach ($subKey in $subKeys) {
        $values = Get-ItemProperty -Path $subKey.PSPath -ErrorAction SilentlyContinue

        # Build a simple hashtable of values (exclude PS* props)
        $valueTable = @{}
        foreach ($p in $values.PSObject.Properties) {
            if ($p.Name -notmatch '^PS') { $valueTable[$p.Name] = $p.Value }
        }

        $debugger = $null
        if ($valueTable.ContainsKey('Debugger')) { $debugger = $valueTable['Debugger'] }

        # Prepare file-related vars (may remain $null)
        $debuggerExe = $null
        $fileExists = $false
        $fileLastWrite = $null
        $fileCreation = $null
        $publisher = $null
        $hash = $null

        if ($debugger) {
            if ($debugger -match '\"([^"]+\.exe)\"') {
                $debuggerExe = $matches[1]
            } elseif ($debugger -match '(^\S+\.exe)') {
                $debuggerExe = $matches[1]
            }

            if ($debuggerExe) {
                $debuggerExe = [Environment]::ExpandEnvironmentVariables($debuggerExe)
                if (Test-Path $debuggerExe) {
                    $fileExists = $true
                    $fileItem = Get-Item -Path $debuggerExe -ErrorAction SilentlyContinue
                    if ($fileItem) {
                        $fileLastWrite = $fileItem.LastWriteTime
                        $fileCreation = $fileItem.CreationTime
                    }
                    $sig = Get-AuthenticodeSignature -FilePath $debuggerExe -ErrorAction SilentlyContinue
                    if ($sig -and $sig.SignerCertificate) { $publisher = $sig.SignerCertificate.Subject } else { $publisher = "Unsigned or Unknown" }
                    $hashObj = Get-FileHash -Path $debuggerExe -Algorithm SHA256 -ErrorAction SilentlyContinue
                    if ($hashObj) { $hash = $hashObj.Hash }
                }
            }
        }

        # Build output object dynamically: include only relevant fields
        $props = [ordered]@{
            Category="Image File Execution Options"
            IFEO_BasePath    = $basePath
            SubKey           = $subKey.PSChildName
            RegistryFullPath = $subKey.PSPath
        }

        if ($debugger) { $props['DebuggerValue'] = $debugger }

        # Only include OtherValues if there are other keys
        $otherKeys = $valueTable.Keys | Where-Object { $_ -ne 'Debugger' }
        if ($otherKeys.Count -gt 0) {
            $props['OtherValues'] = ($otherKeys | ForEach-Object { "$_=`"$($valueTable[$_])`"" }) -join '; '
        }

        # Only include file-related info when we actually resolved a debugger exe
        if ($debuggerExe) { $props['DebuggerExePath'] = $debuggerExe }
        if ($debuggerExe) { $props['FileExists'] = $fileExists }
        if ($fileLastWrite) { $props['FileLastWriteTime'] = $fileLastWrite }
        if ($fileCreation) { $props['FileCreationTime'] = $fileCreation }
        if ($publisher) { $props['FilePublisher'] = $publisher }
        if ($hash) { $props['SHA256Hash'] = $hash }

        $entry = New-Object PSObject -Property $props
        $results += $entry
    }
}

if ($results.Count -eq 0) {
    Write-Output "No IFEO entries found under the scanned paths."
} else {
    # Print each result fully (no truncation)
    $results | Sort-Object IFEO_BasePath, SubKey | Format-List
    $global:AllResults += $results
}
}

# ================================================================
# MODULE 7 - Extension Hijacking (HKLM)
# ================================================================
function Get-hijackingHKLM {
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
        Category="Extension Hijacking (HKLM)"
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
    $global:AllResults += $results
}
}

# ================================================================
# MODULE 8 - Extension Hijacking (HKCU)
# ================================================================
function Get-hijackingHKCU {
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
            Category="Extension Hijacking (HKCU)"
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
    $global:AllResults += $results
}
}

# ================================================================
# MODULE 9 - Trojanized System Binaries
# ================================================================
function Get-trojanized {
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
                Category="Trojanized System Binaries"
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
    $global:AllResults += $results
    # Optional export:
    # $results | Export-Csv -Path ".\Trojanized_System_Binaries_Found.csv" -NoTypeInformation
}

if ($systemChecks.Count -gt 0) {
    Write-Output "`n== System file signature anomalies (unsigned/not-Microsoft) =="
    $systemChecks | Sort-Object SystemFile | Format-List
}
}

# ================================================================
# MODULE 10 - Browser Helper Objects
# ================================================================
function Get-BHO {
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
            Category="Browser Helper Objects"
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
    $global:AllResults += $results
}
}

# ================================================================
# MODULE 11 - Winlogon
# ================================================================
function Get-Winlogon {
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
            Category="Winlogon"
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
    $global:AllResults += $results
}
}

# ================================================================
# MODULE 12 - AppInit DLLs
# ================================================================
function Get-AppInit {
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
        Category="AppInit DLLs"
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
    $global:AllResults += $results
}
}

# ================================================================
# MODULE 13 - Active Setup (HKLM)
# ================================================================
function Get-ASHKLM {
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
            Category="Active Setup (HKLM)"
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
    $global:AllResults += $results
}
}

# ================================================================
# MODULE 14 - Active Setup (HKCU)
# ================================================================
function Get-ASHKCU {
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
            Category="Active Setup (HKCU)"
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
    $global:AllResults += $results
}
}

# ================================================================
# EXECUTION CONTROL
# ================================================================
if (-not ($HKLM -or $HKCU -or $Startup -or $Tasks -or $Services -or $Shortcuts -or $All)) {
    Write-Host "`nSelect which ASEP modules to run:" -ForegroundColor Yellow
    Write-Host "1. HKLM Run Keys"
    Write-Host "2. HKCU Run Keys"
    Write-Host "3. Startup Folders"
    Write-Host "4. Scheduled Tasks"
    Write-Host "5. Services"
    Write-Host "6. Shortcuts Manipulation"
    Write-Host "7. Image File Execution Options"
    Write-Host "8. Extension Hijacking (HKLM)"
    Write-Host "9. Extension Hijacking (HKCU)"
    Write-Host "10. Trojanized System Binaries"
    Write-Host "11. Browser Helper Objects"
    Write-Host "12. Winlogon"
    Write-Host "13. AppInit DLLs"
    Write-Host "14. Active Setup (HKLM)"
    Write-Host "15. Active Setup (HKCU)"
    Write-Host "16. All" -ForegroundColor Cyan
    $choice = Read-Host "Enter your choice (1–16)"
    switch ($choice) {
        "1" { Get-AsepRunKeys -RootHive "HKLM" }
        "2" { Get-AsepRunKeys -RootHive "HKCU" }
        "3" { Get-AsepStartupFolders }
        "4" { Get-AsepScheduledTasks }
        "5" { Get-AsepServices }
        "6" { Get-AsepShortcutsManipulation }
        "7" { Get-IFEO }
        "8" { Get-hijackingHKLM }
        "9" { Get-hijackingHKCU }
        "10" { Get-trojanized }
        "11" { Get-BHO }
        "12" { Get-Winlogon }
        "13" { Get-AppInit }
        "14" { Get-ASHKLM }
        "15" { Get-ASHKCU }
        "16" { Get-AsepRunKeys -RootHive "HKLM"; Get-AsepRunKeys -RootHive "HKCU"; Get-AsepStartupFolders; Get-AsepScheduledTasks; Get-AsepServices; Get-AsepShortcutsManipulation; Get-IFEO; Get-hijackingHKLM; Get-hijackingHKCU; Get-trojanized; Get-BHO; Get-Winlogon; Get-AppInit; Get-ASHKLM; Get-ASHKCU }
        default { Write-Host "Invalid selection." -ForegroundColor Red }
    }
}
elseif ($All) {
    Get-AsepRunKeys -RootHive "HKLM"
    Get-AsepRunKeys -RootHive "HKCU"
    Get-AsepStartupFolders
    Get-AsepScheduledTasks
    Get-AsepServices
    Get-AsepShortcutsManipulation
    Get-IFEO
    Get-hijackingHKLM
    Get-hijackingHKCU
    Get-trojanized
    Get-BHO
    Get-Winlogon
    Get-AppInit
    Get-ASHKLM
    Get-ASHKCU
}
else {
    if ($HKLM) { Get-AsepRunKeys -RootHive "HKLM" }
    if ($HKCU) { Get-AsepRunKeys -RootHive "HKCU" }
    if ($Startup) { Get-AsepStartupFolders }
    if ($Tasks) { Get-AsepScheduledTasks }
    if ($Services) { Get-AsepServices }
    if ($Shortcuts) { Get-AsepShortcutsManipulation } 
    if ($IFEO) { Get-IFEO }
    if ($HijackingHKLM) { Get-hijackingHKLM }
    if ($HijackingHKCU) { Get-hijackingHKCU }
    if ($Trojanized) { Get-trojanized }
    if ($BHO) { Get-BHO }
    if ($Winlogon) { Get-Winlogon }
    if ($AppInit) { Get-AppInit } 
    if ($AppInit) { Get-ASHKLM }
    if ($AppInit) { Get-ASHKCU }
}

# ================================================================
# SAVE RESULTS
# ================================================================
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outFile = "$PSScriptRoot\ASEP_Results_$timestamp.txt"
$AllResults | Format-List | Out-File -FilePath $outFile -Encoding UTF8

Write-Host "`n📁 Results saved to: $outFile" -ForegroundColor Yellow


Write-Host "`n✅ ASEP Check completed." -ForegroundColor Green
