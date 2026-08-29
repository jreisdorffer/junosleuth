<#
.SYNOPSIS
  Junosleuth - Incident Response & Forensic Acquisition for Junos.

.DESCRIPTION
  Platform-aware Junos incident-response collector supporting both:
    1) SSH sessions that land directly in the Junos CLI, and
    2) SSH sessions that land in the underlying OS shell.

  Raw SSH stdout is preserved under raw\. A repeated login notice is learned
  from two harmless probes, saved once in meta\login_notice.txt, and removed
  only from analyst-facing cli\ and shell\ outputs.

  Project:    Junosleuth
  Repository: https://github.com/jreisdorffer/junosleuth
  License:    Beer-Ware License (Revision 42, adapted); see LICENSE

.LEGAL
  Junosleuth is an independent open-source project and is not affiliated with,
  endorsed by, sponsored by, or otherwise associated with Juniper Networks,
  Inc. "Juniper Networks", "Juniper", "Junos", and related names and marks are
  trademarks and/or registered trademarks of Juniper Networks, Inc. and/or its
  affiliates. All such trademarks remain the property of their respective owners.

  Intended only for authorized incident response, forensic investigation,
  laboratory testing, and defensive security research.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$HostName,
    [Parameter(Mandatory=$true)][string]$UserName,
    [int]$Port = 22,
    [string]$OutputBase = ".\junosleuth-evidence",
    [switch]$RunJMRT,
    [switch]$RunShell,
    [switch]$AcquireFiles,
    [string]$AcquireMemory = "",
    [ValidateRange(1,1024)][int]$MemoryRateMBps = 5
)

$ErrorActionPreference = "Continue"
$script:RemoteMode = "unknown"
$script:PlatformFamily = "unknown"
$script:SshRetryCount = 3
$script:SshRetryDelaySeconds = 1
if ($AcquireMemory -and $AcquireMemory -notmatch '^\d+(,\d+)*$') { throw "-AcquireMemory expects comma-separated numeric PIDs" }

$script:SshExe = (Get-Command ssh.exe -ErrorAction SilentlyContinue).Source
if (-not $script:SshExe) { throw "ssh.exe not found. Install the Windows OpenSSH Client." }

$ts = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$safeHost = $HostName -replace '[^A-Za-z0-9._-]','_'
$script:OutDir = Join-Path $OutputBase "${safeHost}_$ts"
$script:CliDir = Join-Path $script:OutDir "cli"
$script:ShellDir = Join-Path $script:OutDir "shell"
$script:RawCliDir = Join-Path $script:OutDir "raw\cli"
$script:RawShellDir = Join-Path $script:OutDir "raw\shell"
$script:FilesDir = Join-Path $script:OutDir "files"
$script:MemoryDir = Join-Path $script:OutDir "memory"
$script:MetaDir = Join-Path $script:OutDir "meta"
New-Item -ItemType Directory -Force -Path $script:CliDir,$script:ShellDir,$script:RawCliDir,$script:RawShellDir,$script:FilesDir,$script:MemoryDir,$script:MetaDir | Out-Null
$script:CollectorLog = Join-Path $script:MetaDir "collector.log"
$script:LoginNotice = Join-Path $script:MetaDir "login_notice.txt"

function Write-Log {
    param([string]$Message)
    $line = "[{0}] {1}" -f ((Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")), $Message
    Write-Host $line
    Add-Content -Path $script:CollectorLog -Value $line
}

function Get-SafeName {
    param([string]$Text)
    $name = ($Text.ToLowerInvariant() -replace '[^a-z0-9]+','_').Trim('_')
    if ($name.Length -gt 100) { $name = $name.Substring(0,100) }
    $name
}

function Invoke-SshRaw {
    param([Parameter(Mandatory=$true)][string]$RemoteCommand,[int]$Retries=$script:SshRetryCount)

    for ($attempt=1; $attempt -le $Retries; $attempt++) {
        $outFile = [IO.Path]::GetTempFileName()
        $errFile = [IO.Path]::GetTempFileName()

        & $script:SshExe -T -p $Port `
            -o BatchMode=yes `
            -o ConnectTimeout=10 `
            -o ServerAliveInterval=15 `
            -o ServerAliveCountMax=3 `
            -o StrictHostKeyChecking=ask `
            "$UserName@$HostName" $RemoteCommand 1> $outFile 2> $errFile

        $rc = $LASTEXITCODE
        $stdout = if (Test-Path $outFile) { [IO.File]::ReadAllText($outFile) } else { "" }
        $stderr = if (Test-Path $errFile) { [IO.File]::ReadAllText($errFile) } else { "" }
        Remove-Item $outFile,$errFile -Force -ErrorAction SilentlyContinue

        if ($rc -ne 255 -or $attempt -eq $Retries) {
            return [pscustomobject]@{ ExitCode=$rc; Stdout=$stdout; Stderr=$stderr; Attempts=$attempt }
        }
        Start-Sleep -Seconds ($script:SshRetryDelaySeconds * $attempt)
    }
}

function Get-RemoteCliCommand {
    param([string]$Command)
    if ($script:RemoteMode -eq "cli") { return $Command }
    $escaped = $Command.Replace("'","'\''")
    "cli -c '$escaped'"
}

function Get-RemoteShellCommand {
    param([string]$Command)
    if ($script:RemoteMode -eq "cli") {
        $escaped = $Command.Replace('"','\"')
        return "start shell command `"$escaped`""
    }
    $Command
}

function Get-SemanticStatus {
    param([int]$ExitCode,[string]$Output)
    if ($ExitCode -eq 255) { return "transport_error" }
    if ($ExitCode -ne 0) { return "remote_error" }
    if ($Output -match '(?im)^\s*(error:|syntax error|unknown command:|invalid command|permission denied|command not found)') {
        return "command_error"
    }
    "ok"
}

function Detect-RemoteMode {
    $direct = Invoke-SshRaw "show system uptime" 2
    [IO.File]::WriteAllText((Join-Path $script:MetaDir "probe_direct.raw"),$direct.Stdout)
    [IO.File]::WriteAllText((Join-Path $script:MetaDir "probe_direct.stderr"),$direct.Stderr)
    if ($direct.ExitCode -eq 0 -and $direct.Stdout -match '(?im)Current time|System booted|Protocols started|uptime' -and
        $direct.Stdout -notmatch '(?im)unknown command|command not found|syntax error') {
        $script:RemoteMode = "cli"; return
    }

    $shell = Invoke-SshRaw "cli -c 'show system uptime'" 2
    [IO.File]::WriteAllText((Join-Path $script:MetaDir "probe_shell.raw"),$shell.Stdout)
    [IO.File]::WriteAllText((Join-Path $script:MetaDir "probe_shell.stderr"),$shell.Stderr)
    if ($shell.ExitCode -eq 0 -and $shell.Stdout -match '(?im)Current time|System booted|Protocols started|uptime' -and
        $shell.Stdout -notmatch '(?im)unknown command|command not found|syntax error') {
        $script:RemoteMode = "shell"; return
    }

    throw "Could not determine SSH landing mode. Review meta\probe_*.raw/stderr."
}

function Get-CommonLinePrefix {
    param([string]$A,[string]$B)
    $aLines = [regex]::Split($A,"(?<=`n)")
    $bLines = [regex]::Split($B,"(?<=`n)")
    $count = [Math]::Min($aLines.Count,$bLines.Count)
    $sb = [Text.StringBuilder]::new()
    for ($i=0; $i -lt $count; $i++) {
        if ($aLines[$i] -cne $bLines[$i]) { break }
        [void]$sb.Append($aLines[$i])
    }
    $sb.ToString()
}

function Learn-LoginNotice {
    $a = Invoke-SshRaw (Get-RemoteCliCommand "show system uptime") 2
    $b = Invoke-SshRaw (Get-RemoteCliCommand "show version") 2
    $notice = Get-CommonLinePrefix $a.Stdout $b.Stdout
    [IO.File]::WriteAllText($script:LoginNotice,$notice)
    if ($notice.Length -gt 0) { Write-Log "Learned repeated login notice; saved in meta\login_notice.txt" }
    else { Write-Log "No stable repeated login notice detected" }
}

function Remove-LoginNotice {
    param([string]$Raw)
    if (-not (Test-Path $script:LoginNotice)) { return $Raw }
    $notice = [IO.File]::ReadAllText($script:LoginNotice)
    if ($notice.Length -gt 0 -and $Raw.StartsWith($notice,[StringComparison]::Ordinal)) {
        return $Raw.Substring($notice.Length)
    }
    $Raw
}

function Invoke-JuniperCli {
    param([Parameter(Mandatory=$true)][string]$Command,[string]$Name)
    if (-not $Name) { $Name = Get-SafeName $Command }

    $rawFile = Join-Path $script:RawCliDir ($Name + ".raw.txt")
    $file = Join-Path $script:CliDir ($Name + ".txt")
    Write-Log "CLI: $Command"

    $r = Invoke-SshRaw (Get-RemoteCliCommand $Command)
    [IO.File]::WriteAllText($rawFile,$r.Stdout)
    $clean = Remove-LoginNotice $r.Stdout
    $semantic = Get-SemanticStatus $r.ExitCode $clean

    [IO.File]::WriteAllText($file,$clean)
    Add-Content $file "`n# collected_utc=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    Add-Content $file "# command=$Command"
    Add-Content $file "# remote_mode=$script:RemoteMode"
    Add-Content $file "# raw_output=raw/cli/$Name.raw.txt"
    Add-Content $file "# exit_status=$($r.ExitCode)"
    Add-Content $file "# semantic_status=$semantic"
    Add-Content $file "# ssh_attempts=$($r.Attempts)"

    if ($r.Stderr) {
        Add-Content (Join-Path $script:MetaDir "ssh_stderr.log") "`n### $Command`n$($r.Stderr)"
    }
    Start-Sleep -Milliseconds 250
}

function Invoke-JuniperShell {
    param([Parameter(Mandatory=$true)][string]$Command,[string]$Name)
    if (-not $Name) { $Name = Get-SafeName $Command }

    $rawFile = Join-Path $script:RawShellDir ($Name + ".raw.txt")
    $file = Join-Path $script:ShellDir ($Name + ".txt")
    Write-Log "SHELL: $Command"

    $r = Invoke-SshRaw (Get-RemoteShellCommand $Command)
    [IO.File]::WriteAllText($rawFile,$r.Stdout)
    $clean = Remove-LoginNotice $r.Stdout
    $semantic = Get-SemanticStatus $r.ExitCode $clean

    [IO.File]::WriteAllText($file,$clean)
    Add-Content $file "`n# collected_utc=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    Add-Content $file "# shell_command=$Command"
    Add-Content $file "# remote_mode=$script:RemoteMode"
    Add-Content $file "# raw_output=raw/shell/$Name.raw.txt"
    Add-Content $file "# exit_status=$($r.ExitCode)"
    Add-Content $file "# semantic_status=$semantic"
    Add-Content $file "# ssh_attempts=$($r.Attempts)"

    if ($r.Stderr) {
        Add-Content (Join-Path $script:MetaDir "ssh_stderr.log") "`n### SHELL: $Command`n$($r.Stderr)"
    }
    Start-Sleep -Milliseconds 250
}

@(
    "project=Junosleuth"
    "repository=https://github.com/jreisdorffer/junosleuth"
    "collector_host=$env:COMPUTERNAME"
    "collector_user=$env:USERNAME"
    "target=$HostName"
    "ssh_user=$UserName"
    "ssh_port=$Port"
    "utc_started=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    "jmrt_enabled=$($RunJMRT.IsPresent)"
    "shell_enabled=$([bool]($RunShell -or $AcquireMemory))"
    "file_acquisition_enabled=$($AcquireFiles.IsPresent)"
    "memory_acquisition_pids=$AcquireMemory"
    "memory_rate_mbps=$MemoryRateMBps"
    "memory_acquisition_experimental=$([bool]$AcquireMemory)"
    "recommended_file_paths=/var/log,/var/tmp,/tmp,/var/crash,/var/core,/var/core/re,/var/core/re0,/var/core/re1,/config,/root,/home,/mfs/var/etc,/var/db/config,/var/rundb+"
    "recommended_priority_files=/var/log/messages,/var/log/interactive-commands,/var/log/authorization,/mfs/var/etc/syslog.conf,/mfs/var/etc/syslog.conf0,/var/rundb+,/config/usage_db,/var/db/config/usage_db,/usr/lib/libjucomm.so.1"
) | Set-Content (Join-Path $script:MetaDir "manifest.txt")

Write-Log "Starting Junosleuth collection"
Detect-RemoteMode
Add-Content (Join-Path $script:MetaDir "manifest.txt") "remote_mode=$script:RemoteMode"
Write-Log "Detected SSH login mode: $script:RemoteMode"
Learn-LoginNotice

Invoke-JuniperCli "show version detail" "00_platform_version"
$v = Get-Content (Join-Path $script:CliDir "00_platform_version.txt") -Raw
if ($v -match '(?i)Junos OS Evolved|JUNOS-EVO') { $script:PlatformFamily="evolved" }
elseif ($v -match '(?i)Junos|JUNOS') { $script:PlatformFamily="traditional" }
else { $script:PlatformFamily="unknown" }
Add-Content (Join-Path $script:MetaDir "manifest.txt") "platform_family=$script:PlatformFamily"

$cliCommands = @(
    @("show chassis hardware detail","01_show_chassis_hardware_detail"),
    @("show system uptime","02_show_system_uptime"),
    @("show system users","03_show_system_users"),
    @("show system alarms","04_show_system_alarms"),
    @("show chassis alarms","05_show_chassis_alarms"),
    @("show system storage","06_show_system_storage"),
    @("show system core-dumps","07_show_system_core_dumps"),
    @("show chassis routing-engine","08_show_chassis_routing_engine"),
    @("show system memory","09_show_system_memory"),
    @("show system processes extensive","10_show_system_processes_extensive"),
    @("show system connections","11_show_system_connections"),
    @("show system statistics","13_show_system_statistics"),
    @("show task memory","14_show_task_memory"),
    @("show interfaces terse","20_show_interfaces_terse"),
    @("show interfaces extensive","21_show_interfaces_extensive"),
    @("show route summary","22_show_route_summary"),
    @("show route forwarding-table summary","23_show_forwarding_table_summary"),
    @("show arp no-resolve","24_show_arp_no_resolve"),
    @("show bgp summary","25_show_bgp_summary"),
    @("show system commit","30_show_system_commit"),
    @("show configuration | display set | no-more","31_configuration_display_set"),
    @("show log messages | no-more","40_log_messages"),
    @("show log interactive-commands | no-more","41_log_interactive_commands"),
    @("show log authorization | no-more","42_log_authorization"),
    @("file list /var/log detail","43_file_list_var_log"),
    @("file list /var/tmp detail","44_file_list_var_tmp"),
    @("file list /tmp detail","45_file_list_tmp")
)
foreach ($c in $cliCommands) { Invoke-JuniperCli $c[0] $c[1] }

if ($script:PlatformFamily -eq "traditional") {
    Invoke-JuniperCli "show system connections extensive" "12_show_system_connections_extensive"
}

if ($RunJMRT) {
    Invoke-JuniperCli "request system malware-scan quick-scan clean-action warn" "50_jmrt_quick_scan_warn"
    Invoke-JuniperCli "request system malware-scan integrity-check" "51_jmrt_integrity_check"
}

if ($RunShell -or $AcquireMemory) {
    Invoke-JuniperShell "uname -a" "60_uname"
    Invoke-JuniperShell "date -u" "61_date_utc"
    Invoke-JuniperShell "uptime" "62_uptime"
    Invoke-JuniperShell "ps auxww" "63_ps_auxww"
    if ($script:PlatformFamily -eq "evolved") {
        Invoke-JuniperShell "ss -anp" "64_ss_anp"
        Invoke-JuniperShell "ip addr show" "65_ip_addr"
    } else {
        Invoke-JuniperShell "netstat -an" "64_netstat_an"
        Invoke-JuniperShell "sockstat -4 -6" "65_sockstat"
    }
    Invoke-JuniperShell "mount" "66_mount"
    Invoke-JuniperShell "df -h" "67_df_h"
    Invoke-JuniperShell "ls -laT /var/tmp /tmp /var/log 2>&1" "68_writable_dirs_listing"
    Invoke-JuniperShell "find /var/tmp /tmp -type f -ls 2>&1" "69_writable_files_find"
    Invoke-JuniperShell "who -a 2>&1 || w 2>&1" "70_logged_in_users"
    Invoke-JuniperShell "ps -ax -o pid,ppid,uid,lstart,args 2>&1 || ps auxww 2>&1" "71_process_provenance"
    Invoke-JuniperShell "find /proc -maxdepth 2 \( -name status -o -name cmdline -o -name maps -o -name map \) -type f -print 2>/dev/null" "72_proc_metadata_index"
    Invoke-JuniperShell 'for p in /proc/[0-9]*; do [ -d "$p" ] || continue; echo "===== $p ====="; for x in status cmdline maps map; do [ -r "$p/$x" ] && { echo "--- $x ---"; cat "$p/$x"; echo; }; done; for x in exe file cwd; do [ -e "$p/$x" ] && { echo "--- $x ---"; ls -ld "$p/$x" 2>&1; }; done; done 2>&1' "73_proc_metadata"
}

if ($AcquireFiles) {
    Write-Log "File acquisition enabled"
    $acqManifest = Join-Path $script:MetaDir "acquired_files_manifest.txt"
    $candidates = Join-Path $script:MetaDir "remote_file_candidates.txt"

    function Get-RemoteFileSize([string]$Path) {
        $cmd = if ($script:PlatformFamily -eq "evolved") { "stat -c %s '$Path'" } else { "stat -f %z '$Path'" }
        $r = Invoke-SshRaw (Get-RemoteShellCommand $cmd)
        [long]$n=0
        if ($r.ExitCode -eq 0 -and [long]::TryParse($r.Stdout.Trim(),[ref]$n)) { return $n }
        return $null
    }

    function Get-RemoteSha256([string]$Path) {
        foreach ($cmd in @("sha256 -q '$Path'","sha256sum '$Path'","openssl dgst -sha256 '$Path'")) {
            $r = Invoke-SshRaw (Get-RemoteShellCommand $cmd)
            if ($r.ExitCode -eq 0 -and $r.Stdout.Trim()) {
                $parts = $r.Stdout.Trim() -split '\s+'
                if ($cmd.StartsWith("sha256sum")) { return $parts[0].ToLowerInvariant() }
                return $parts[-1].ToLowerInvariant()
            }
        }
        ""
    }

    function Acquire-RemoteFile([string]$RemotePath) {
        $relative = $RemotePath.TrimStart('/') -replace '/','\'
        $dest = Join-Path $script:FilesDir $relative
        New-Item -ItemType Directory -Force -Path (Split-Path $dest -Parent) | Out-Null
        $rh = Get-RemoteSha256 $RemotePath
        $rs = Get-RemoteFileSize $RemotePath

        & scp.exe -q -P $Port -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=ask `
            "$UserName@$HostName`:$RemotePath" $dest 2>> (Join-Path $script:MetaDir "file_acquisition.log")
        if ($LASTEXITCODE -eq 0 -and (Test-Path $dest)) {
            $lh = (Get-FileHash -Algorithm SHA256 $dest).Hash.ToLowerInvariant()
            $ls = (Get-Item $dest).Length
            $match = if ($rh) { if ($rh -eq $lh) {"true"} else {"false"} } else {"unknown"}
            @("remote_path=$RemotePath","local_path=files\$relative","status=acquired",
              "remote_size=$rs","local_size=$ls","remote_sha256=$rh","local_sha256=$lh",
              "hash_match=$match","") | Add-Content $acqManifest
        } else {
            @("remote_path=$RemotePath","status=failed","remote_size=$rs","remote_sha256=$rh","") |
                Add-Content $acqManifest
        }
    }

    $metaCmd = if ($script:PlatformFamily -eq "evolved") {
        "find /var/log /var/tmp /tmp /var/crash /var/core /var/core/re /var/core/re0 /var/core/re1 /config /root /home /mfs/var/etc /var/db/config /var/rundb+ -type f -exec stat -c 'path=%n|type=%F|size=%s|owner=%U|group=%G|mode=%a|inode=%i|mtime=%y|ctime=%z|atime=%x' {} \; 2>/dev/null; [ -f /usr/lib/libjucomm.so.1 ] && stat -c 'path=%n|type=%F|size=%s|owner=%U|group=%G|mode=%a|inode=%i|mtime=%y|ctime=%z|atime=%x' /usr/lib/libjucomm.so.1"
    } else {
        "find /var/log /var/tmp /tmp /var/crash /var/core /var/core/re /var/core/re0 /var/core/re1 /config /root /home /mfs/var/etc /var/db/config /var/rundb+ -type f -exec stat -f 'path=%N|type=%HT|size=%z|owner=%Su|group=%Sg|mode=%Lp|inode=%i|mtime=%Sm|ctime=%Sc|atime=%Sa' -t '%Y-%m-%dT%H:%M:%SZ' {} \; 2>/dev/null; [ -f /usr/lib/libjucomm.so.1 ] && stat -f 'path=%N|type=%HT|size=%z|owner=%Su|group=%Sg|mode=%Lp|inode=%i|mtime=%Sm|ctime=%Sc|atime=%Sa' -t '%Y-%m-%dT%H:%M:%SZ' /usr/lib/libjucomm.so.1"
    }
    $metaResult = Invoke-SshRaw (Get-RemoteShellCommand $metaCmd)
    [IO.File]::WriteAllText((Join-Path $script:MetaDir "remote_file_metadata.txt"),$metaResult.Stdout)
    [IO.File]::WriteAllText((Join-Path $script:MetaDir "remote_file_metadata.stderr"),$metaResult.Stderr)

    $find = Invoke-SshRaw (Get-RemoteShellCommand "find /var/log /var/tmp /tmp /var/crash /var/core /var/core/re /var/core/re0 /var/core/re1 /config /root /home /mfs/var/etc /var/db/config /var/rundb+ -type f 2>/dev/null; [ -f /usr/lib/libjucomm.so.1 ] && echo /usr/lib/libjucomm.so.1")
    [IO.File]::WriteAllText($candidates,$find.Stdout)

    foreach ($f in @("/var/log/messages","/var/log/interactive-commands","/var/log/authorization","/mfs/var/etc/syslog.conf","/mfs/var/etc/syslog.conf0","/var/rundb+","/config/usage_db","/var/db/config/usage_db","/usr/lib/libjucomm.so.1")) {
        Acquire-RemoteFile $f
    }
    foreach ($f in (Get-Content $candidates -ErrorAction SilentlyContinue | Sort-Object -Unique)) {
        if (-not $f) { continue }
        if ($f.StartsWith("/var/log/")) { Acquire-RemoteFile $f; continue }
        if ($f -match '^/(var/tmp|tmp|var/crash|config|root|home|mfs/var/etc|var/db/config|var/rundb\+)/') {
            $size = Get-RemoteFileSize $f
            if ($null -ne $size -and $size -le 104857600) { Acquire-RemoteFile $f }
        }
    }
}


# Existing core dumps: discover and acquire as historical process-memory evidence.
if ($AcquireFiles) {
    Write-Log "Acquiring existing core dumps (best effort)"
    $coreResult = Invoke-SshRaw (Get-RemoteShellCommand "find /var/core /var/crash -type f -print 2>/dev/null; find /var/tmp -type f \( -name '*.core' -o -name '*.core.*' -o -name 'core.*' -o -name '*core*.tgz' \) -print 2>/dev/null")
    [IO.File]::WriteAllText((Join-Path $script:MetaDir "existing_core_candidates.txt"),$coreResult.Stdout)
    [IO.File]::WriteAllText((Join-Path $script:MetaDir "existing_core_candidates.stderr"),$coreResult.Stderr)
    foreach ($f in ($coreResult.Stdout -split "`r?`n" | Where-Object { $_ } | Sort-Object -Unique)) {
        Acquire-RemoteFile $f
    }
}

# Binary-safe, throttled SSH receive used only for EXPERIMENTAL live memory.
function Receive-SshBinary {
    param([string]$RemoteCommand,[string]$Destination,[string]$StderrPath,[int]$RateMBps)
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $script:SshExe
    $target = "$UserName@$HostName"
    # Remote memory commands deliberately contain no embedded double quotes when
    # the account lands in a shell. Direct-CLI mode is wrapped by start shell command.
    $rcmd = Get-RemoteShellCommand $RemoteCommand
    $escaped = $rcmd.Replace('"','\"')
    $psi.Arguments = "-T -p $Port -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=ask `"$target`" `"$escaped`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [Diagnostics.Process]::new(); $p.StartInfo=$psi
    [void]$p.Start()
    $notice = if (Test-Path $script:LoginNotice) { [IO.File]::ReadAllBytes($script:LoginNotice) } else { [byte[]]@() }
    $fs = [IO.File]::Open($Destination,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $stream=$p.StandardOutput.BaseStream
        $buffer=New-Object byte[] 65536
        $prefix=[System.Collections.Generic.List[byte]]::new()
        if ($notice.Length -gt 0) {
            while ($prefix.Count -lt $notice.Length) {
                $need=[Math]::Min($buffer.Length,$notice.Length-$prefix.Count)
                $n=$stream.Read($buffer,0,$need); if ($n -le 0) { break }
                for($i=0;$i -lt $n;$i++){ $prefix.Add($buffer[$i]) }
            }
            $same=($prefix.Count -eq $notice.Length)
            if($same){ for($i=0;$i -lt $notice.Length;$i++){ if($prefix[$i] -ne $notice[$i]){$same=$false;break} } }
            if(-not $same -and $prefix.Count -gt 0){ $fs.Write($prefix.ToArray(),0,$prefix.Count) }
        }
        $written=$fs.Length; $sw=[Diagnostics.Stopwatch]::StartNew(); $rate=[double]$RateMBps*1MB
        while(($n=$stream.Read($buffer,0,$buffer.Length)) -gt 0){
            $fs.Write($buffer,0,$n); $written += $n
            $expected=$written/$rate; $delay=$expected-$sw.Elapsed.TotalSeconds
            if($delay -gt 0){ Start-Sleep -Milliseconds ([Math]::Min(250,[int]($delay*1000))) }
        }
    } finally { $fs.Dispose() }
    $stderr=$p.StandardError.ReadToEnd(); $p.WaitForExit(); [IO.File]::WriteAllText($StderrPath,$stderr)
    return $p.ExitCode
}

if ($AcquireMemory) {
    Write-Log "EXPERIMENTAL live-memory acquisition requested for PID(s): $AcquireMemory"
    Invoke-JuniperCli "show chassis routing-engine" "80_memory_pre_routing_engine"
    Invoke-JuniperCli "show system processes extensive" "81_memory_pre_processes"
    Invoke-JuniperCli "show system storage" "82_memory_pre_storage"
    Invoke-JuniperCli "show system memory" "83_memory_pre_system_memory"

    foreach($pidText in ($AcquireMemory -split ',')) {
        $pid=[int64]$pidText; $pdir=Join-Path $script:MemoryDir $pidText; $rdir=Join-Path $pdir 'regions'
        New-Item -ItemType Directory -Force -Path $rdir | Out-Null
        $mapResult=Invoke-SshRaw (Get-RemoteShellCommand "cat /proc/$pid/maps 2>/dev/null || cat /proc/$pid/map 2>/dev/null")
        $mapBefore=Join-Path $pdir 'map_before.txt'; [IO.File]::WriteAllText($mapBefore,$mapResult.Stdout); [IO.File]::WriteAllText((Join-Path $pdir 'map.stderr'),$mapResult.Stderr)
        $manifest=Join-Path $pdir 'manifest.txt'
        if(-not $mapResult.Stdout.Trim()) { @("pid=$pid","status=no_readable_map") | Set-Content $manifest; Write-Log "PID $pid: no readable /proc memory map"; continue }
        $ident=Invoke-SshRaw (Get-RemoteShellCommand "ps -p $pid -o pid,ppid,uid,lstart,args 2>&1 || ps auxww 2>&1")
        [IO.File]::WriteAllText((Join-Path $pdir 'process_identity.txt'),$ident.Stdout)
        @("pid=$pid","started_utc=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))","rate_limit_mbps=$MemoryRateMBps","status=in_progress") | Set-Content $manifest

        $regions=@()
        foreach($line in ($mapResult.Stdout -split "`r?`n")) {
            $line=$line.Trim(); if(-not $line){continue}; $f=$line -split '\s+'; $start=$null;$end=$null;$perms='';$kind='';$backing=''
            if($f[0] -match '^([0-9A-Fa-f]+)-([0-9A-Fa-f]+)$') {
                $start=[Convert]::ToInt64($Matches[1],16); $end=[Convert]::ToInt64($Matches[2],16); if($f.Count -gt 1){$perms=$f[1]}; if($f.Count -gt 5){$backing=($f[5..($f.Count-1)] -join ' ')}; if($backing -eq '[vsyscall]'){continue}
            } elseif($f.Count -ge 6 -and $f[0] -match '^0x[0-9A-Fa-f]+$' -and $f[1] -match '^0x[0-9A-Fa-f]+$') {
                $start=[Convert]::ToInt64($f[0].Substring(2),16); $end=[Convert]::ToInt64($f[1].Substring(2),16); $perms=$f[5]; if($f.Count -gt 11){$kind=$f[11]}; if($f.Count -gt 12){$backing=$f[12]}; if($kind -in @('device','phys')){continue}
            } else { continue }
            if($perms -notmatch 'r' -or $end -le $start -or ($start%4096) -ne 0 -or ($end%4096) -ne 0){continue}
            $pos=$start; $chunk=64MB
            while($pos -lt $end){ $len=[Math]::Min($chunk,$end-$pos); $len=$len-($len%4096); if($len -le 0){break}; $regions += [pscustomobject]@{Start=$pos;End=$pos+$len;Length=$len;Perms=$perms;Kind=$kind;Backing=$backing}; $pos += $len }
        }
        foreach($r in $regions) {
            $sh=$r.Start.ToString('x');$eh=$r.End.ToString('x');$dest=Join-Path $rdir "$sh-$eh.bin";$err=Join-Path $rdir "$sh-$eh.stderr"
            $skip=[int64]($r.Start/4096);$count=[int64]($r.Length/4096); Write-Log "PID $pid memory: 0x$sh-0x$eh ($($r.Length) bytes, $($r.Perms))"
            $rc=Receive-SshBinary "dd if=/proc/$pid/mem bs=4096 skip=$skip count=$count 2>/dev/null" $dest $err $MemoryRateMBps
            $actual=if(Test-Path $dest){(Get-Item $dest).Length}else{0};$status=if($rc -eq 0 -and $actual -eq $r.Length){'acquired'}else{'failed_or_incomplete'};$hash=if(Test-Path $dest){(Get-FileHash -Algorithm SHA256 $dest).Hash.ToLowerInvariant()}else{''}
            "region=0x$sh-0x$eh|expected=$($r.Length)|actual=$actual|perms=$($r.Perms)|type=$($r.Kind)|status=$status|sha256=$hash|backing=$($r.Backing)" | Add-Content $manifest
        }
        $after=Invoke-SshRaw (Get-RemoteShellCommand "cat /proc/$pid/maps 2>/dev/null || cat /proc/$pid/map 2>/dev/null")
        [IO.File]::WriteAllText((Join-Path $pdir 'map_after.txt'),$after.Stdout);[IO.File]::WriteAllText((Join-Path $pdir 'map_after.stderr'),$after.Stderr)
        @("finished_utc=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))","status=completed_best_effort") | Add-Content $manifest
    }
    Invoke-JuniperCli "show chassis routing-engine" "84_memory_post_routing_engine"
    Invoke-JuniperCli "show system processes extensive" "85_memory_post_processes"
    Invoke-JuniperCli "show system storage" "86_memory_post_storage"
    Invoke-JuniperCli "show system memory" "87_memory_post_system_memory"
}

Add-Content (Join-Path $script:MetaDir "manifest.txt") "utc_finished=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"

Get-ChildItem $script:CliDir,$script:ShellDir,$script:RawCliDir,$script:RawShellDir,$script:FilesDir,$script:MemoryDir,$script:MetaDir -File -Recurse |
    Sort-Object FullName | ForEach-Object {
        $h = Get-FileHash -Algorithm SHA256 $_.FullName
        "{0}  {1}" -f $h.Hash.ToLowerInvariant(),$_.FullName.Substring($script:OutDir.Length+1)
    } | Set-Content (Join-Path $script:OutDir "SHA256SUMS.txt")

Write-Log "Collection complete: $script:OutDir"
