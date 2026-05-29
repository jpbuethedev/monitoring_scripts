<#
.SYNOPSIS
    NSClient++ / Nagios plugin — checks Puppet SSL certificate expiry.

.DESCRIPTION
    Returns output and exit codes in the Nagios plugin format so it can be called
    by NSClient++ via CheckExternalScripts or NRPE.

    Exit codes:
        0 = OK
        1 = WARNING
        2 = CRITICAL
        3 = UNKNOWN

    NSClient++ nsclient.ini example:
    -------------------------------------------------------
    [/settings/external scripts/scripts]
    check_puppet_certs = powershell -ExecutionPolicy Bypass -NonInteractive -File "scripts\check_puppet_certs.ps1" -WarningDays 30 -CriticalDays 7
    -------------------------------------------------------

    Nagios / Icinga command definition example:
    -------------------------------------------------------
    define command {
        command_name  check_puppet_certs
        command_line  $USER1$/check_nrpe -H $HOSTADDRESS$ -c check_puppet_certs
    }
    -------------------------------------------------------

.PARAMETER WarningDays
    Days before expiry to enter WARNING state. Default: 30

.PARAMETER CriticalDays
    Days before expiry to enter CRITICAL state. Default: 7

.PARAMETER PuppetSslDir
    Override the auto-detected Puppet SSL directory.

.EXAMPLE
    .\check_puppet_certs.ps1
    .\check_puppet_certs.ps1 -WarningDays 60 -CriticalDays 14
    .\check_puppet_certs.ps1 -PuppetSslDir "C:\ProgramData\PuppetLabs\puppet\etc\ssl"
#>

[CmdletBinding()]
param(
    [int]$WarningDays    = 30,
    [int]$CriticalDays   = 7,
    [string]$PuppetSslDir = ""
)

# Suppress non-plugin output; all output goes through explicit Write-Host at the end
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helper: exit with a Nagios-format message
# ---------------------------------------------------------------------------
function Exit-Plugin {
    param(
        [ValidateSet("OK","WARNING","CRITICAL","UNKNOWN")]
        [string]$Status,
        [string]$Summary,
        [string[]]$Details  = @(),
        [string]$PerfData   = ""
    )

    $code = switch ($Status) {
        "OK"       { 0 }
        "WARNING"  { 1 }
        "CRITICAL" { 2 }
        "UNKNOWN"  { 3 }
    }

    $firstLine = "${Status}: ${Summary}"
    if ($PerfData -ne "") { $firstLine += " | $PerfData" }

    # NSClient++ surfaces multi-line output — list individual cert issues below the summary
    $output = @($firstLine) + $Details
    Write-Host ($output -join "`n")
    exit $code
}

# ---------------------------------------------------------------------------
# Locate Puppet SSL directory
# ---------------------------------------------------------------------------
function Resolve-SslDir {
    param([string]$Override)

    if ($Override -ne "") { return $Override }

    if ($IsLinux -or $IsMacOS) {
        return "/etc/puppetlabs/puppet/ssl"
    }

    foreach ($candidate in @(
        "C:\ProgramData\PuppetLabs\puppet\etc\ssl",
        "C:\ProgramData\PuppetLabs\puppet\ssl"
    )) {
        if (Test-Path $candidate) { return $candidate }
    }

    return $null
}

# ---------------------------------------------------------------------------
# Get the configured Puppet server from puppet.conf (or fallback methods)
# ---------------------------------------------------------------------------
function Get-PuppetServer {
    $confPaths = if ($IsLinux -or $IsMacOS) {
        @("/etc/puppetlabs/puppet/puppet.conf", "/etc/puppet/puppet.conf")
    } else {
        @(
            "C:\ProgramData\PuppetLabs\puppet\etc\puppet.conf",
            "C:\ProgramData\PuppetLabs\puppet\puppet.conf"
        )
    }

    foreach ($confFile in $confPaths) {
        if (-not (Test-Path $confFile)) { continue }
        $lines   = Get-Content $confFile -ErrorAction SilentlyContinue
        $inSection = $false
        $mainVal   = $null
        foreach ($line in $lines) {
            if ($line -match '^\s*\[(main|agent)\]') { $inSection = $true;  continue }
            if ($line -match '^\s*\['              ) { $inSection = $false; continue }
            if ($inSection -and $line -match '^\s*server\s*=\s*(.+)') {
                return $Matches[1].Trim()
            }
            if ($line -match '^\s*server\s*=\s*(.+)') { $mainVal = $Matches[1].Trim() }
        }
        if ($mainVal) { return $mainVal }
    }

    # Try puppet CLI
    if (Get-Command puppet -ErrorAction SilentlyContinue) {
        try {
            $val = & puppet config print server 2>$null
            if ($val) { return $val.Trim() }
        } catch { }
    }

    return "unknown"
}

# ---------------------------------------------------------------------------
# Get the installed Puppet agent version
# ---------------------------------------------------------------------------
function Get-PuppetVersion {
    if (Get-Command puppet -ErrorAction SilentlyContinue) {
        try {
            $ver = & puppet --version 2>$null
            if ($ver) { return $ver.Trim() }
        } catch { }
    }
    return "unknown"
}

# ---------------------------------------------------------------------------
# Parse a PEM file — returns PSCustomObject{Subject, NotAfter} or $null
# ---------------------------------------------------------------------------
function Read-PemCert {
    param([string]$Path)

    # .NET X509Certificate2 (no external tools needed)
    try {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
        return [PSCustomObject]@{ Subject = $cert.Subject; NotAfter = $cert.NotAfter }
    }
    catch { }

    # Fall back to openssl (Linux / macOS / WSL)
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        try {
            $endLine  = & openssl x509 -noout -enddate -in $Path 2>$null
            $subjLine = & openssl x509 -noout -subject -in $Path 2>$null

            if ($endLine -match "notAfter=(.+)") {
                $raw = $Matches[1].Trim()
                # openssl may emit single-digit day as " 1" (space-padded) or "1"
                $fmt = if ($raw -match "^\w+\s{2}\d ") { "MMM  d HH:mm:ss yyyy G\MT" } else { "MMM dd HH:mm:ss yyyy G\MT" }
                $notAfter = [datetime]::ParseExact(
                    $raw, $fmt,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::AssumeUniversal
                )
                $subject = if ($subjLine -match "subject=(.+)") { $Matches[1].Trim() } else { Split-Path $Path -Leaf }
                return [PSCustomObject]@{ Subject = $subject; NotAfter = $notAfter }
            }
        }
        catch { }
    }

    return $null
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$sslDir         = Resolve-SslDir -Override $PuppetSslDir
$puppetServer   = Get-PuppetServer
$puppetVersion  = Get-PuppetVersion

if (-not $sslDir) {
    Exit-Plugin -Status UNKNOWN -Summary "Puppet SSL directory not found. Use -PuppetSslDir to specify it."
}

if (-not (Test-Path $sslDir)) {
    Exit-Plugin -Status UNKNOWN -Summary "Puppet SSL directory does not exist: $sslDir"
}

# Collect PEM files from known sub-paths
$searchPaths = @(
    (Join-Path $sslDir "certs"),
    (Join-Path $sslDir "ca\signed"),
    (Join-Path $sslDir "ca/signed")
)

$pemFiles = [System.Collections.Generic.List[string]]::new()

foreach ($dir in $searchPaths) {
    if (Test-Path $dir) {
        Get-ChildItem -Path $dir -File -Include "*.pem","*.crt" -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object { if ($pemFiles -notcontains $_.FullName) { $pemFiles.Add($_.FullName) } }
    }
}

# Fallback: recurse the whole ssl dir if nothing found in standard sub-dirs
if ($pemFiles.Count -eq 0) {
    Get-ChildItem -Path $sslDir -Recurse -File -Include "*.pem","*.crt" -ErrorAction SilentlyContinue |
        ForEach-Object { $pemFiles.Add($_.FullName) }
}

if ($pemFiles.Count -eq 0) {
    Exit-Plugin -Status UNKNOWN -Summary "No certificate files found under: $sslDir"
}

$now      = Get-Date
$expired  = [System.Collections.Generic.List[string]]::new()
$critical = [System.Collections.Generic.List[string]]::new()
$warning  = [System.Collections.Generic.List[string]]::new()
$perfParts = [System.Collections.Generic.List[string]]::new()
$okCount  = 0

foreach ($path in $pemFiles) {
    $info = Read-PemCert -Path $path
    if ($null -eq $info) { continue }

    $daysLeft = [math]::Floor(($info.NotAfter - $now).TotalDays)
    $label    = (Split-Path $path -Leaf) -replace '\.pem$|\.crt$',''

    # Sanitise perfdata label (no spaces or special chars)
    $safeLabel = $label -replace '[^A-Za-z0-9_.-]','_'
    $perfParts.Add("'${safeLabel}_days'=${daysLeft};${WarningDays};${CriticalDays};0;")

    if ($daysLeft -lt 0) {
        $expired.Add("EXPIRED  : $label (expired $([math]::Abs($daysLeft)) days ago) [$($info.NotAfter.ToString('yyyy-MM-dd'))]")
    }
    elseif ($daysLeft -le $CriticalDays) {
        $critical.Add("CRITICAL : $label expires in ${daysLeft}d [$($info.NotAfter.ToString('yyyy-MM-dd'))]")
    }
    elseif ($daysLeft -le $WarningDays) {
        $warning.Add("WARNING  : $label expires in ${daysLeft}d [$($info.NotAfter.ToString('yyyy-MM-dd'))]")
    }
    else {
        $okCount++
    }
}

$perfData   = $perfParts -join " "
$totalIssues = $expired.Count + $critical.Count + $warning.Count
$details     = @($expired) + @($critical) + @($warning)

$serverTag = "puppet-server=${puppetServer} puppet-version=${puppetVersion}"

if ($expired.Count -gt 0 -or $critical.Count -gt 0) {
    $summary = "[$serverTag] $($expired.Count) expired, $($critical.Count) critical, $($warning.Count) warning, $okCount OK"
    Exit-Plugin -Status CRITICAL -Summary $summary -Details $details -PerfData $perfData
}
elseif ($warning.Count -gt 0) {
    $summary = "[$serverTag] $($warning.Count) certificate(s) expiring within ${WarningDays} days, $okCount OK"
    Exit-Plugin -Status WARNING  -Summary $summary -Details $details -PerfData $perfData
}
else {
    Exit-Plugin -Status OK -Summary "[$serverTag] All $okCount certificate(s) are valid (warn=${WarningDays}d crit=${CriticalDays}d)" -PerfData $perfData
}
