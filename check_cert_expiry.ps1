# Put this in nsclient.ini under [/settings/external scripts/scripts]
#
# Option 1 (recommended — uses -Command for reliable exit code):
# check_cert_expiry = cmd /c powershell.exe -ExecutionPolicy Bypass -NonInteractive -Command "& 'C:\Program Files\NSClient++\scripts\check_cert_expiry.ps1' -WarningDays %ARG1% -CriticalDays %ARG2%; exit $LASTEXITCODE"
#
# Option 2 (call powershell directly with -File):
# check_cert_expiry = powershell.exe -ExecutionPolicy Bypass -NonInteractive -File "C:\Program Files\NSClient++\scripts\check_cert_expiry.ps1" -WarningDays %ARG1% -CriticalDays %ARG2%
#
# WARNING: Do NOT use 'cmd /c ... & exit %ERRORLEVEL%' — %ERRORLEVEL% is expanded before
# PowerShell runs, so the exit code is always 0.

# Script Location: C:\Program Files\NSClient++\scripts\check_cert_expiry.ps1

<#
.SYNOPSIS
    Nagios/Icinga-compatible check for certificate expiry and revocation status
    on the local Windows machine store.

.DESCRIPTION
    Inspects all non-self-signed certificates in the LocalMachine\My (Personal)
    certificate store. For each certificate it:
      - Checks days remaining until expiry against configurable Warning and
        Critical thresholds.
      - Performs an online CRL/OCSP revocation check via X509Chain.
      - Outputs a single Nagios-format status line with performance data,
        followed by per-certificate detail lines.

    Exit codes follow the Nagios convention:
      0 = OK
      1 = WARNING
      2 = CRITICAL
      3 = UNKNOWN

.PARAMETER WarningDays
    Number of days before expiry at which a certificate transitions to WARNING
    state. Must be >= 0 and >= CriticalDays. Default: 30.

.PARAMETER CriticalDays
    Number of days before expiry at which a certificate transitions to CRITICAL
    state. Must be >= 0 and <= WarningDays. Default: 10.

.PARAMETER ShowOnlyProblems
    When specified, only certificates in WARNING or CRITICAL state (including
    revoked/invalid) are included in the output. If no problems are found,
    outputs a single OK line.

.EXAMPLE
    .\check_cert_expiry.ps1
    Checks all certificates using default thresholds (warn=30, crit=10).

.EXAMPLE
    .\check_cert_expiry.ps1 -WarningDays 60 -CriticalDays 30
    Checks all certificates with custom thresholds.

.EXAMPLE
    .\check_cert_expiry.ps1 -WarningDays 60 -CriticalDays 30 -ShowOnlyProblems
    Reports only certificates that are expiring soon or have revocation issues.

.EXAMPLE
    # NSClient++ nsclient.ini entry (Option 1 - recommended):
    # check_cert_expiry = cmd /c powershell.exe -ExecutionPolicy Bypass -NonInteractive -Command "& 'C:\Program Files\NSClient++\scripts\check_cert_expiry.ps1' -WarningDays %ARG1% -CriticalDays %ARG2%; exit $LASTEXITCODE"
#>

param(
    [int]$WarningDays = 30,
    [int]$CriticalDays = 10,
    [switch]$ShowOnlyProblems
)

function Test-CertificateRevocation {
    param($cert)

    $chain = $null
    try {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = "Online"
        $chain.ChainPolicy.RevocationFlag = "EntireChain"
        $chain.ChainPolicy.UrlRetrievalTimeout = New-TimeSpan -Seconds 10

        $isValid = $chain.Build($cert)

        if (-not $isValid) {
            foreach ($status in $chain.ChainStatus) {
                if ($status.Status -eq "Revoked") {
                    return "REVOKED"
                }
            }
            return "INVALID"
        }

        return "OK"
    }
    catch {
        return "UNKNOWN"
    }
    finally {
        if ($chain) { $chain.Dispose() }
    }
}

$exitCode = 3
$store = $null

try {
    if ($WarningDays -lt 0 -or $CriticalDays -lt 0) {
        Write-Host "UNKNOWN - WarningDays and CriticalDays must be >= 0"
        $exitCode = 3
        throw "EARLY_EXIT"
    }

    if ($CriticalDays -gt $WarningDays) {
        Write-Host "UNKNOWN - CriticalDays must be less than or equal to WarningDays"
        $exitCode = 3
        throw "EARLY_EXIT"
    }

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
    $store.Open("ReadOnly")

    if ($store.Certificates.Count -eq 0) {
        Write-Host "UNKNOWN - No certificates found"
        $exitCode = 3
        throw "EARLY_EXIT"
    }

    $now = Get-Date
    $globalStatus = 0
    $results = @()
    $validCertFound = $false

    foreach ($cert in $store.Certificates) {

        # Skip self-signed
        if ($cert.Subject -eq $cert.Issuer) { continue }

        $validCertFound = $true
        $daysLeft = [math]::Floor(($cert.NotAfter - $now).TotalDays)

        # Extract CN
        if ($cert.Subject -match "CN=([^,]+)") {
            $cn = $matches[1].Trim()
        } else {
            $cn = "Unknown-CN"
        }

        # ✅ CRL check
        $revocationStatus = Test-CertificateRevocation $cert

        $certStatus = "OK"
        $certStateCode = 0

        if ($revocationStatus -eq "REVOKED") {
            $certStatus = "CRITICAL"
            $certStateCode = 2
        }
        elseif ($revocationStatus -eq "INVALID") {
            $certStatus = "WARNING"
            $certStateCode = 1
        }
        elseif ($daysLeft -le $CriticalDays) {
            $certStatus = "CRITICAL"
            $certStateCode = 2
        }
        elseif ($daysLeft -le $WarningDays) {
            $certStatus = "WARNING"
            $certStateCode = 1
        }

        if ($certStateCode -gt $globalStatus) {
            $globalStatus = $certStateCode
        }

        # Friendly days text
        if ($daysLeft -lt 0) {
            $daysText = "Expired " + (-$daysLeft) + " days ago"
        } else {
            $daysText = "$daysLeft days"
        }

        $results += [PSCustomObject]@{
            Status      = $certStatus
            StateCode   = $certStateCode
            CN          = $cn
            Expiry      = $cert.NotAfter
            DaysLeft    = $daysLeft
            DaysText    = $daysText
            Thumbprint  = $cert.Thumbprint
            Revocation  = $revocationStatus
        }
    }

    if (-not $validCertFound) {
        Write-Host "UNKNOWN - No valid certificates found"
        $exitCode = 3
        throw "EARLY_EXIT"
    }

    # Deduplicate and sort
    $results = $results | Sort-Object CN, Expiry -Unique
    $results = $results | Sort-Object DaysLeft

    # Optional filter
    if ($ShowOnlyProblems) {
        $results = $results | Where-Object { $_.StateCode -gt 0 -or $_.Revocation -ne "OK" }
    }

    # If no problems
    if ($ShowOnlyProblems -and @($results).Count -eq 0) {
        Write-Host "OK - No certificate problems detected | 'total'=0 'crit'=0 'warn'=0"
        $exitCode = 0
        throw "EARLY_EXIT"
    }

    # Global state text
    switch ($globalStatus) {
        0 { $stateText = "OK" }
        1 { $stateText = "WARNING" }
        2 { $stateText = "CRITICAL" }
        default { $stateText = "UNKNOWN" }
    }

    # Summary counts
    $total = $results.Count
    $crit  = ($results | Where-Object { $_.StateCode -eq 2 }).Count
    $warn  = ($results | Where-Object { $_.StateCode -eq 1 }).Count

    # ✅ Build detail lines FIRST
    $detailLines = @()

    foreach ($r in $results) {
        $detailLines += "[{0}] CN: {1}" -f $r.Status, $r.CN
        $detailLines += "    Expiry     : {0}  ({1})" -f $r.Expiry.ToString("yyyy-MM-dd"), $r.DaysText
        $detailLines += "    Revocation : {0}" -f $r.Revocation
        $detailLines += "    Thumbprint : {0}" -f $r.Thumbprint
        $detailLines += ""
    }

    # ✅ Single Nagios line (SAFE perfdata)
    Write-Host "$stateText - Certs: Total=$total, Critical=$crit, Warning=$warn | 'total'=$total 'crit'=$crit 'warn'=$warn"

    # ✅ Then output details
    Write-Host ""
    foreach ($line in $detailLines) {
        Write-Host $line
    }

    $exitCode = $globalStatus
}
catch {
    if ($_.Exception.Message -ne "EARLY_EXIT") {
        Write-Host "UNKNOWN - Error: $($_.Exception.Message)"
        $exitCode = 3
    }
}
finally {
    if ($store) {
        $store.Close()
    }
}

# ✅ Exit at script top-level (outside try/catch) — guarantees exit code propagation
$host.SetShouldExit($exitCode)
[System.Environment]::ExitCode = $exitCode
exit $exitCode