# Version One Shows Windows Version and Build Number
# Get Windows Patch Level / UBR

#  NSClient++ (nsclient.ini)
#  check_patch_level = powershell.exe -ExecutionPolicy Bypass -File "scripts\get_patch_level.ps1"

# Windows Version + Build + UBR (Nagios-style output)
# Works on Windows 7 → Windows 11 and modern Windows Server
# Requires PowerShell 3.0+

Try {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    # -----------------------------
    # WINDOWS VERSION (Major/Minor)
    # -----------------------------
    # Modern Windows: 10/11/Server 2016+
    $Major = $cv.CurrentMajorVersionNumber
    $Minor = $cv.CurrentMinorVersionNumber

    # Legacy Windows: Win7/8/8.1 → fallback to 'CurrentVersion'
    if ($null -eq $Major -or $null -eq $Minor) {
        # 'CurrentVersion' is a string like "6.1", "6.2", "6.3"
        $legacyVer = $cv.CurrentVersion
        if ($legacyVer -match '^(\d+)\.(\d+)$') {
            $Major = [int]$Matches[1]
            $Minor = [int]$Matches[2]
        }
        else {
            # Ultimate fallback (should never hit)
            $Major = 0
            $Minor = 0
        }
    }

    # -----------------------------
    # BUILD NUMBER & UBR
    # -----------------------------
    $Build = [int]$cv.CurrentBuild

    # UBR may not exist on Win7 RTM (exists on Win7 SP1+)
    if ($cv.PSObject.Properties.Name -contains 'UBR') {
        $UBR = [int]$cv.UBR
    }
    else {
        $UBR = 0
    }

    # -----------------------------
    # FRIENDLY VERSION (22H2/21H2/etc.)
    # -----------------------------
    $DisplayVer = $cv.DisplayVersion
    if (-not $DisplayVer) { $DisplayVer = $cv.ReleaseId }
    if (-not $DisplayVer) { $DisplayVer = "$Major.$Minor" }

    # -----------------------------
    # PRODUCT NAME (Fallback for Win7/8)
    # -----------------------------
    $ProductName = $cv.ProductName
    if (-not $ProductName) {
        try {
            $ProductName = (Get-CimInstance Win32_OperatingSystem).Caption
        } catch {
            $ProductName = "Windows"
        }
    }

    # -----------------------------
    # MESSAGE AND PERF DATA
    # -----------------------------
    $VersionText = "$Major.$Minor"

    $Message = "OK: $ProductName $DisplayVer - Version: $VersionText - Build: $Build - Patch Level (UBR): $UBR"

    $Perf = "'version_major'=$Major;;;; 'version_minor'=$Minor;;;; 'build'=$Build;;;; 'ubr'=$UBR;;;;"

    Write-Output "$Message | $Perf"
    Exit 0
}
Catch {
    Write-Output "CRITICAL: Unable to read Windows patch level/version: $($_.Exception.Message)"
    Exit 2
}