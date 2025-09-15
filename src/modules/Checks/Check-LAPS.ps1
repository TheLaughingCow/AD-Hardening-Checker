function Check-LAPS {

    [CmdletBinding()]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        Write-Verbose "settings.json not found, using default values"
        $settings = @{ }
    }

    $result = [PSCustomObject]@{
        ID                    = 9
        Action                = "LAPS Deployment Check"
        Status                = "UNKNOWN"
        DetectedValue         = $null
        ComputersWithoutLAPS  = @()
        Recommendation        = "Deploy Microsoft LAPS (legacy or Windows LAPS) and ensure all computers have a managed local admin password."
    }

    try {
        $lapsInstalled = $false
        $lapsVersion   = $null
        $adChecked     = $false

        try {
            $windowsLaps = Get-WindowsCapability -Online -Name "LAPS*" -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Installed" }
            if ($windowsLaps) {
                $lapsInstalled = $true
                $lapsVersion   = "Windows LAPS"
            }
        } catch {
            Write-Verbose "Could not query Windows LAPS capability"
        }

        if (-not $lapsInstalled) {
            try {
                $lapsRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D7B4D3A7-5B3C-4B3D-8B3C-4B3D8B3C4B3D}"
                $lapsReg = Get-ItemProperty -Path $lapsRegPath -ErrorAction SilentlyContinue
                if ($lapsReg) {
                    $lapsInstalled = $true
                    $lapsVersion   = "Legacy LAPS"
                }
            } catch {
                Write-Verbose "Could not read registry for legacy LAPS"
            }
        }

        if (Get-Module -Name ActiveDirectory -ListAvailable) {
            $adChecked = $true
            try {
                $domain = Get-ADDomain -ErrorAction SilentlyContinue
                if ($domain) {
                    $lapsSchema = Get-ADObject -SearchBase $domain.SchemaNamingContext -Filter "Name -like 'ms-Mcs-AdmPwd'" -ErrorAction SilentlyContinue
                    if ($lapsSchema -and -not $lapsInstalled) {
                        $lapsInstalled = $true
                        $lapsVersion   = "LAPS Schema Present"
                    }

                    if ($lapsInstalled) {
                        $computersWithoutPwd = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object { -not $_.'ms-Mcs-AdmPwd' }
                        if ($computersWithoutPwd.Count -gt 0) {
                            $result.ComputersWithoutLAPS = $computersWithoutPwd | Select-Object Name, DistinguishedName
                        }
                    }
                }
            } catch {
                Write-Verbose "Could not query AD for LAPS schema or computer objects"
            }
        } else {
            Write-Verbose "Active Directory module not available, skipping AD schema and computer checks"
        }

        if ($lapsInstalled) {
            if ($result.ComputersWithoutLAPS.Count -gt 0) {
                $result.Status        = "WARN"
                $result.Action        = "LAPS Partially Configured"
                $result.DetectedValue = "$lapsVersion detected, but $($result.ComputersWithoutLAPS.Count) computers have no LAPS password set" + ($(if (-not $adChecked) { " (AD check skipped)" }))
            } else {
                $result.Status        = "OK"
                $result.Action        = "LAPS Deployed and Configured"
                $result.DetectedValue = "$lapsVersion detected and appears fully configured" + ($(if (-not $adChecked) { " (AD check skipped)" }))
            }
        } else {
            $result.Status        = "FAIL"
            $result.Action        = "LAPS Not Detected"
            $result.DetectedValue = "No LAPS (legacy or Windows LAPS) detected, or schema not extended" + ($(if (-not $adChecked) { " (AD check skipped)" }))
        }

    }
    catch {
        $result.Status = "WARN"
        $result.Action = "LAPS Check Error"
        $result.DetectedValue = "Error: $($_.Exception.Message)"
    }

    if ($settings.ShowRecommendationsInConsole -eq $true) {
        $color = switch ($result.Status) {
            "OK"   { $settings.Color_OK }
            "FAIL" { $settings.Color_FAIL }
            "WARN" { $settings.Color_WARN }
            default { "White" }
        }

        Write-Host ("[ID {0}] {1} -> {2} (Detected: {3})" -f `
            $result.ID, $result.Action, $result.Status, $result.DetectedValue) -ForegroundColor $color

        if ($result.ComputersWithoutLAPS.Count -gt 0) {
            foreach ($c in $result.ComputersWithoutLAPS) {
                Write-Host ("   - Computer missing LAPS password: {0}" -f $c.Name) -ForegroundColor Yellow
            }
        }
    }

    return $result
}
