function Check-SMBNullSession {

    [CmdletBinding()]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        Write-Verbose "settings.json not found, using default values."
        $settings = @{ }
    }

    $result = [PSCustomObject]@{
        ID             = 13
        Action         = "SMB Null Session Hardening"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Set RestrictNullSessAccess=1 and clear NullSessionPipes / NullSessionShares to block anonymous SMB access."
    }

    try {
        $lmServerPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"

        $restrictNullSessAccess = Get-ItemProperty -Path $lmServerPath -Name "RestrictNullSessAccess" -ErrorAction SilentlyContinue
        $nullSessionPipes       = Get-ItemProperty -Path $lmServerPath -Name "NullSessionPipes" -ErrorAction SilentlyContinue
        $nullSessionShares      = Get-ItemProperty -Path $lmServerPath -Name "NullSessionShares" -ErrorAction SilentlyContinue

        $issues = @()
        $secureSettings = @()

        if ($restrictNullSessAccess) {
            if ($restrictNullSessAccess.RestrictNullSessAccess -eq 1) {
                $secureSettings += "RestrictNullSessAccess=1 (secure)"
            } else {
                $issues += "RestrictNullSessAccess=$($restrictNullSessAccess.RestrictNullSessAccess) (should be 1)"
            }
        } else {
            $issues += "RestrictNullSessAccess missing (default allows null sessions)"
        }

        if ($nullSessionPipes -and $nullSessionPipes.NullSessionPipes.Count -gt 0) {
            $issues += "NullSessionPipes defined: $($nullSessionPipes.NullSessionPipes -join ', ')"
        } else {
            $secureSettings += "NullSessionPipes empty"
        }

        if ($nullSessionShares -and $nullSessionShares.NullSessionShares.Count -gt 0) {
            $issues += "NullSessionShares defined: $($nullSessionShares.NullSessionShares -join ', ')"
        } else {
            $secureSettings += "NullSessionShares empty"
        }

        if ($issues.Count -eq 0) {
            $result.Status = "OK"
            $result.Action = "SMB Null Sessions Fully Disabled"
            $result.DetectedValue = "All protections applied: $($secureSettings -join ', ')"
        }
        elseif ($issues.Count -lt 3) {
            $result.Status = "WARN"
            $result.Action = "Partial SMB Null Session Hardening"
            $result.DetectedValue = "Some protections applied: $($secureSettings -join ', '); Issues: $($issues -join '; ')"
        }
        else {
            $result.Status = "FAIL"
            $result.Action = "SMB Null Sessions Still Enabled"
            $result.DetectedValue = "Misconfigurations detected: $($issues -join '; ')"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "SMB Null Session Check Error"
        $result.DetectedValue = "Error reading configuration: $($_.Exception.Message)"
    }

    if ($settings.ShowRecommendationsInConsole -eq $true) {
        $color = switch ($result.Status) {
            "OK"   { $settings.Color_OK }
            "FAIL" { $settings.Color_FAIL }
            "WARN" { $settings.Color_WARN }
            default { "White" }
        }

        Write-Host ("[ID {0}] {1} -> {2}" -f $result.ID, $result.Action, $result.Status) -ForegroundColor $color
        Write-Host ("   Details: {0}" -f $result.DetectedValue) -ForegroundColor $color
    }

    return $result
}
