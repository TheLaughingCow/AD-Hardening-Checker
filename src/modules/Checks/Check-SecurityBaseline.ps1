function Check-SecurityBaseline {
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
        ID             = 27
        Action         = "Security Baseline Compliance"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Indicators     = @()
        Issues         = @()
        Recommendation = "Apply Microsoft Security Baselines or CIS benchmarks, ensure UAC, Defender, firewall, audit policies are enabled, and keep security patches up to date."
    }

    try {
        $baselineIndicators = @()
        $issues = @()

        try {
            $gpos = Get-GPO -All -ErrorAction SilentlyContinue
            $securityGPOs = $gpos | Where-Object {
                $_.DisplayName -match "Baseline" -or $_.DisplayName -match "CIS" -or $_.DisplayName -match "Security"
            }
            if ($securityGPOs.Count -gt 0) {
                $baselineIndicators += "Security GPOs detected ($($securityGPOs.Count))"
            } else {
                $issues += "No security baseline GPO detected"
            }
        } catch {
            $issues += "Unable to query GPOs"
        }

        $securityPatches = Get-HotFix -ErrorAction SilentlyContinue | Where-Object {
            $_.InstalledOn -gt (Get-Date).AddDays(-30) -and $_.Description -like "*Security*"
        }
        if ($securityPatches.Count -gt 0) {
            $baselineIndicators += "Recent security patches ($($securityPatches.Count))"
        } else {
            $issues += "No recent security patches (older than 30 days)"
        }

        $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $uacEnabled = (Get-ItemProperty -Path $uacKey -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
        if ($uacEnabled -eq 1) {
            $baselineIndicators += "UAC enabled"
        } else {
            $issues += "UAC disabled"
        }

        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus -and $defenderStatus.AntivirusEnabled -and $defenderStatus.RealTimeProtectionEnabled) {
            $baselineIndicators += "Defender + RealTime protection enabled"
        } else {
            $issues += "Defender or RealTime protection disabled"
        }

        $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        if ($firewallProfiles -and ($firewallProfiles | Where-Object {$_.Enabled -eq $true})) {
            $baselineIndicators += "Firewall enabled"
        } else {
            $issues += "Firewall disabled"
        }

        try {
            $auditPolicy = auditpol /get /category:* 2>$null | Where-Object { $_ -match "Audit" -and $_ -notmatch "No Auditing" }
            if ($auditPolicy) {
                $baselineIndicators += "Security auditing enabled"
            } else {
                $issues += "No auditing configured"
            }
        } catch {
            $issues += "Unable to check audit policy"
        }

        $totalChecks = 6
        $passedChecks = $baselineIndicators.Count
        $baselineScore = [math]::Round(($passedChecks / $totalChecks) * 100, 1)

        $result.Indicators = $baselineIndicators
        $result.Issues = $issues

        if ($passedChecks -eq $totalChecks) {
            $result.Status = "OK"
            $result.Action = "Security Baseline Fully Applied"
            $result.DetectedValue = "Full compliance ($baselineScore%). Indicators: $($baselineIndicators -join '; ')"
        }
        elseif ($passedChecks -ge 3) {
            $result.Status = "WARN"
            $result.Action = "Security Baseline Partially Applied"
            $result.DetectedValue = "Partial compliance ($baselineScore%). Indicators: $($baselineIndicators -join '; '); Missing: $($issues -join '; ')"
        }
        else {
            $result.Status = "FAIL"
            $result.Action = "Security Baseline Not Applied"
            $result.DetectedValue = "Non-compliant ($baselineScore%). Missing: $($issues -join '; ')"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "Security Baseline Check Error"
        $result.DetectedValue = "Error: $($_.Exception.Message)"
    }

    if ($settings.ShowRecommendationsInConsole -eq $true) {
        $color = switch ($result.Status) {
            "OK"   { $settings.Color_OK }
            "FAIL" { $settings.Color_FAIL }
            "WARN" { $settings.Color_WARN }
            default { "White" }
        }

        Write-Host ("[ID {0}] {1} -> {2}" -f $result.ID, $result.Action, $result.Status) -ForegroundColor $color
        Write-Host ("   Score: {0}% | Details: {1}" -f $baselineScore, $result.DetectedValue) -ForegroundColor $color

        if ($result.Issues.Count -gt 0) {
            foreach ($issue in $result.Issues) {
                Write-Host ("   - Missing: {0}" -f $issue) -ForegroundColor Yellow
            }
        }
    }

    return $result
}