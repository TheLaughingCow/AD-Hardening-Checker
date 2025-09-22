function Check-PasswordPolicy {

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
        ID             = 15
        Action         = "Domain Password Policy Status"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        PolicyDetails  = @()
        Recommendation = "Enforce strong password policy: length ≥ 12, complexity enabled, max age ≤ 90 days, history ≥ 12, account lockout configured."
    }

    try {
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.Action = "Password Policy Check Skipped"
            $result.DetectedValue = "Active Directory module not available"
            return $result
        }

        $pwdPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
        if (-not $pwdPolicy) {
            $result.Status = "WARN"
            $result.Action = "Password Policy Check Error"
            $result.DetectedValue = "Unable to retrieve domain password policy"
            return $result
        }

        $issues = @()
        $checksPassed = 0

        if ($pwdPolicy.MinPasswordLength -ge 12) { $checksPassed++ } else { $issues += "Min Length: $($pwdPolicy.MinPasswordLength) (recommended >= 12)" }
        if ($pwdPolicy.ComplexityEnabled) { $checksPassed++ } else { $issues += "Complexity Disabled" }
        if ($pwdPolicy.MaxPasswordAge -le (New-TimeSpan -Days 90)) { $checksPassed++ } else { $issues += "Max Age: $($pwdPolicy.MaxPasswordAge.Days) days (recommended <= 90)" }
        if ($pwdPolicy.MinPasswordAge -ge (New-TimeSpan -Days 1)) { $checksPassed++ } else { $issues += "Min Age: $($pwdPolicy.MinPasswordAge.Days) days (recommended >= 1)" }
        if ($pwdPolicy.LockoutThreshold -ge 5 -and $pwdPolicy.LockoutThreshold -le 10) { $checksPassed++ } else { $issues += "Lockout Threshold: $($pwdPolicy.LockoutThreshold) (recommended 5-10)" }
        if (-not $pwdPolicy.ReversibleEncryptionEnabled) { $checksPassed++ } else { $issues += "Reversible Encryption Enabled (security risk)" }
        if ($pwdPolicy.PasswordHistoryCount -ge 12) { $checksPassed++ } else { $issues += "Password History: $($pwdPolicy.PasswordHistoryCount) (recommended >= 12)" }

        $totalChecks = 7
        $securityScore = [math]::Round(($checksPassed / $totalChecks) * 100, 1)

        $result.PolicyDetails = [PSCustomObject]@{
            MinLength         = $pwdPolicy.MinPasswordLength
            ComplexityEnabled = $pwdPolicy.ComplexityEnabled
            MaxPasswordAge    = $pwdPolicy.MaxPasswordAge.Days
            MinPasswordAge    = $pwdPolicy.MinPasswordAge.Days
            LockoutThreshold  = $pwdPolicy.LockoutThreshold
            HistoryCount      = $pwdPolicy.PasswordHistoryCount
            ReversibleEncrypt = $pwdPolicy.ReversibleEncryptionEnabled
        }

        if ($issues.Count -eq 0) {
            $result.Status = "OK"
            $result.Action = "Password Policy Compliant"
            $result.DetectedValue = "Domain password policy fully compliant ($($securityScore)%)"
        } elseif ($securityScore -ge 70) {
            $result.Status = "WARN"
            $result.Action = "Password Policy Partially Compliant"
            $result.DetectedValue = "Partial compliance ($($securityScore)%): $($issues -join '; ')"
        } else {
            $result.Status = "FAIL"
            $result.Action = "Password Policy Non-Compliant"
            $result.DetectedValue = "Non-compliant policy ($($securityScore)%): $($issues -join '; ')"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "Password Policy Check Error"
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

        if ($result.PolicyDetails) {
            Write-Host ("   - MinLength: {0}, Complexity: {1}, MaxAge: {2}d, MinAge: {3}d, History: {4}, LockoutThreshold: {5}, ReversibleEncryption: {6}" -f `
                $result.PolicyDetails.MinLength,
                $result.PolicyDetails.ComplexityEnabled,
                $result.PolicyDetails.MaxPasswordAge,
                $result.PolicyDetails.MinPasswordAge,
                $result.PolicyDetails.HistoryCount,
                $result.PolicyDetails.LockoutThreshold,
                $result.PolicyDetails.ReversibleEncrypt) -ForegroundColor Yellow
        }
    }

    return $result
}
