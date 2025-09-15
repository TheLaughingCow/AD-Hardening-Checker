function Check-NTLMRestriction {

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
        ID             = 19
        Action         = "NTLM Hardening Status"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        PassedSettings = @()
        FailedSettings = @()
        Recommendation = "Set LmCompatibilityLevel=5, RestrictReceivingNTLMTraffic=1, RestrictSendingNTLMTraffic=1, AuditNTLMInDomain=1 for maximum NTLM hardening."
    }

    try {
        $keys = @(
            'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0',
            'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
        )

        $ntlmValues = @{
            LmCompatibilityLevel = $null
            RestrictReceivingNTLMTraffic = $null
            RestrictSendingNTLMTraffic   = $null
            AuditNTLMInDomain            = $null
        }

        foreach ($key in $keys) {
            $regValues = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($regValues) {
                foreach ($prop in $ntlmValues.Keys) {
                    if ($regValues.PSObject.Properties.Name -contains $prop) {
                        $ntlmValues[$prop] = $regValues.$prop
                    }
                }
            }
        }

        if ($ntlmValues.LmCompatibilityLevel -eq 5) {
            $result.PassedSettings += "LmCompatibilityLevel=5 (NTLMv2 only)"
        } elseif ($ntlmValues.LmCompatibilityLevel) {
            $result.FailedSettings += "LmCompatibilityLevel=$($ntlmValues.LmCompatibilityLevel) (not strict)"
        } else {
            $result.FailedSettings += "LmCompatibilityLevel not set (allows LM/NTLMv1)"
        }

        if ($ntlmValues.RestrictReceivingNTLMTraffic -eq 1) {
            $result.PassedSettings += "RestrictReceivingNTLMTraffic=1"
        } else {
            $result.FailedSettings += "RestrictReceivingNTLMTraffic not set"
        }

        if ($ntlmValues.RestrictSendingNTLMTraffic -eq 1) {
            $result.PassedSettings += "RestrictSendingNTLMTraffic=1"
        } else {
            $result.FailedSettings += "RestrictSendingNTLMTraffic not set"
        }

        if ($ntlmValues.AuditNTLMInDomain -eq 1) {
            $result.PassedSettings += "AuditNTLMInDomain=1"
        } else {
            $result.FailedSettings += "AuditNTLMInDomain not set"
        }

        # Calcul du score
        $totalChecks = 4
        $passed = $result.PassedSettings.Count
        $ntlmScore = [math]::Round(($passed / $totalChecks) * 100, 1)

        if ($result.FailedSettings.Count -eq 0) {
            $result.Status = "OK"
            $result.Action = "NTLM Fully Restricted"
            $result.DetectedValue = "NTLM properly restricted ($ntlmScore%)"
        }
        elseif ($ntlmScore -ge 50) {
            $result.Status = "WARN"
            $result.Action = "NTLM Partially Restricted"
            $result.DetectedValue = "Partial NTLM hardening ($ntlmScore%)"
        }
        else {
            $result.Status = "FAIL"
            $result.Action = "NTLM Not Restricted"
            $result.DetectedValue = "NTLM hardening insufficient ($ntlmScore%)"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "NTLM Check Error"
        $result.DetectedValue = "Error: $($_.Exception.Message)"
    }

    if ($settings.ShowRecommendationsInConsole -eq $true) {
        $color = switch ($result.Status) {
            "OK"   { $settings.Color_OK }
            "FAIL" { $settings.Color_FAIL }
            "WARN" { $settings.Color_WARN }
            default { "White" }
        }
        Write-Host ("[ID {0}] {1} -> {2} (Score: {3}%)" -f `
            $result.ID, $result.Action, $result.Status, $ntlmScore) -ForegroundColor $color

        if ($result.PassedSettings.Count -gt 0) {
            Write-Host "   Passed:" -ForegroundColor Green
            foreach ($ok in $result.PassedSettings) {
                Write-Host ("     - {0}" -f $ok) -ForegroundColor Green
            }
        }
        if ($result.FailedSettings.Count -gt 0) {
            Write-Host "   Missing/Weak:" -ForegroundColor Yellow
            foreach ($fail in $result.FailedSettings) {
                Write-Host ("     - {0}" -f $fail) -ForegroundColor Yellow
            }
        }
    }

    return $result
}
