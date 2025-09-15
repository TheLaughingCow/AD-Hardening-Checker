function Check-RIDBruteForceMitigation {

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
        ID             = 16
        Action         = "RID Brute Force Protection Status"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Mitigations    = @()
        Missing        = @()
        Recommendation = "Enable SMB signing, require LDAP signing, configure NTDS rate limiting, and enable 'RidBruteForceMitigation' on modern Windows versions to block RID enumeration attacks."
    }

    try {
        $mitigations = @()
        $issues = @()

        try {
            $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
            if ($smbConfig.RequireSecuritySignature) {
                $mitigations += "SMB Signing Required"
            } else {
                $issues += "SMB Signing not required"
            }
        }
        catch {
            $issues += "Unable to read SMB configuration"
        }

        try {
            $ldapServerIntegrity = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
            if ($ldapServerIntegrity -and $ldapServerIntegrity.LDAPServerIntegrity -eq 2) {
                $mitigations += "LDAP Signing Required"
            } elseif ($ldapServerIntegrity -and $ldapServerIntegrity.LDAPServerIntegrity -eq 1) {
                $issues += "LDAP Signing only supported (not enforced)"
            } else {
                $issues += "LDAP Signing not configured"
            }
        }
        catch {
            $issues += "Unable to read LDAP signing configuration"
        }

        try {
            $rateLimit = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "RateLimit" -ErrorAction SilentlyContinue
            if ($rateLimit -and $rateLimit.RateLimit -gt 0) {
                $mitigations += "NTDS Rate Limiting enabled (RateLimit=$($rateLimit.RateLimit))"
            } else {
                $issues += "No NTDS rate limiting configured"
            }
        }
        catch {
            $issues += "Unable to read NTDS rate limiting configuration"
        }

        try {
            $ridMitigation = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "RidBruteForceMitigation" -ErrorAction SilentlyContinue
            if ($ridMitigation -and $ridMitigation.RidBruteForceMitigation -eq 1) {
                $mitigations += "RID Brute Force Mitigation Registry Key enabled"
            }
        }
        catch {
            Write-Verbose "RidBruteForceMitigation registry key not found (expected on newer OS only)"
        }

        $result.Mitigations = $mitigations
        $result.Missing = $issues

        if ($mitigations.Count -ge 3) {
            $result.Status = "OK"
            $result.Action = "RID Brute Force Protection Enabled"
            $result.DetectedValue = "Strong protection applied: $($mitigations -join ', ')"
        }
        elseif ($mitigations.Count -ge 1) {
            $result.Status = "WARN"
            $result.Action = "RID Brute Force Protection Partial"
            $result.DetectedValue = "Partial protection: $($mitigations -join ', '). Missing: $($issues -join ', ')"
        }
        else {
            $result.Status = "FAIL"
            $result.Action = "RID Brute Force Protection Missing"
            $result.DetectedValue = "No mitigation detected. Missing: $($issues -join ', ')"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "RID Brute Force Check Error"
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
        Write-Host ("   Detected: {0}" -f $result.DetectedValue) -ForegroundColor $color

        if ($result.Missing.Count -gt 0) {
            foreach ($item in $result.Missing) {
                Write-Host ("   - Missing: {0}" -f $item) -ForegroundColor Yellow
            }
        }
    }

    return $result
}
