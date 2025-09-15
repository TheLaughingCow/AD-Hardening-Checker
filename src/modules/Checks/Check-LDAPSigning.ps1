function Check-LDAPSigning {

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
        ID             = 6
        Action         = "LDAP Signing Status"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Set LDAPServerIntegrity=2 (Require Signing) to fully prevent LDAP relay attacks. Consider enabling LDAP Channel Binding (KB4598347)."
    }

    try {
        $details = @()
        $ldapSigningConfigured = $false
        $ldapSigningStrong = $false

        try {
            $ldapSigningPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
            $ldapSigning = Get-ItemProperty -Path $ldapSigningPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue

            if ($ldapSigning) {
                $details += "LDAPServerIntegrity=$($ldapSigning.LDAPServerIntegrity)"
                switch ($ldapSigning.LDAPServerIntegrity) {
                    2 { $ldapSigningConfigured = $true; $ldapSigningStrong = $true }
                    1 { $ldapSigningConfigured = $true }
                    0 { $ldapSigningConfigured = $true }
                }
            } else {
                $details += "LDAPServerIntegrity not set"
            }
        }
        catch {
            Write-Verbose "Unable to read LDAPServerIntegrity: $($_.Exception.Message)"
        }

        try {
            $gpoPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
            $signingPolicy = Get-ItemProperty -Path $gpoPath -Name "LDAPClientIntegrity" -ErrorAction SilentlyContinue

            if ($signingPolicy) {
                $details += "LDAPClientIntegrity=$($signingPolicy.LDAPClientIntegrity)"
            }
        }
        catch {
            Write-Verbose "Unable to read LDAPClientIntegrity: $($_.Exception.Message)"
        }

        if ($ldapSigningConfigured -and $ldapSigningStrong) {
            $result.Status = "OK"
            $result.Action = "LDAP Signing Required"
            $result.DetectedValue = "LDAP signing is enforced (LDAPServerIntegrity=2). Details: $($details -join '; ')"
        }
        elseif ($ldapSigningConfigured) {
            $result.Status = "FAIL"
            $result.Action = "LDAP Signing Not Enforced"
            $result.DetectedValue = "LDAP signing is not required (LDAPServerIntegrity=$($ldapSigning.LDAPServerIntegrity)) - vulnerable to relay attacks. Details: $($details -join '; ')"
        }
        else {
            $result.Status = "WARN"
            $result.Action = "LDAP Signing Unknown"
            $result.DetectedValue = "Unable to determine LDAP signing status. Details: $($details -join '; ')"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "LDAP Signing Check Error"
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
    }

    return $result
}
