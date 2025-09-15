function Check-LDAPAnonymousBind {

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
        ID             = 14
        Action         = "LDAP Anonymous Bind Check"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Disable LDAP Anonymous Bind by clearing dsHeuristics or removing '2'. Ensure LDAPServerIntegrity=2 (signing & sealing)."
    }

    try {
        $ldapAnonymousEnabled = $false
        $ldapPartialProtection = $false
        $details = @()

        try {
            $root = [ADSI]"LDAP://RootDSE"
            $configNC = $root.configurationNamingContext
            $dsObject = [ADSI]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
            $dsHeuristics = $dsObject.Get("dsHeuristics")

            if ($dsHeuristics) {
                $details += "dsHeuristics=$dsHeuristics"
                if ($dsHeuristics -match "2") {
                    $ldapAnonymousEnabled = $true
                }
            } else {
                $details += "dsHeuristics not defined (default secure)"
            }
        }
        catch {
            Write-Verbose "Unable to read dsHeuristics, falling back to registry check"
        }

        try {
            $ldapPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
            $ldapServerIntegrity = Get-ItemProperty -Path $ldapPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue

            if ($ldapServerIntegrity) {
                $details += "LDAPServerIntegrity=$($ldapServerIntegrity.LDAPServerIntegrity)"
                switch ($ldapServerIntegrity.LDAPServerIntegrity) {
                    2 { } # Signing & sealing enforced, secure
                    1 { $ldapPartialProtection = $true } # Signing only, still partial exposure
                    0 { $ldapAnonymousEnabled = $true }  # No protection
                }
            } else {
                $details += "LDAPServerIntegrity not set"
            }
        }
        catch {
            Write-Verbose "Unable to read LDAPServerIntegrity from registry"
        }

        if ($ldapAnonymousEnabled) {
            $result.Status = "FAIL"
            $result.Action = "LDAP Anonymous Bind Enabled"
            $result.DetectedValue = "Anonymous LDAP bind allowed. Details: $($details -join '; ')"
        }
        elseif ($ldapPartialProtection) {
            $result.Status = "WARN"
            $result.Action = "LDAP Partial Protection"
            $result.DetectedValue = "LDAPServerIntegrity=1 (signing only) - consider enforcing LDAP signing & sealing. Details: $($details -join '; ')"
        }
        else {
            $result.Status = "OK"
            $result.Action = "LDAP Anonymous Bind Disabled"
            $result.DetectedValue = "Anonymous LDAP bind not allowed. Details: $($details -join '; ')"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "LDAP Anonymous Bind Check Error"
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
