function Check-LDAPSigning {

    [CmdletBinding()]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ }
    }

    $result = [PSCustomObject]@{
        ID             = 6
        Action         = "LDAP Signing Status"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Configurer LDAPServerIntegrity=2 (Require signing) et RequireSecureSimpleBind=1. Optionnel : LDAPClientIntegrity=1 ou 2 côté clients, et activer LDAP Channel Binding."
    }

    try {
        $details = @()
        $lsi = $null
        $rsb = $null
        $lci = $null

        try {
            $ntdsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
            $lsi = (Get-ItemProperty -Path $ntdsPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue).LDAPServerIntegrity
            $rsb = (Get-ItemProperty -Path $ntdsPath -Name "RequireSecureSimpleBind" -ErrorAction SilentlyContinue).RequireSecureSimpleBind

            if ($null -ne $lsi) { $details += "LDAPServerIntegrity=$lsi" } else { $details += "LDAPServerIntegrity=unset" }
            if ($null -ne $rsb) { $details += "RequireSecureSimpleBind=$rsb" } else { $details += "RequireSecureSimpleBind=unset" }
        } catch {
            $details += "NTDS read error: $($_.Exception.Message)"
        }

        try {
            $ldapClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"
            $lci = (Get-ItemProperty -Path $ldapClientPath -Name "LDAPClientIntegrity" -ErrorAction SilentlyContinue).LDAPClientIntegrity
            if ($null -ne $lci) { $details += "LDAPClientIntegrity=$lci" } else { $details += "LDAPClientIntegrity=unset" }
        } catch {
            $details += "LDAP client read error: $($_.Exception.Message)"
        }

        if ($lsi -eq 2) {
            $result.Status = "OK"
            $result.Action = "LDAP Signing Required"
            $result.DetectedValue = ($details -join '; ')
        }
        elseif ($null -eq $lsi) {
            $result.Status = "WARN"
            $result.Action = "LDAP Signing Unknown"
            $result.DetectedValue = ($details -join '; ')
        }
        else {
            $result.Status = "FAIL"
            $result.Action = "LDAP Signing Not Enforced"
            $result.DetectedValue = ($details -join '; ')
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
