function Test-LDAPAnonymousBind {
    [CmdletBinding()]
    param(
        [string]$SettingsPath = "$PSScriptRoot/../../../config/settings.json"
    )

    # Charger la configuration
    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        Write-Verbose "Fichier settings.json introuvable, utilisation des valeurs par défaut."
        $settings = @{ }
    }

    $result = [PSCustomObject]@{
        ID             = 14
        Action         = "LDAP Anonymous Bind Disabled"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Désactiver LDAP Anonymous Bind pour empêcher les requêtes LDAP non authentifiées."
    }

    try {
        # Vérifier la configuration LDAP Anonymous Bind
        $ldapPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        $ldapServerIntegrity = Get-ItemProperty -Path $ldapPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
        
        # Vérifier également la configuration de sécurité LDAP
        $ldapSecurityPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        $ldapServerIntegrityRequired = Get-ItemProperty -Path $ldapSecurityPath -Name "LDAPServerIntegrityRequired" -ErrorAction SilentlyContinue
        
        if ($ldapServerIntegrityRequired -and $ldapServerIntegrityRequired.LDAPServerIntegrityRequired -eq 1) {
            $result.Status = "OK"
            $result.DetectedValue = "LDAP Anonymous Bind désactivé (Required)"
        } elseif ($ldapServerIntegrity -and $ldapServerIntegrity.LDAPServerIntegrity -eq 2) {
            $result.Status = "OK"
            $result.DetectedValue = "LDAP Anonymous Bind désactivé (Integrity=2)"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "LDAP Anonymous Bind activé ou non configuré"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.DetectedValue = "Error: $($_.Exception.Message)"
    }

    if ($settings.ShowRecommendationsInConsole -eq $true) {
        $color = switch ($result.Status) {
            "OK"   { $settings.Color_OK   }
            "FAIL" { $settings.Color_FAIL }
            "WARN" { $settings.Color_WARN }
            default { "White" }
        }
        Write-Host ("[ID {0}] {1} → {2} (Detected: {3})" -f `
            $result.ID, $result.Action, $result.Status, $result.DetectedValue) -ForegroundColor $color
    }

    return $result
}

