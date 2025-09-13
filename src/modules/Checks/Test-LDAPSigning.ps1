function Test-LDAPSigning {
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
        ID             = 6
        Action         = "LDAP Signing Enabled"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Activer LDAP Signing pour forcer les connexions LDAP sécurisées."
    }

    try {
        # Vérifier la configuration LDAP dans le registre
        $ldapSigningPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        $ldapSigning = Get-ItemProperty -Path $ldapSigningPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
        
        if (-not $ldapSigning) {
            $result.Status = "FAIL"
            $result.DetectedValue = "LDAP Signing non configuré (valeur par défaut)"
        } elseif ($ldapSigning.LDAPServerIntegrity -eq 2) {
            $result.Status = "OK"
            $result.DetectedValue = "LDAP Signing activé (Required)"
        } elseif ($ldapSigning.LDAPServerIntegrity -eq 1) {
            $result.Status = "WARN"
            $result.DetectedValue = "LDAP Signing activé mais non requis"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "LDAP Signing désactivé"
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

