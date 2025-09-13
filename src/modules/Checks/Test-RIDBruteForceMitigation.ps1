function Test-RIDBruteForceMitigation {
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
        ID             = 16
        Action         = "RID Brute Force Mitigation"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Implémenter des mesures de mitigation contre les attaques de brute force RID (Rate limiting, monitoring)."
    }

    try {
        # Vérifier la configuration de sécurité pour les attaques RID
        $securityPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        $ridBruteForceMitigation = Get-ItemProperty -Path $securityPath -Name "RidBruteForceMitigation" -ErrorAction SilentlyContinue
        
        # Vérifier les paramètres de sécurité LDAP
        $ldapSecurityPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        $ldapServerIntegrity = Get-ItemProperty -Path $ldapSecurityPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
        
        # Vérifier la configuration de rate limiting
        $rateLimitPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        $rateLimit = Get-ItemProperty -Path $rateLimitPath -Name "RateLimit" -ErrorAction SilentlyContinue
        
        $mitigations = @()
        
        # Vérifier RID Brute Force Mitigation
        if ($ridBruteForceMitigation -and $ridBruteForceMitigation.RidBruteForceMitigation -eq 1) {
            $mitigations += "RID Brute Force Mitigation activé"
        }
        
        # Vérifier LDAP Server Integrity
        if ($ldapServerIntegrity -and $ldapServerIntegrity.LDAPServerIntegrity -eq 2) {
            $mitigations += "LDAP Server Integrity activé"
        }
        
        # Vérifier Rate Limiting
        if ($rateLimit -and $rateLimit.RateLimit -gt 0) {
            $mitigations += "Rate Limiting configuré"
        }
        
        if ($mitigations.Count -ge 2) {
            $result.Status = "OK"
            $result.DetectedValue = "Mitigations en place: $($mitigations -join ', ')"
        } elseif ($mitigations.Count -eq 1) {
            $result.Status = "WARN"
            $result.DetectedValue = "Mitigation partielle: $($mitigations -join ', ')"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "Aucune mitigation RID Brute Force détectée"
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

