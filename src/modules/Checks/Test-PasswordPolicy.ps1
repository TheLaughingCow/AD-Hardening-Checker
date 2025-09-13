function Test-PasswordPolicy {
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
        ID             = 15
        Action         = "Password Policy Strengthened"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Renforcer la politique de mot de passe avec complexité, longueur minimale et expiration appropriée."
    }

    try {
        # Vérifier si le module Active Directory est disponible
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.DetectedValue = "Module Active Directory non disponible"
            return $result
        }

        # Obtenir la politique de mot de passe du domaine
        $domain = Get-ADDomain -ErrorAction SilentlyContinue
        if (-not $domain) {
            $result.Status = "WARN"
            $result.DetectedValue = "Impossible d'accéder au domaine Active Directory"
            return $result
        }

        # Vérifier les paramètres de la politique de mot de passe
        $minPasswordLength = $domain.MinPasswordLength
        $passwordComplexity = $domain.PasswordComplexity
        $maxPasswordAge = $domain.MaxPasswordAge
        $minPasswordAge = $domain.MinPasswordAge
        
        $issues = @()
        
        # Vérifier la longueur minimale (recommandé: 12+)
        if ($minPasswordLength -lt 12) {
            $issues += "Longueur minimale: $minPasswordLength (recommandé: 12+)"
        }
        
        # Vérifier la complexité
        if (-not $passwordComplexity) {
            $issues += "Complexité désactivée"
        }
        
        # Vérifier l'âge maximum (recommandé: 90 jours max)
        if ($maxPasswordAge -gt (New-TimeSpan -Days 90)) {
            $issues += "Âge maximum: $($maxPasswordAge.Days) jours (recommandé: 90 max)"
        }
        
        # Vérifier l'âge minimum (recommandé: 1 jour min)
        if ($minPasswordAge -lt (New-TimeSpan -Days 1)) {
            $issues += "Âge minimum: $($minPasswordAge.Days) jours (recommandé: 1 min)"
        }
        
        if ($issues.Count -eq 0) {
            $result.Status = "OK"
            $result.DetectedValue = "Politique de mot de passe conforme"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "Problèmes détectés: $($issues -join '; ')"
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

