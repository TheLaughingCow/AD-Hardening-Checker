function Test-TieredAdminModel {
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
        ID             = 24
        Action         = "Tiered Admin Model / PAW Applied"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Implémenter le modèle d'administration en couches (Tiered Admin) avec des PAW (Privileged Access Workstations)."
    }

    try {
        # Vérifier si le module Active Directory est disponible
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.DetectedValue = "Module Active Directory non disponible"
            return $result
        }

        $tieredModelIndicators = @()
        
        # Vérifier l'existence de groupes d'administration en couches
        $tierGroups = @("Tier 0 Admins", "Tier 1 Admins", "Tier 2 Admins", "PAW Users")
        $existingTierGroups = @()
        
        foreach ($groupName in $tierGroups) {
            try {
                $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
                if ($group) {
                    $existingTierGroups += $groupName
                }
            }
            catch {
                # Ignore si le groupe n'existe pas
            }
        }
        
        if ($existingTierGroups.Count -gt 0) {
            $tieredModelIndicators += "Groupes en couches: $($existingTierGroups -join ', ')"
        }
        
        # Vérifier les comptes Domain Admins (doivent être limités)
        $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue
        if ($domainAdmins -and $domainAdmins.Count -le 5) {
            $tieredModelIndicators += "Domain Admins limités ($($domainAdmins.Count) membres)"
        } elseif ($domainAdmins) {
            $tieredModelIndicators += "Domain Admins nombreux ($($domainAdmins.Count) membres)"
        }
        
        # Vérifier les comptes Enterprise Admins
        $enterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -ErrorAction SilentlyContinue
        if ($enterpriseAdmins -and $enterpriseAdmins.Count -le 3) {
            $tieredModelIndicators += "Enterprise Admins limités ($($enterpriseAdmins.Count) membres)"
        } elseif ($enterpriseAdmins) {
            $tieredModelIndicators += "Enterprise Admins nombreux ($($enterpriseAdmins.Count) membres)"
        }
        
        if ($tieredModelIndicators.Count -ge 2) {
            $result.Status = "OK"
            $result.DetectedValue = "Modèle en couches détecté: $($tieredModelIndicators -join '; ')"
        } elseif ($tieredModelIndicators.Count -eq 1) {
            $result.Status = "WARN"
            $result.DetectedValue = "Modèle en couches partiel: $($tieredModelIndicators -join '; ')"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "Modèle d'administration en couches non implémenté"
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

