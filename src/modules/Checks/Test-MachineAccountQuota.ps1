function Test-MachineAccountQuota {
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
        ID             = 4
        Action         = "MachineAccountQuota = 0"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Définir l'attribut ms-DS-MachineAccountQuota à 0 pour empêcher la création de comptes machines par les utilisateurs."
    }

    try {
        # Vérifier si le module Active Directory est disponible
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.DetectedValue = "Module Active Directory non disponible"
            return $result
        }

        # Obtenir le domaine actuel
        $domain = Get-ADDomain -ErrorAction SilentlyContinue
        if (-not $domain) {
            $result.Status = "WARN"
            $result.DetectedValue = "Impossible d'accéder au domaine Active Directory"
            return $result
        }

        # Vérifier l'attribut ms-DS-MachineAccountQuota
        $quota = $domain.MachineAccountQuota
        
        if ($quota -eq 0) {
            $result.Status = "OK"
            $result.DetectedValue = "MachineAccountQuota = 0"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "MachineAccountQuota = $quota"
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

