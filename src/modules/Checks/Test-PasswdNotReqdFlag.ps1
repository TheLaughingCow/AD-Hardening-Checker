function Test-PasswdNotReqdFlag {
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
        ID             = 25
        Action         = "No Accounts with PASSWD_NOTREQD Flag"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Supprimer le flag PASSWD_NOTREQD de tous les comptes pour exiger des mots de passe."
    }

    try {
        # Vérifier si le module Active Directory est disponible
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.DetectedValue = "Module Active Directory non disponible"
            return $result
        }

        # Rechercher les comptes avec le flag PASSWD_NOTREQD
        $accountsWithFlag = Get-ADUser -Filter "userAccountControl -band 0x0020" -Properties userAccountControl -ErrorAction SilentlyContinue
        
        if (-not $accountsWithFlag) {
            $result.Status = "OK"
            $result.DetectedValue = "Aucun compte avec flag PASSWD_NOTREQD"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "$($accountsWithFlag.Count) comptes avec flag PASSWD_NOTREQD"
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

