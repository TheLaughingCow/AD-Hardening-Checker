function Test-KerberosPreAuth {
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
        ID             = 22
        Action         = "Kerberos Pre-Authentication Required"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Exiger Kerberos Pre-Authentication pour empêcher les attaques AS-REP roasting."
    }

    try {
        # Vérifier si le module Active Directory est disponible
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.DetectedValue = "Module Active Directory non disponible"
            return $result
        }

        # Rechercher les comptes sans Pre-Authentication requise
        $accountsWithoutPreAuth = Get-ADUser -Filter "userAccountControl -band 0x400000" -Properties userAccountControl -ErrorAction SilentlyContinue
        
        if (-not $accountsWithoutPreAuth) {
            $result.Status = "OK"
            $result.DetectedValue = "Tous les comptes exigent Kerberos Pre-Authentication"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "$($accountsWithoutPreAuth.Count) comptes sans Pre-Authentication requise"
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

