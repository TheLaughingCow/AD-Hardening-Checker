function Test-DefaultCredentials {
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
        ID             = 21
        Action         = "Default Credentials Changed"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Changer les identifiants par défaut (comptes admin locaux communs, mots de passe par défaut)."
    }

    try {
        # Vérifier si le module Active Directory est disponible
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.DetectedValue = "Module Active Directory non disponible"
            return $result
        }

        # Comptes administrateurs par défaut communs
        $defaultAdminAccounts = @("Administrator", "Admin", "root", "sa", "test", "guest")
        $foundDefaultAccounts = @()
        
        # Vérifier les comptes locaux
        $localUsers = Get-LocalUser -ErrorAction SilentlyContinue
        foreach ($user in $localUsers) {
            if ($user.Name -in $defaultAdminAccounts -and $user.Enabled) {
                $foundDefaultAccounts += "Local: $($user.Name)"
            }
        }
        
        # Vérifier les comptes de domaine
        try {
            $domainUsers = Get-ADUser -Filter "Enabled -eq $true" -Properties Name -ErrorAction SilentlyContinue
            foreach ($user in $domainUsers) {
                if ($user.Name -in $defaultAdminAccounts) {
                    $foundDefaultAccounts += "Domain: $($user.Name)"
                }
            }
        }
        catch {
            # Ignore les erreurs d'accès AD
        }
        
        # Vérifier les comptes de service avec mots de passe par défaut
        $serviceAccounts = Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -like "*Administrator*" -or $_.StartName -like "*sa*"}
        foreach ($service in $serviceAccounts) {
            $foundDefaultAccounts += "Service: $($service.Name) ($($service.StartName))"
        }
        
        if ($foundDefaultAccounts.Count -eq 0) {
            $result.Status = "OK"
            $result.DetectedValue = "Aucun compte avec identifiants par défaut détecté"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "Comptes avec identifiants par défaut: $($foundDefaultAccounts -join ', ')"
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

