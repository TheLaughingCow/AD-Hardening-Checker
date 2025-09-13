function Test-SecureServiceAccounts {
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
        ID             = 26
        Action         = "Secure Service Accounts / gMSA Used"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Utiliser des comptes de service sécurisés (gMSA) pour éviter Kerberoast et mots de passe faibles."
    }

    try {
        # Vérifier si le module Active Directory est disponible
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.DetectedValue = "Module Active Directory non disponible"
            return $result
        }

        $securityIndicators = @()
        
        # Vérifier l'existence de gMSA (Group Managed Service Accounts)
        $gmsaAccounts = Get-ADServiceAccount -Filter "ObjectClass -eq 'msDS-GroupManagedServiceAccount'" -ErrorAction SilentlyContinue
        if ($gmsaAccounts) {
            $securityIndicators += "gMSA détectés ($($gmsaAccounts.Count))"
        }
        
        # Vérifier les comptes de service avec mots de passe forts
        $serviceAccounts = Get-ADUser -Filter "ServicePrincipalName -like '*'" -Properties ServicePrincipalName, PasswordLastSet -ErrorAction SilentlyContinue
        $strongServiceAccounts = 0
        $weakServiceAccounts = 0
        
        foreach ($account in $serviceAccounts) {
            if ($account.PasswordLastSet -and $account.PasswordLastSet -gt (Get-Date).AddDays(-90)) {
                $strongServiceAccounts++
            } else {
                $weakServiceAccounts++
            }
        }
        
        if ($strongServiceAccounts -gt 0) {
            $securityIndicators += "Comptes de service avec mots de passe récents ($strongServiceAccounts)"
        }
        
        if ($weakServiceAccounts -gt 0) {
            $securityIndicators += "Comptes de service avec mots de passe anciens ($weakServiceAccounts)"
        }
        
        # Vérifier les comptes de service avec SPN multiples (potentiellement vulnérables)
        $multiSPNAccounts = $serviceAccounts | Where-Object {$_.ServicePrincipalName.Count -gt 1}
        if ($multiSPNAccounts) {
            $securityIndicators += "Comptes avec SPN multiples ($($multiSPNAccounts.Count))"
        }
        
        if ($gmsaAccounts -and $weakServiceAccounts -eq 0) {
            $result.Status = "OK"
            $result.DetectedValue = "Comptes de service sécurisés: $($securityIndicators -join ', ')"
        } elseif ($gmsaAccounts -or $strongServiceAccounts -gt 0) {
            $result.Status = "WARN"
            $result.DetectedValue = "Sécurité partielle: $($securityIndicators -join ', ')"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "Aucun compte de service sécurisé détecté"
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

