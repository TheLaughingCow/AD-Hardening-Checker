function Test-ProtectedUsersGroup {
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
        ID             = 11
        Action         = "Sensitive Accounts in Protected Users Group"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Ajouter les comptes sensibles (Domain Admins, Enterprise Admins, etc.) au groupe Protected Users."
    }

    try {
        # Vérifier si le module Active Directory est disponible
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.DetectedValue = "Module Active Directory non disponible"
            return $result
        }

        # Obtenir les membres du groupe Protected Users
        $protectedUsers = Get-ADGroupMember -Identity "Protected Users" -ErrorAction SilentlyContinue
        
        # Vérifier si les comptes sensibles sont dans Protected Users
        $sensitiveGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
        $missingAccounts = @()
        
        foreach ($groupName in $sensitiveGroups) {
            try {
                $groupMembers = Get-ADGroupMember -Identity $groupName -ErrorAction SilentlyContinue
                foreach ($member in $groupMembers) {
                    if ($member.ObjectClass -eq "user") {
                        $isProtected = $protectedUsers | Where-Object {$_.SID -eq $member.SID}
                        if (-not $isProtected) {
                            $missingAccounts += $member.Name
                        }
                    }
                }
            }
            catch {
                # Ignore si le groupe n'existe pas
            }
        }
        
        if ($missingAccounts.Count -eq 0) {
            $result.Status = "OK"
            $result.DetectedValue = "Tous les comptes sensibles sont dans Protected Users"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "Comptes sensibles manquants dans Protected Users: $($missingAccounts -join ', ')"
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

