function Test-PreWin2000CompatibleAccess {
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
        ID             = 17
        Action         = "Pre-Windows 2000 Compatible Access Group Empty"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Vider le groupe 'Pre-Windows 2000 Compatible Access' pour supprimer les héritages inutiles."
    }

    try {
        # Vérifier si le module Active Directory est disponible
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.DetectedValue = "Module Active Directory non disponible"
            return $result
        }

        # Obtenir les membres du groupe Pre-Windows 2000 Compatible Access
        $preWin2000Group = Get-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" -ErrorAction SilentlyContinue
        
        if (-not $preWin2000Group) {
            $result.Status = "OK"
            $result.DetectedValue = "Groupe Pre-Windows 2000 Compatible Access vide"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "Groupe Pre-Windows 2000 Compatible Access contient $($preWin2000Group.Count) membres"
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

