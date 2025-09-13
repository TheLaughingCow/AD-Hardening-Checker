function Test-CoercionPatches {
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
        ID             = 23
        Action         = "Coercion Patches Applied (PetitPotam, etc.)"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Appliquer les correctifs de coercion (PetitPotam, etc.) pour mitiger les attaques NTLM relay."
    }

    try {
        # Vérifier les correctifs de coercion
        $patches = @()
        
        # Vérifier le correctif PetitPotam (KB5005413)
        $petitPotamPatch = Get-HotFix -Id "KB5005413" -ErrorAction SilentlyContinue
        if ($petitPotamPatch) {
            $patches += "PetitPotam (KB5005413)"
        }
        
        # Vérifier les correctifs de coercion généraux
        $coercionPatches = Get-HotFix | Where-Object {$_.Description -like "*coercion*" -or $_.Description -like "*relay*"}
        if ($coercionPatches) {
            foreach ($patch in $coercionPatches) {
                $patches += "$($patch.HotFixID) - $($patch.Description)"
            }
        }
        
        # Vérifier la version du système d'exploitation
        $osVersion = [System.Environment]::OSVersion.Version
        $buildNumber = $osVersion.Build
        
        # Les builds récents incluent les correctifs de coercion
        if ($buildNumber -ge 19044) { # Windows 10 21H2 et plus récent
            $patches += "Build récent ($buildNumber) - Correctifs inclus"
        }
        
        if ($patches.Count -gt 0) {
            $result.Status = "OK"
            $result.DetectedValue = "Correctifs de coercion détectés: $($patches -join ', ')"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "Aucun correctif de coercion détecté"
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

