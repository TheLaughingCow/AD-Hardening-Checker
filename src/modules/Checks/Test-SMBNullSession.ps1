function Test-SMBNullSession {
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
        ID             = 13
        Action         = "SMB Null Session Disabled"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Désactiver SMB Null Session pour empêcher l'accès anonyme aux partages."
    }

    try {
        # Vérifier la configuration SMB Null Session
        $nullSessionPipesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"
        $nullSessionPipes = Get-ItemProperty -Path $nullSessionPipesPath -Name "NullSessionPipes" -ErrorAction SilentlyContinue
        
        $restrictNullSessAccessPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"
        $restrictNullSessAccess = Get-ItemProperty -Path $restrictNullSessAccessPath -Name "RestrictNullSessAccess" -ErrorAction SilentlyContinue
        
        if ($restrictNullSessAccess -and $restrictNullSessAccess.RestrictNullSessAccess -eq 1) {
            $result.Status = "OK"
            $result.DetectedValue = "SMB Null Session restreint"
        } elseif ($nullSessionPipes -and $nullSessionPipes.NullSessionPipes -eq "") {
            $result.Status = "OK"
            $result.DetectedValue = "Aucun pipe accessible en session nulle"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "SMB Null Session activé"
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

