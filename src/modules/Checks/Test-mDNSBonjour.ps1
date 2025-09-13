function Test-mDNSBonjour {
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
        ID             = 3
        Action         = "mDNS/Bonjour Disabled"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Désinstaller ou arrêter le service Bonjour (Apple) et désactiver mDNS."
    }

    try {
        # Vérifier le service Bonjour
        $bonjourService = Get-Service -Name "Bonjour Service" -ErrorAction SilentlyContinue
        $bonjourInstalled = $null -ne $bonjourService
        
        # Vérifier les processus mDNS
        $mdnsProcesses = Get-Process -Name "*mdns*" -ErrorAction SilentlyContinue
        
        if (-not $bonjourInstalled -and $mdnsProcesses.Count -eq 0) {
            $result.Status = "OK"
            $result.DetectedValue = "mDNS/Bonjour non détecté"
        } elseif ($bonjourService.Status -eq "Running") {
            $result.Status = "FAIL"
            $result.DetectedValue = "Service Bonjour en cours d'exécution"
        } elseif ($bonjourInstalled) {
            $result.Status = "WARN"
            $result.DetectedValue = "Service Bonjour installé mais arrêté"
        } else {
            $result.Status = "WARN"
            $result.DetectedValue = "Processus mDNS détectés: $($mdnsProcesses.Name -join ', ')"
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
