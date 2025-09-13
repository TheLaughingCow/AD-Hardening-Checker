function Test-PrintSpooler {
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
        ID             = 7
        Action         = "Print Spooler Disabled on DC"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Désactiver le service Print Spooler sur les contrôleurs de domaine et serveurs non-print."
    }

    try {
        # Vérifier si c'est un contrôleur de domaine
        $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -in @(4, 5) # 4=Backup DC, 5=Primary DC
        
        # Vérifier le statut du service Print Spooler
        $spoolerService = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
        
        if (-not $spoolerService) {
            $result.Status = "OK"
            $result.DetectedValue = "Service Print Spooler non installé"
        } elseif ($spoolerService.Status -eq "Stopped") {
            $result.Status = "OK"
            $result.DetectedValue = "Service Print Spooler arrêté"
        } elseif ($isDC -and $spoolerService.Status -eq "Running") {
            $result.Status = "FAIL"
            $result.DetectedValue = "Service Print Spooler en cours d'exécution sur DC"
        } else {
            $result.Status = "WARN"
            $result.DetectedValue = "Service Print Spooler en cours d'exécution (serveur membre)"
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

