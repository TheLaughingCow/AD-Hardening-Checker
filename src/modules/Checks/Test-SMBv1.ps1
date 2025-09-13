function Test-SMBv1 {
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
        ID             = 8
        Action         = "SMBv1 Disabled"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Désactiver SMBv1 qui est obsolète et vulnérable."
    }

    try {
        # Vérifier si SMBv1 est installé
        $smbv1Feature = Get-WindowsFeature -Name "SMB1Protocol" -ErrorAction SilentlyContinue
        
        if (-not $smbv1Feature) {
            # Alternative pour Windows 10/11
            $smbv1Client = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -ErrorAction SilentlyContinue
            $smbv1Server = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -ErrorAction SilentlyContinue
            
            if ($smbv1Client -and $smbv1Server) {
                $clientEnabled = $smbv1Client.State -eq "Enabled"
                $serverEnabled = $smbv1Server.State -eq "Enabled"
                
                if (-not $clientEnabled -and -not $serverEnabled) {
                    $result.Status = "OK"
                    $result.DetectedValue = "SMBv1 désactivé (Client et Server)"
                } elseif ($clientEnabled -or $serverEnabled) {
                    $result.Status = "FAIL"
                    $result.DetectedValue = "SMBv1 activé (Client: $clientEnabled, Server: $serverEnabled)"
                } else {
                    $result.Status = "WARN"
                    $result.DetectedValue = "Impossible de déterminer l'état de SMBv1"
                }
            } else {
                $result.Status = "WARN"
                $result.DetectedValue = "Fonctionnalité SMBv1 non trouvée"
            }
        } else {
            if ($smbv1Feature.InstallState -eq "Installed") {
                $result.Status = "FAIL"
                $result.DetectedValue = "SMBv1 installé et activé"
            } else {
                $result.Status = "OK"
                $result.DetectedValue = "SMBv1 non installé"
            }
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

