function Test-NBTNS {
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
        ID             = 2
        Action         = "NBT-NS Disabled"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Désactiver NetBIOS sur toutes les interfaces réseau via GPO ou manuellement."
    }

    try {
        $interfaces = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        $nbtEnabled = @()
        
        foreach ($interface in $interfaces) {
            $nbtConfig = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($interface.InterfaceGuid)" -Name "NetbiosOptions" -ErrorAction SilentlyContinue
            
            if ($nbtConfig -and $nbtConfig.NetbiosOptions -ne 2) {
                $nbtEnabled += $interface.Name
            }
        }

        if ($nbtEnabled.Count -eq 0) {
            $result.Status = "OK"
            $result.DetectedValue = "NBT-NS désactivé sur toutes les interfaces"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "NBT-NS activé sur: $($nbtEnabled -join ', ')"
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

