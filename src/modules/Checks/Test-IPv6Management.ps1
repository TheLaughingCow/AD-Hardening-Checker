function Test-IPv6Management {
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
        ID             = 18
        Action         = "IPv6 Properly Managed"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Gérer IPv6 correctement sans désactivation brutale pour maintenir la compatibilité AD."
    }

    try {
        # Vérifier l'état d'IPv6
        $ipv6Enabled = $false
        $ipv6Disabled = $false
        
        # Vérifier les interfaces IPv6
        $ipv6Interfaces = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue
        
        if ($ipv6Interfaces) {
            $ipv6Enabled = $true
        }
        
        # Vérifier la configuration IPv6 dans le registre
        $ipv6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        $ipv6Disabled = Get-ItemProperty -Path $ipv6Path -Name "DisabledComponents" -ErrorAction SilentlyContinue
        
        if ($ipv6Disabled -and $ipv6Disabled.DisabledComponents -eq 0xFFFFFFFF) {
            $ipv6Disabled = $true
        }
        
        # Vérifier les services IPv6
        $ipv6Service = Get-Service -Name "Tcpip6" -ErrorAction SilentlyContinue
        $ipv6ServiceRunning = $ipv6Service -and $ipv6Service.Status -eq "Running"
        
        if ($ipv6Disabled) {
            $result.Status = "FAIL"
            $result.DetectedValue = "IPv6 complètement désactivé (peut causer des problèmes AD)"
        } elseif ($ipv6Enabled -and $ipv6ServiceRunning) {
            $result.Status = "OK"
            $result.DetectedValue = "IPv6 activé et géré correctement"
        } elseif ($ipv6Enabled) {
            $result.Status = "WARN"
            $result.DetectedValue = "IPv6 activé mais service Tcpip6 non en cours d'exécution"
        } else {
            $result.Status = "WARN"
            $result.DetectedValue = "IPv6 non détecté sur les interfaces"
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

