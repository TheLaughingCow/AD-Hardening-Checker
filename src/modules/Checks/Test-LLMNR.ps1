function Test-LLMNR {
    [CmdletBinding()]
    param(
        [string]$SettingsPath = "$PSScriptRoot/../../config/settings.json"
    )

    # Charger la configuration
    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        Write-Verbose "Fichier settings.json introuvable, utilisation des valeurs par défaut."
        $settings = @{ }
    }

    $result = [PSCustomObject]@{
        ID             = 1
        Action         = "LLMNR Disabled"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Configurer la GPO 'Turn Off Multicast Name Resolution' sur Enabled."
    }

    try {
        $regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
        $reg = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

        if ($null -eq $reg) {
            # Si la clé n'existe pas, LLMNR est activé par défaut
            $result.Status = "FAIL"
            $result.DetectedValue = "NotConfigured (LLMNR Enabled)"
        }
        elseif ($reg.EnableMulticast -eq 0) {
            $result.Status = "OK"
            $result.DetectedValue = 0
        }
        elseif ($reg.EnableMulticast -eq 1) {
            $result.Status = "FAIL"
            $result.DetectedValue = 1
        }
        else {
            $result.Status = "WARN"
            $result.DetectedValue = "UnknownValue: $($reg.EnableMulticast)"
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
