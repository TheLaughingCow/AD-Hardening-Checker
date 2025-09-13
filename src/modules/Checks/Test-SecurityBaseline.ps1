function Test-SecurityBaseline {
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
        ID             = 27
        Action         = "Security Baseline Applied (Microsoft/CIS)"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Appliquer et maintenir les baselines de sécurité Microsoft/CIS sans drift majeur."
    }

    try {
        $baselineIndicators = @()
        
        # Vérifier les GPO de sécurité
        $securityGPOs = @()
        try {
            $gpos = Get-GPO -All -ErrorAction SilentlyContinue
            $securityGPOs = $gpos | Where-Object {$_.DisplayName -like "*Security*" -or $_.DisplayName -like "*Baseline*" -or $_.DisplayName -like "*CIS*"}
        }
        catch {
            # Ignore les erreurs GPO
        }
        
        if ($securityGPOs.Count -gt 0) {
            $baselineIndicators += "GPO de sécurité ($($securityGPOs.Count))"
        }
        
        # Vérifier les correctifs de sécurité récents
        $securityPatches = Get-HotFix | Where-Object {$_.InstalledOn -gt (Get-Date).AddDays(-30)} | Where-Object {$_.Description -like "*Security*"}
        if ($securityPatches.Count -gt 0) {
            $baselineIndicators += "Correctifs de sécurité récents ($($securityPatches.Count))"
        }
        
        # Vérifier la configuration de sécurité de base
        $securityConfigs = @()
        
        # Vérifier UAC
        $uacEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
        if ($uacEnabled -eq 1) {
            $securityConfigs += "UAC activé"
        }
        
        # Vérifier Windows Defender
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus -and $defenderStatus.AntivirusEnabled) {
            $securityConfigs += "Windows Defender activé"
        }
        
        # Vérifier le pare-feu
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $firewallEnabled = $firewallProfiles | Where-Object {$_.Enabled -eq $true}
        if ($firewallEnabled) {
            $securityConfigs += "Pare-feu activé"
        }
        
        if ($securityConfigs.Count -gt 0) {
            $baselineIndicators += "Configurations de sécurité: $($securityConfigs -join ', ')"
        }
        
        # Vérifier les logs de sécurité
        $securityLogs = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($securityLogs) {
            $baselineIndicators += "Logs de sécurité actifs"
        }
        
        if ($baselineIndicators.Count -ge 3) {
            $result.Status = "OK"
            $result.DetectedValue = "Baseline de sécurité appliquée: $($baselineIndicators -join '; ')"
        } elseif ($baselineIndicators.Count -ge 1) {
            $result.Status = "WARN"
            $result.DetectedValue = "Baseline de sécurité partielle: $($baselineIndicators -join '; ')"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "Aucune baseline de sécurité détectée"
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

