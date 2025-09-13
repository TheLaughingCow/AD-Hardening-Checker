function Test-LSASSProtectedMode {
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
        ID             = 12
        Action         = "LSASS Protected Mode (RunAsPPL)"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Activer RunAsPPL pour protéger LSASS contre les dumps mémoire (Mimikatz)."
    }

    try {
        # Vérifier la configuration RunAsPPL dans le registre
        $runAsPPLPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $runAsPPL = Get-ItemProperty -Path $runAsPPLPath -Name "RunAsPPL" -ErrorAction SilentlyContinue
        
        if (-not $runAsPPL) {
            $result.Status = "FAIL"
            $result.DetectedValue = "RunAsPPL non configuré (désactivé par défaut)"
        } elseif ($runAsPPL.RunAsPPL -eq 1) {
            $result.Status = "OK"
            $result.DetectedValue = "RunAsPPL activé"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "RunAsPPL désactivé"
        }
        
        # Vérifier également la configuration RunAsPPLBoot
        $runAsPPLBoot = Get-ItemProperty -Path $runAsPPLPath -Name "RunAsPPLBoot" -ErrorAction SilentlyContinue
        if ($runAsPPLBoot -and $runAsPPLBoot.RunAsPPLBoot -eq 1) {
            $result.DetectedValue += " (Boot activé)"
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

