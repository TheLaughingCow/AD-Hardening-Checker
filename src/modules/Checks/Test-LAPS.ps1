function Test-LAPS {
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
        ID             = 9
        Action         = "LAPS Deployed"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Déployer LAPS (Local Administrator Password Solution) ou Windows LAPS pour gérer les mots de passe des comptes administrateurs locaux."
    }

    try {
        # Vérifier si LAPS est installé
        $lapsInstalled = $false
        $lapsVersion = $null
        
        # Vérifier LAPS classique
        $lapsRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D7B4D3A7-5B3C-4B3D-8B3C-4B3D8B3C4B3D}"
        $lapsReg = Get-ItemProperty -Path $lapsRegPath -ErrorAction SilentlyContinue
        
        if ($lapsReg) {
            $lapsInstalled = $true
            $lapsVersion = "LAPS Classic"
        }
        
        # Vérifier Windows LAPS (nouvelle version)
        $windowsLaps = Get-WindowsCapability -Online -Name "LAPS*" -ErrorAction SilentlyContinue | Where-Object {$_.State -eq "Installed"}
        if ($windowsLaps) {
            $lapsInstalled = $true
            $lapsVersion = "Windows LAPS"
        }
        
        # Vérifier les attributs AD pour LAPS
        if (-not $lapsInstalled) {
            try {
                $domain = Get-ADDomain -ErrorAction SilentlyContinue
                if ($domain) {
                    $lapsSchema = Get-ADObject -SearchBase $domain.SchemaNamingContext -Filter "Name -like '*LAPS*'" -ErrorAction SilentlyContinue
                    if ($lapsSchema) {
                        $lapsInstalled = $true
                        $lapsVersion = "LAPS Schema Present"
                    }
                }
            } catch {
                # Ignore AD errors
            }
        }
        
        if ($lapsInstalled) {
            $result.Status = "OK"
            $result.DetectedValue = "LAPS détecté: $lapsVersion"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "LAPS non installé ou non configuré"
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

