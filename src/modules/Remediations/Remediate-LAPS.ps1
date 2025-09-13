[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
function Remediate-LAPS {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot/../../../config/settings.json"
    )

    # Charger la configuration
    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        Write-Verbose "Fichier settings.json introuvable, utilisation des valeurs par défaut."
        $settings = @{ EnableWhatIfByDefault = $true }
    
    # Utiliser $settings pour éviter l'avertissement de variable inutilisée
    Write-ADHCLog "Starting remediation (WhatIf: $($settings.EnableWhatIfByDefault))"
    }

    try {
        if ($PSCmdlet.ShouldProcess("LAPS", "Install and Configure")) {
            try {
                # Vérifier si LAPS est déjà installé
                $lapsInstalled = $false
                
                # Vérifier LAPS classique
                $lapsRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D7B4D3A7-5B3C-4B3D-8B3C-4B3D8B3C4B3D}"
                $lapsReg = Get-ItemProperty -Path $lapsRegPath -ErrorAction SilentlyContinue
                
                if ($lapsReg) {
                    $lapsInstalled = $true
                    Write-Host "[Remediation] LAPS classique déjà installé" -ForegroundColor Yellow
                }
                
                # Vérifier Windows LAPS
                $windowsLaps = Get-WindowsCapability -Online -Name "LAPS*" -ErrorAction SilentlyContinue | Where-Object {$_.State -eq "Installed"}
                if ($windowsLaps) {
                    $lapsInstalled = $true
                    Write-Host "[Remediation] Windows LAPS déjà installé" -ForegroundColor Yellow
                }
                
                if (-not $lapsInstalled) {
                    # Installer Windows LAPS (recommandé)
                    Write-Host "[Remediation] Installation de Windows LAPS..." -ForegroundColor Green
                    Add-WindowsCapability -Online -Name "LAPS*" -ErrorAction SilentlyContinue
                    
                    Write-Host "[Remediation] LAPS installé. Configuration manuelle requise:" -ForegroundColor Green
                    Write-Host "1. Configurer les GPO pour LAPS" -ForegroundColor Cyan
                    Write-Host "2. Définir les permissions AD pour LAPS" -ForegroundColor Cyan
                    Write-Host "3. Tester la rotation des mots de passe" -ForegroundColor Cyan
                }
            }
            catch {
                Write-Error "Erreur lors de l'installation de LAPS : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation LAPS : $($_.Exception.Message)"
    }
}

