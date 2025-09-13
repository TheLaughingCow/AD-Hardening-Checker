[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
function Remediate-LSASSProtectedMode {
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
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        
        if ($PSCmdlet.ShouldProcess("LSASS Protected Mode", "Enable RunAsPPL")) {
            try {
                # Créer la clé si elle n'existe pas
                if (-not (Test-Path $lsaPath)) {
                    New-Item -Path $lsaPath -Force | Out-Null
                }
                
                # Activer RunAsPPL
                Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -Force
                
                # Activer RunAsPPLBoot pour la protection au démarrage
                Set-ItemProperty -Path $lsaPath -Name "RunAsPPLBoot" -Value 1 -Force
                
                Write-Host "[Remediation] LSASS Protected Mode activé (RunAsPPL)" -ForegroundColor Green
                Write-Host "Redémarrage requis pour appliquer les changements." -ForegroundColor Yellow
                Write-Host "ATTENTION: Cela peut affecter certains outils de sécurité et de diagnostic." -ForegroundColor Red
            }
            catch {
                Write-Error "Erreur lors de l'activation de LSASS Protected Mode : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation LSASS Protected Mode : $($_.Exception.Message)"
    }
}

