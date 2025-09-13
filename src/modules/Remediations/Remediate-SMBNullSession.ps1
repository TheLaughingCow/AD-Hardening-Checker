[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
function Remediate-SMBNullSession {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
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
        $lanmanPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"
        
        if ($PSCmdlet.ShouldProcess("SMB Null Session", "Disable")) {
            try {
                # Créer la clé si elle n'existe pas
                if (-not (Test-Path $lanmanPath)) {
                    New-Item -Path $lanmanPath -Force | Out-Null
                }
                
                # Activer la restriction des sessions nulles
                Set-ItemProperty -Path $lanmanPath -Name "RestrictNullSessAccess" -Value 1 -Force
                
                # Supprimer les pipes accessibles en session nulle
                Set-ItemProperty -Path $lanmanPath -Name "NullSessionPipes" -Value "" -Force
                
                # Supprimer les partages accessibles en session nulle
                Set-ItemProperty -Path $lanmanPath -Name "NullSessionShares" -Value "" -Force
                
                Write-Host "[Remediation] SMB Null Session désactivé" -ForegroundColor Green
                Write-Host "Redémarrage requis pour appliquer les changements." -ForegroundColor Yellow
            }
            catch {
                Write-Error "Erreur lors de la désactivation de SMB Null Session : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation SMB Null Session : $($_.Exception.Message)"
    }
}

