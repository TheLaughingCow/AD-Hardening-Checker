[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
function Remediate-PrintSpooler {
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
        # Vérifier si c'est un contrôleur de domaine
        $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -in @(4, 5) # 4=Backup DC, 5=Primary DC
        
        if ($isDC) {
            if ($PSCmdlet.ShouldProcess("Print Spooler Service", "Stop and Disable on Domain Controller")) {
                try {
                    # Arrêter le service Print Spooler
                    Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
                    
                    # Désactiver le service
                    Set-Service -Name "Spooler" -StartupType Disabled
                    
                    Write-Host "[Remediation] Service Print Spooler arrêté et désactivé sur le contrôleur de domaine" -ForegroundColor Green
                    Write-Host "ATTENTION: Cela peut affecter les fonctionnalités d'impression sur ce serveur." -ForegroundColor Yellow
                }
                catch {
                    Write-Error "Erreur lors de la désactivation du service Print Spooler : $($_.Exception.Message)"
                }
            }
        } else {
            Write-Host "[Remediation] Serveur membre détecté. Vérifiez si l'impression est nécessaire avant de désactiver le service." -ForegroundColor Yellow
            Write-Host "Pour désactiver manuellement: Set-Service -Name 'Spooler' -StartupType Disabled" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation Print Spooler : $($_.Exception.Message)"
    }
}

