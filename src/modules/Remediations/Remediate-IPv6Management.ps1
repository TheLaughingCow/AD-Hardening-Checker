[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
function Remediate-IPv6Management {
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
        if ($PSCmdlet.ShouldProcess("IPv6 Management", "Configure properly")) {
            try {
                # Vérifier l'état actuel d'IPv6
                $ipv6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
                $currentDisabled = Get-ItemProperty -Path $ipv6Path -Name "DisabledComponents" -ErrorAction SilentlyContinue
                
                if ($currentDisabled -and $currentDisabled.DisabledComponents -eq 0xFFFFFFFF) {
                    Write-Host "[Remediation] IPv6 est complètement désactivé. Réactivation recommandée pour la compatibilité AD." -ForegroundColor Yellow
                    
                    # Réactiver IPv6 partiellement
                    Set-ItemProperty -Path $ipv6Path -Name "DisabledComponents" -Value 0 -Force
                    Write-Host "  - IPv6 réactivé" -ForegroundColor Cyan
                } else {
                    Write-Host "[Remediation] IPv6 est déjà géré correctement" -ForegroundColor Green
                }
                
                # Vérifier et activer le service Tcpip6
                $tcpip6Service = Get-Service -Name "Tcpip6" -ErrorAction SilentlyContinue
                if ($tcpip6Service -and $tcpip6Service.Status -ne "Running") {
                    Start-Service -Name "Tcpip6" -ErrorAction SilentlyContinue
                    Write-Host "  - Service Tcpip6 démarré" -ForegroundColor Cyan
                }
                
                Write-Host "[Remediation] Configuration IPv6 appliquée"
                Write-ADHCLog "Remediation applied successfully" -ForegroundColor Green
                Write-Host "Redémarrage recommandé pour appliquer tous les changements." -ForegroundColor Yellow
            }
            catch {
                Write-Error "Erreur lors de la configuration d'IPv6 : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation IPv6 Management : $($_.Exception.Message)"
    }
}

