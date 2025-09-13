[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
function Remediate-mDNSBonjour {
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
        $actions = @()
        
        # Arrêter le service Bonjour s'il est en cours d'exécution
        $bonjourService = Get-Service -Name "Bonjour Service" -ErrorAction SilentlyContinue
        if ($bonjourService -and $bonjourService.Status -eq "Running") {
            if ($PSCmdlet.ShouldProcess("Service Bonjour", "Stop")) {
                Stop-Service -Name "Bonjour Service" -Force
                $actions += "Service Bonjour arrêté"
            }
        }
        
        # Désactiver le service Bonjour
        if ($bonjourService) {
            if ($PSCmdlet.ShouldProcess("Service Bonjour", "Set to Disabled")) {
                Set-Service -Name "Bonjour Service" -StartupType Disabled
                $actions += "Service Bonjour désactivé"
            }
        }
        
        # Arrêter les processus mDNS
        $mdnsProcesses = Get-Process -Name "*mdns*" -ErrorAction SilentlyContinue
        if ($mdnsProcesses) {
            foreach ($process in $mdnsProcesses) {
                if ($PSCmdlet.ShouldProcess("Process $($process.Name)", "Stop")) {
                    try {
                        Stop-Process -Id $process.Id -Force
                        $actions += "Processus $($process.Name) arrêté"
                    }
                    catch {
                        Write-Warning "Impossible d'arrêter le processus $($process.Name): $($_.Exception.Message)"
                    }
                }
            }
        }
        
        # Désinstaller Bonjour si possible
        $bonjourProgram = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "*Bonjour*"}
        if ($bonjourProgram) {
            if ($PSCmdlet.ShouldProcess("Programme Bonjour", "Uninstall")) {
                try {
                    $bonjourProgram.Uninstall()
                    $actions += "Programme Bonjour désinstallé"
                }
                catch {
                    Write-Warning "Impossible de désinstaller Bonjour: $($_.Exception.Message)"
                    $actions += "Échec de la désinstallation de Bonjour"
                }
            }
        }
        
        if ($actions.Count -gt 0) {
            Write-Host "[Remediation] Actions effectuées:" -ForegroundColor Green
            foreach ($action in $actions) {
                Write-Host "  - $action" -ForegroundColor White
            }
        } else {
            Write-Host "[Remediation] Aucune action nécessaire (mDNS/Bonjour déjà désactivé)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation mDNS/Bonjour : $($_.Exception.Message)"
    }
}

