[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
function Remediate-DefaultCredentials {
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
        if ($PSCmdlet.ShouldProcess("Default Credentials", "Change or disable")) {
            try {
                $actions = @()
                
                # Comptes administrateurs par défaut communs
                $defaultAdminAccounts = @("Administrator", "Admin", "root", "sa", "test", "guest")
                
                # Vérifier et désactiver les comptes locaux par défaut
                $localUsers = Get-LocalUser -ErrorAction SilentlyContinue
                foreach ($user in $localUsers) {
                    if ($user.Name -in $defaultAdminAccounts -and $user.Enabled) {
                        if ($PSCmdlet.ShouldProcess("Local User $($user.Name)", "Disable")) {
                            try {
                                Disable-LocalUser -Name $user.Name
                                $actions += "Compte local '$($user.Name)' désactivé"
                            }
                            catch {
                                Write-Warning "Impossible de désactiver le compte local $($user.Name): $($_.Exception.Message)"
                            }
                        }
                    }
                }
                
                # Vérifier les comptes de service avec identifiants par défaut
                $serviceAccounts = Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -like "*Administrator*" -or $_.StartName -like "*sa*"}
                foreach ($service in $serviceAccounts) {
                    if ($PSCmdlet.ShouldProcess("Service $($service.Name)", "Change service account")) {
                        Write-Host "  - Service $($service.Name) utilise un compte par défaut: $($service.StartName)" -ForegroundColor Yellow
                        $actions += "Service $($service.Name) nécessite un changement de compte de service"
                    }
                }
                
                if ($actions.Count -gt 0) {
                    Write-Host "[Remediation] Actions effectuées:" -ForegroundColor Green
                    foreach ($action in $actions) {
                        Write-Host "  - $action" -ForegroundColor Cyan
                    }
                } else {
                    Write-Host "[Remediation] Aucun compte avec identifiants par défaut trouvé" -ForegroundColor Yellow
                }
                
                Write-Host "`nRecommandations supplémentaires:" -ForegroundColor Yellow
                Write-Host "1. Changer les mots de passe des comptes administrateurs" -ForegroundColor Cyan
                Write-Host "2. Utiliser des comptes de service dédiés" -ForegroundColor Cyan
                Write-Host "3. Implémenter LAPS pour les comptes administrateurs locaux" -ForegroundColor Cyan
            }
            catch {
                Write-Error "Erreur lors de la modification des identifiants par défaut : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation Default Credentials : $($_.Exception.Message)"
    }
}

