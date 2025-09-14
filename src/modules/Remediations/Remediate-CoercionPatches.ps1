function Remediate-CoercionPatches {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        Write-Verbose "Fichier settings.json introuvable, utilisation des valeurs par défaut."
        $settings = @{ EnableWhatIfByDefault = $true }
    
    Write-ADHCLog "Starting remediation (WhatIf: $($settings.EnableWhatIfByDefault))"
    }

    try {
        if ($PSCmdlet.ShouldProcess("Coercion Patches", "Install and configure")) {
            try {
                $actions = @()
                
                $petitPotamPatch = Get-HotFix -Id "KB5005413" -ErrorAction SilentlyContinue
                if ($petitPotamPatch) {
                    Write-Host "[Remediation] Correctif PetitPotam (KB5005413) déjà installé" -ForegroundColor Yellow
                } else {
                    Write-Host "[Remediation] Correctif PetitPotam (KB5005413) non trouvé" -ForegroundColor Red
                    $actions += "Installer le correctif KB5005413 (PetitPotam)"
                }
                
                Write-Host "[Remediation] Vérification des mises à jour Windows..." -ForegroundColor Green
                try {
                    $updates = Get-WindowsUpdate -ErrorAction SilentlyContinue
                    if ($updates) {
                        $securityUpdates = $updates | Where-Object {$_.Title -like "*Security*" -or $_.Title -like "*coercion*"}
                        if ($securityUpdates) {
                            $actions += "Mises à jour de sécurité disponibles: $($securityUpdates.Count)"
                        }
                    }
                }
                catch {
                    Write-Warning "Impossible de vérifier les mises à jour Windows: $($_.Exception.Message)"
                }
                
                $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                $lsaConfig = Get-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
                
                if (-not $lsaConfig -or $lsaConfig.LsaCfgFlags -ne 1) {
                    if ($PSCmdlet.ShouldProcess("LSA Configuration", "Enable LSA Protection")) {
                        Set-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -Value 1 -Force
                        $actions += "Protection LSA activée"
                    }
                }
                
                if ($actions.Count -gt 0) {
                    Write-Host "[Remediation] Actions recommandées:" -ForegroundColor Green
                    foreach ($action in $actions) {
                        Write-Host "  - $action" -ForegroundColor Cyan
                    }
                } else {
                    Write-Host "[Remediation] Correctifs de coercion déjà appliqués" -ForegroundColor Yellow
                }
                
                Write-Host "`nRecommandations supplémentaires:" -ForegroundColor Yellow
                Write-Host "1. Installer toutes les mises à jour de sécurité Windows" -ForegroundColor Cyan
                Write-Host "2. Configurer les GPO pour bloquer les attaques de coercion" -ForegroundColor Cyan
                Write-Host "3. Surveiller les logs d'événements pour les tentatives d'attaque" -ForegroundColor Cyan
            }
            catch {
                Write-Error "Erreur lors de l'application des correctifs de coercion : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation Coercion Patches : $($_.Exception.Message)"
    }
}

