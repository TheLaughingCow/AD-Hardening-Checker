[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
function Remediate-PasswordPolicy {
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
        # Vérifier si le module Active Directory est disponible
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            Write-Error "Module Active Directory non disponible. Impossible d'appliquer la remédiation."
            return
        }

        if ($PSCmdlet.ShouldProcess("Domain Password Policy", "Strengthen")) {
            try {
                # Obtenir le domaine actuel
                $domain = Get-ADDomain -ErrorAction SilentlyContinue
                if (-not $domain) {
                    Write-Error "Impossible d'accéder au domaine Active Directory"
                    return
                }
                
                # Définir une politique de mot de passe renforcée
                $newPasswordPolicy = @{
                    MinPasswordLength = 12
                    MaxPasswordAge = (New-TimeSpan -Days 90)
                    MinPasswordAge = (New-TimeSpan -Days 1)
                    PasswordComplexity = $true
                    PasswordHistoryCount = 12
                }
                
                # Appliquer la nouvelle politique
                Set-ADDomain -Identity $domain.DNSRoot -Replace @{
                    MinPasswordLength = $newPasswordPolicy.MinPasswordLength
                    MaxPasswordAge = $newPasswordPolicy.MaxPasswordAge
                    MinPasswordAge = $newPasswordPolicy.MinPasswordAge
                    PasswordComplexity = $newPasswordPolicy.PasswordComplexity
                    PasswordHistoryCount = $newPasswordPolicy.PasswordHistoryCount
                }
                
                Write-Host "[Remediation] Politique de mot de passe renforcée appliquée:"
                Write-ADHCLog "Remediation applied successfully" -ForegroundColor Green
                Write-Host "  - Longueur minimale: $($newPasswordPolicy.MinPasswordLength) caractères" -ForegroundColor Cyan
                Write-Host "  - Âge maximum: $($newPasswordPolicy.MaxPasswordAge.Days) jours" -ForegroundColor Cyan
                Write-Host "  - Âge minimum: $($newPasswordPolicy.MinPasswordAge.Days) jour" -ForegroundColor Cyan
                Write-Host "  - Complexité: Activée" -ForegroundColor Cyan
                Write-Host "  - Historique: $($newPasswordPolicy.PasswordHistoryCount) mots de passe" -ForegroundColor Cyan
            }
            catch {
                Write-Error "Erreur lors de la modification de la politique de mot de passe : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation Password Policy : $($_.Exception.Message)"
    }
}

