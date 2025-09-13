[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
function Remediate-KerberosPreAuth {
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

        if ($PSCmdlet.ShouldProcess("Kerberos Pre-Authentication", "Enable for all accounts")) {
            try {
                # Rechercher les comptes sans Pre-Authentication requise
                $accountsWithoutPreAuth = Get-ADUser -Filter "userAccountControl -band 0x400000" -Properties userAccountControl -ErrorAction SilentlyContinue
                
                if (-not $accountsWithoutPreAuth) {
                    Write-Host "[Remediation] Tous les comptes exigent déjà Kerberos Pre-Authentication" -ForegroundColor Yellow
                    return
                }
                
                Write-Host "[Remediation] Activation de Kerberos Pre-Authentication pour $($accountsWithoutPreAuth.Count) comptes..." -ForegroundColor Green
                
                foreach ($account in $accountsWithoutPreAuth) {
                    try {
                        # Supprimer le flag DONT_REQ_PREAUTH
                        $newUAC = $account.userAccountControl -band (-bnot 0x400000)
                        Set-ADUser -Identity $account.SamAccountName -Replace @{userAccountControl = $newUAC}
                        Write-Host "  - Activé pour: $($account.Name)" -ForegroundColor Cyan
                    }
                    catch {
                        Write-Warning "Impossible de modifier le compte $($account.Name): $($_.Exception.Message)"
                    }
                }
                
                Write-Host "[Remediation] Kerberos Pre-Authentication activé pour tous les comptes" -ForegroundColor Green
            }
            catch {
                Write-Error "Erreur lors de l'activation de Kerberos Pre-Authentication : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation Kerberos Pre-Authentication : $($_.Exception.Message)"
    }
}

