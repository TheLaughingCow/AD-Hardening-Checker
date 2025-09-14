function Remediate-PasswdNotReqdFlag {
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
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            Write-Error "Module Active Directory non disponible. Impossible d'appliquer la remédiation."
            return
        }

        if ($PSCmdlet.ShouldProcess("PASSWD_NOTREQD Flag", "Remove from all accounts")) {
            try {
                $accountsWithFlag = Get-ADUser -Filter "userAccountControl -band 0x0020" -Properties userAccountControl -ErrorAction SilentlyContinue
                
                if (-not $accountsWithFlag) {
                    Write-Host "[Remediation] Aucun compte avec flag PASSWD_NOTREQD trouvé" -ForegroundColor Yellow
                    return
                }
                
                Write-Host "[Remediation] Suppression du flag PASSWD_NOTREQD pour $($accountsWithFlag.Count) comptes..." -ForegroundColor Green
                
                foreach ($account in $accountsWithFlag) {
                    try {
                        $newUAC = $account.userAccountControl -band (-bnot 0x0020)
                        Set-ADUser -Identity $account.SamAccountName -Replace @{userAccountControl = $newUAC}
                        Write-Host "  - Flag supprimé pour: $($account.Name)" -ForegroundColor Cyan
                    }
                    catch {
                        Write-Warning "Impossible de modifier le compte $($account.Name): $($_.Exception.Message)"
                    }
                }
                
                Write-Host "[Remediation] Flag PASSWD_NOTREQD supprimé de tous les comptes" -ForegroundColor Green
                Write-Host "Tous les comptes exigent maintenant un mot de passe." -ForegroundColor Yellow
            }
            catch {
                Write-Error "Erreur lors de la suppression du flag PASSWD_NOTREQD : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation PasswdNotReqd Flag : $($_.Exception.Message)"
    }
}

