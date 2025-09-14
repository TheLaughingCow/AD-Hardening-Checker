function Remediate-UnconstrainedDelegation {
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

        if ($PSCmdlet.ShouldProcess("Unconstrained Delegation", "Disable for all accounts")) {
            try {
                $unconstrainedComputers = Get-ADComputer -Filter "userAccountControl -band 0x80000" -Properties userAccountControl -ErrorAction SilentlyContinue
                $unconstrainedUsers = Get-ADUser -Filter "userAccountControl -band 0x80000" -Properties userAccountControl -ErrorAction SilentlyContinue
                
                $totalAccounts = $unconstrainedComputers.Count + $unconstrainedUsers.Count
                
                if ($totalAccounts -eq 0) {
                    Write-Host "[Remediation] Aucun compte avec Unconstrained Delegation trouvé" -ForegroundColor Yellow
                    return
                }
                
                Write-Host "[Remediation] Désactivation de Unconstrained Delegation pour $totalAccounts comptes..." -ForegroundColor Green
                
                foreach ($computer in $unconstrainedComputers) {
                    try {
                        $newUAC = $computer.userAccountControl -band (-bnot 0x80000)
                        Set-ADComputer -Identity $computer.SamAccountName -Replace @{userAccountControl = $newUAC}
                        Write-Host "  - Ordinateur: $($computer.Name)" -ForegroundColor Cyan
                    }
                    catch {
                        Write-Warning "Impossible de modifier l'ordinateur $($computer.Name): $($_.Exception.Message)"
                    }
                }
                
                foreach ($user in $unconstrainedUsers) {
                    try {
                        $newUAC = $user.userAccountControl -band (-bnot 0x80000)
                        Set-ADUser -Identity $user.SamAccountName -Replace @{userAccountControl = $newUAC}
                        Write-Host "  - Utilisateur: $($user.Name)" -ForegroundColor Cyan
                    }
                    catch {
                        Write-Warning "Impossible de modifier l'utilisateur $($user.Name): $($_.Exception.Message)"
                    }
                }
                
                Write-Host "[Remediation] Unconstrained Delegation désactivé pour tous les comptes" -ForegroundColor Green
            }
            catch {
                Write-Error "Erreur lors de la désactivation de Unconstrained Delegation : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation Unconstrained Delegation : $($_.Exception.Message)"
    }
}

