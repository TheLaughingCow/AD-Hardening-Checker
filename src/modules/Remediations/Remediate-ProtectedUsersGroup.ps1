[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
function Remediate-ProtectedUsersGroup {
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

        if ($PSCmdlet.ShouldProcess("Protected Users Group", "Add sensitive accounts")) {
            try {
                # Vérifier si le groupe Protected Users existe
                $protectedUsersGroup = Get-ADGroup -Identity "Protected Users" -ErrorAction SilentlyContinue
                if (-not $protectedUsersGroup) {
                    Write-Error "Groupe 'Protected Users' non trouvé. Créez-le d'abord dans Active Directory."
                    return
                }
                
                # Obtenir les comptes sensibles
                $sensitiveGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
                $addedAccounts = @()
                
                foreach ($groupName in $sensitiveGroups) {
                    try {
                        $groupMembers = Get-ADGroupMember -Identity $groupName -ErrorAction SilentlyContinue
                        foreach ($member in $groupMembers) {
                            if ($member.ObjectClass -eq "user") {
                                # Vérifier si le compte est déjà dans Protected Users
                                $isProtected = Get-ADGroupMember -Identity "Protected Users" -ErrorAction SilentlyContinue | Where-Object {$_.SID -eq $member.SID}
                                
                                if (-not $isProtected) {
                                    try {
                                        Add-ADGroupMember -Identity "Protected Users" -Members $member.SamAccountName
                                        $addedAccounts += $member.Name
                                        Write-Host "  - Ajouté: $($member.Name)" -ForegroundColor Cyan
                                    }
                                    catch {
                                        Write-Warning "Impossible d'ajouter $($member.Name) au groupe Protected Users: $($_.Exception.Message)"
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-Warning "Impossible d'accéder au groupe $groupName : $($_.Exception.Message)"
                    }
                }
                
                if ($addedAccounts.Count -gt 0) {
                    Write-Host "[Remediation] $($addedAccounts.Count) comptes ajoutés au groupe Protected Users" -ForegroundColor Green
                } else {
                    Write-Host "[Remediation] Tous les comptes sensibles sont déjà dans Protected Users" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Error "Erreur lors de l'ajout des comptes au groupe Protected Users : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation Protected Users Group : $($_.Exception.Message)"
    }
}

