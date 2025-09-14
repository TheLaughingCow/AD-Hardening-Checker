function Remediate-SecureServiceAccounts {
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

        if ($PSCmdlet.ShouldProcess("Secure Service Accounts", "Configure gMSA and improve security")) {
            try {
                $actions = @()
                
                $gmsaAccounts = Get-ADServiceAccount -Filter "ObjectClass -eq 'msDS-GroupManagedServiceAccount'" -ErrorAction SilentlyContinue
                if ($gmsaAccounts) {
                    Write-Host "[Remediation] $($gmsaAccounts.Count) gMSA déjà configurés" -ForegroundColor Yellow
                } else {
                    $actions += "Aucun gMSA configuré - implémentation recommandée"
                }
                
                $serviceAccounts = Get-ADUser -Filter "ServicePrincipalName -like '*'" -Properties ServicePrincipalName, PasswordLastSet -ErrorAction SilentlyContinue
                $oldPasswordAccounts = $serviceAccounts | Where-Object {$_.PasswordLastSet -and $_.PasswordLastSet -lt (Get-Date).AddDays(-90)}
                
                if ($oldPasswordAccounts) {
                    $actions += "$($oldPasswordAccounts.Count) comptes de service avec mots de passe anciens (>90 jours)"
                }
                
                $multiSPNAccounts = $serviceAccounts | Where-Object {$_.ServicePrincipalName.Count -gt 1}
                if ($multiSPNAccounts) {
                    $actions += "$($multiSPNAccounts.Count) comptes avec SPN multiples (potentiellement vulnérables)"
                }
                
                if ($actions.Count -gt 0) {
                    Write-Host "[Remediation] Problèmes détectés:" -ForegroundColor Green
                    foreach ($action in $actions) {
                        Write-Host "  - $action" -ForegroundColor Cyan
                    }
                } else {
                    Write-Host "[Remediation] Comptes de service déjà sécurisés" -ForegroundColor Yellow
                }
                
                Write-Host "`nRecommandations pour sécuriser les comptes de service:" -ForegroundColor Yellow
                Write-Host "1. Implémenter gMSA (Group Managed Service Accounts)" -ForegroundColor Cyan
                Write-Host "2. Changer les mots de passe des comptes de service existants" -ForegroundColor Cyan
                Write-Host "3. Limiter les SPN par compte (principe de moindre privilège)" -ForegroundColor Cyan
                Write-Host "4. Surveiller les tentatives de Kerberoast" -ForegroundColor Cyan
                Write-Host "5. Utiliser des comptes de service dédiés par application" -ForegroundColor Cyan
                
                if ($PSCmdlet.ShouldProcess("gMSA Example", "Show creation command")) {
                    Write-Host "`nExemple de création de gMSA:" -ForegroundColor Green
                    Write-Host "New-ADServiceAccount -Name 'MyApp-gMSA' -DNSHostName 'MyApp-gMSA.domain.com' -PrincipalsAllowedToRetrieveManagedPassword 'MyApp-Servers$'" -ForegroundColor Cyan
                }
            }
            catch {
                Write-Error "Erreur lors de la sécurisation des comptes de service : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation Secure Service Accounts : $($_.Exception.Message)"
    }
}

