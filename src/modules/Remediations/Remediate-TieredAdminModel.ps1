function Remediate-TieredAdminModel {
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

        if ($PSCmdlet.ShouldProcess("Tiered Admin Model", "Implement basic structure")) {
            try {
                $actions = @()
                
                $tierGroups = @{
                    "Tier 0 Admins" = "Administrateurs de niveau 0 (Domain Admins, Enterprise Admins)"
                    "Tier 1 Admins" = "Administrateurs de niveau 1 (Server Admins, Workstation Admins)"
                    "Tier 2 Admins" = "Administrateurs de niveau 2 (Help Desk, Application Admins)"
                    "PAW Users" = "Utilisateurs de PAW (Privileged Access Workstations)"
                }
                
                foreach ($groupName in $tierGroups.Keys) {
                    try {
                        $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
                        if (-not $group) {
                            if ($PSCmdlet.ShouldProcess("AD Group $groupName", "Create")) {
                                New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security -Description $tierGroups[$groupName]
                                $actions += "Groupe '$groupName' créé"
                            }
                        } else {
                            Write-Host "  - Groupe '$groupName' existe déjà" -ForegroundColor Yellow
                        }
                    }
                    catch {
                        Write-Warning "Impossible de créer le groupe $groupName : $($_.Exception.Message)"
                    }
                }
                
                $sensitiveGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
                foreach ($groupName in $sensitiveGroups) {
                    try {
                        $members = Get-ADGroupMember -Identity $groupName -ErrorAction SilentlyContinue
                        if ($members -and $members.Count -gt 5) {
                            $actions += "Groupe '$groupName' a $($members.Count) membres (recommandé: ≤5)"
                        }
                    }
                    catch {
                    }
                }
                
                if ($actions.Count -gt 0) {
                    Write-Host "[Remediation] Actions effectuées:" -ForegroundColor Green
                    foreach ($action in $actions) {
                        Write-Host "  - $action" -ForegroundColor Cyan
                    }
                } else {
                    Write-Host "[Remediation] Structure d'administration en couches déjà en place" -ForegroundColor Yellow
                }
                
                Write-Host "`nRecommandations supplémentaires:" -ForegroundColor Yellow
                Write-Host "1. Définir des GPO spécifiques pour chaque niveau" -ForegroundColor Cyan
                Write-Host "2. Implémenter des PAW (Privileged Access Workstations)" -ForegroundColor Cyan
                Write-Host "3. Configurer la séparation des privilèges" -ForegroundColor Cyan
                Write-Host "4. Mettre en place la surveillance des comptes privilégiés" -ForegroundColor Cyan
            }
            catch {
                Write-Error "Erreur lors de l'implémentation du modèle d'administration en couches : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation Tiered Admin Model : $($_.Exception.Message)"
    }
}

