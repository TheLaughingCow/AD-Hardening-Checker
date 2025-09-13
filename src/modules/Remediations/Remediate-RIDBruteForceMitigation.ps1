[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
function Remediate-RIDBruteForceMitigation {
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
        $ntdsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        
        if ($PSCmdlet.ShouldProcess("RID Brute Force Mitigation", "Enable")) {
            try {
                # Créer la clé si elle n'existe pas
                if (-not (Test-Path $ntdsPath)) {
                    New-Item -Path $ntdsPath -Force | Out-Null
                }
                
                # Activer RID Brute Force Mitigation
                Set-ItemProperty -Path $ntdsPath -Name "RidBruteForceMitigation" -Value 1 -Force
                
                # Activer LDAP Server Integrity
                Set-ItemProperty -Path $ntdsPath -Name "LDAPServerIntegrity" -Value 2 -Force
                
                # Configurer le rate limiting
                Set-ItemProperty -Path $ntdsPath -Name "RateLimit" -Value 100 -Force
                
                Write-Host "[Remediation] RID Brute Force Mitigation activée" -ForegroundColor Green
                Write-Host "  - RID Brute Force Mitigation: Activé" -ForegroundColor Cyan
                Write-Host "  - LDAP Server Integrity: Activé" -ForegroundColor Cyan
                Write-Host "  - Rate Limiting: 100 requêtes/seconde" -ForegroundColor Cyan
                Write-Host "Redémarrage du service Active Directory requis pour appliquer les changements." -ForegroundColor Yellow
            }
            catch {
                Write-Error "Erreur lors de l'activation de RID Brute Force Mitigation : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation RID Brute Force Mitigation : $($_.Exception.Message)"
    }
}

