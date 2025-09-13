[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
function Remediate-LDAPAnonymousBind {
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
        
        if ($PSCmdlet.ShouldProcess("LDAP Anonymous Bind", "Disable")) {
            try {
                # Créer la clé si elle n'existe pas
                if (-not (Test-Path $ntdsPath)) {
                    New-Item -Path $ntdsPath -Force | Out-Null
                }
                
                # Désactiver LDAP Anonymous Bind
                Set-ItemProperty -Path $ntdsPath -Name "LDAPServerIntegrityRequired" -Value 1 -Force
                Set-ItemProperty -Path $ntdsPath -Name "LDAPServerIntegrity" -Value 2 -Force
                
                Write-Host "[Remediation] LDAP Anonymous Bind désactivé" -ForegroundColor Green
                Write-Host "Redémarrage du service Active Directory requis pour appliquer les changements." -ForegroundColor Yellow
            }
            catch {
                Write-Error "Erreur lors de la désactivation de LDAP Anonymous Bind : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation LDAP Anonymous Bind : $($_.Exception.Message)"
    }
}

