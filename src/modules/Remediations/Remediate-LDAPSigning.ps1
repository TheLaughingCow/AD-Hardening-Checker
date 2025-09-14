function Remediate-LDAPSigning {
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
        $ldapPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        
        if ($PSCmdlet.ShouldProcess("LDAP Server Integrity", "Set to Required (2)")) {
            try {
                if (-not (Test-Path $ldapPath)) {
                    New-Item -Path $ldapPath -Force | Out-Null
                }
                
                Set-ItemProperty -Path $ldapPath -Name "LDAPServerIntegrity" -Value 2 -Force
                
                Write-Host "[Remediation] LDAP Signing activé et requis" -ForegroundColor Green
                Write-Host "Redémarrage du service Active Directory requis pour appliquer les changements." -ForegroundColor Yellow
            }
            catch {
                Write-Error "Erreur lors de l'activation de LDAP Signing : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation LDAP Signing : $($_.Exception.Message)"
    }
}

