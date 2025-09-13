[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
function Remediate-NTLMRestriction {
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
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $msv1Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        
        if ($PSCmdlet.ShouldProcess("NTLM Restriction", "Enable audit and restrictions")) {
            try {
                # Créer les clés si elles n'existent pas
                if (-not (Test-Path $lsaPath)) {
                    New-Item -Path $lsaPath -Force | Out-Null
                }
                if (-not (Test-Path $msv1Path)) {
                    New-Item -Path $msv1Path -Force | Out-Null
                }
                
                # Activer l'audit NTLM
                Set-ItemProperty -Path $lsaPath -Name "AuditNTLMInDomain" -Value 1 -Force
                
                # Activer la restriction NTLM
                Set-ItemProperty -Path $lsaPath -Name "RestrictNTLMInDomain" -Value 1 -Force
                
                # Activer la restriction d'envoi NTLM
                Set-ItemProperty -Path $msv1Path -Name "RestrictSendingNTLMTraffic" -Value 1 -Force
                
                Write-Host "[Remediation] Restrictions NTLM activées:" -ForegroundColor Green
                Write-Host "  - Audit NTLM: Activé" -ForegroundColor Cyan
                Write-Host "  - Restriction NTLM: Activée" -ForegroundColor Cyan
                Write-Host "  - Restriction envoi NTLM: Activée" -ForegroundColor Cyan
                Write-Host "Redémarrage requis pour appliquer les changements." -ForegroundColor Yellow
            }
            catch {
                Write-Error "Erreur lors de l'activation des restrictions NTLM : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation NTLM Restriction : $($_.Exception.Message)"
    }
}

