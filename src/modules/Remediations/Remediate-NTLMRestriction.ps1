function Remediate-NTLMRestriction {
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
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $msv1Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        
        if ($PSCmdlet.ShouldProcess("NTLM Restriction", "Enable audit and restrictions")) {
            try {
                if (-not (Test-Path $lsaPath)) {
                    New-Item -Path $lsaPath -Force | Out-Null
                }
                if (-not (Test-Path $msv1Path)) {
                    New-Item -Path $msv1Path -Force | Out-Null
                }
                
                Set-ItemProperty -Path $lsaPath -Name "AuditNTLMInDomain" -Value 1 -Force
                
                Set-ItemProperty -Path $lsaPath -Name "RestrictNTLMInDomain" -Value 1 -Force
                
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

