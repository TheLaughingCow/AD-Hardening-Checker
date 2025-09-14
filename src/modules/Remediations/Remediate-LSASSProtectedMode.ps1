function Remediate-LSASSProtectedMode {
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
        
        if ($PSCmdlet.ShouldProcess("LSASS Protected Mode", "Enable RunAsPPL")) {
            try {
                if (-not (Test-Path $lsaPath)) {
                    New-Item -Path $lsaPath -Force | Out-Null
                }
                
                Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -Force
                
                Set-ItemProperty -Path $lsaPath -Name "RunAsPPLBoot" -Value 1 -Force
                
                Write-Host "[Remediation] LSASS Protected Mode activé (RunAsPPL)" -ForegroundColor Green
                Write-Host "Redémarrage requis pour appliquer les changements." -ForegroundColor Yellow
                Write-Host "ATTENTION: Cela peut affecter certains outils de sécurité et de diagnostic." -ForegroundColor Red
            }
            catch {
                Write-Error "Erreur lors de l'activation de LSASS Protected Mode : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation LSASS Protected Mode : $($_.Exception.Message)"
    }
}

