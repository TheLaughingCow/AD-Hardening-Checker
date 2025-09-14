function Remediate-SMBNullSession {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
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
        $lanmanPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"
        
        if ($PSCmdlet.ShouldProcess("SMB Null Session", "Disable")) {
            try {
                if (-not (Test-Path $lanmanPath)) {
                    New-Item -Path $lanmanPath -Force | Out-Null
                }
                
                Set-ItemProperty -Path $lanmanPath -Name "RestrictNullSessAccess" -Value 1 -Force
                
                Set-ItemProperty -Path $lanmanPath -Name "NullSessionPipes" -Value "" -Force
                
                Set-ItemProperty -Path $lanmanPath -Name "NullSessionShares" -Value "" -Force
                
                Write-Host "[Remediation] SMB Null Session désactivé" -ForegroundColor Green
                Write-Host "Redémarrage requis pour appliquer les changements." -ForegroundColor Yellow
            }
            catch {
                Write-Error "Erreur lors de la désactivation de SMB Null Session : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation SMB Null Session : $($_.Exception.Message)"
    }
}

