function Remediate-SMBv1 {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs","")]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting SMBv1 remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("SMBv1 Protocol", "Disable")) {
            try {
                Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart -ErrorAction SilentlyContinue
                Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart -ErrorAction SilentlyContinue
                
                # Alternative pour Windows Server
                if (Get-WindowsFeature -Name "SMB1Protocol" -ErrorAction SilentlyContinue) {
                    Uninstall-WindowsFeature -Name "SMB1Protocol" -Restart:$false -ErrorAction SilentlyContinue
                }
                
                Write-Host "[Remediation] SMBv1 désactivé" -ForegroundColor Green
                Write-Host "Redémarrage requis pour appliquer les changements." -ForegroundColor Yellow
                Write-Host "ATTENTION: Vérifiez que tous les clients supportent SMBv2\v3 avant de redémarrer." -ForegroundColor Red
            }
            catch {
                Write-Error "Erreur lors de la désactivation de SMBv1 : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation SMBv1 : $($_.Exception.Message)"
    }
}
