function Remediate-NBTNS {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs","")]
    param(
        [string]$SettingsPath = "$PSScriptRoot/../../../config/settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting NBT-NS remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        $interfaces = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        $modifiedInterfaces = @()
        
        foreach ($interface in $interfaces) {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($interface.InterfaceGuid)"
            
            if ($PSCmdlet.ShouldProcess("Interface $($interface.Name)", "Set NetbiosOptions=2")) {
                try {
                    # Créer la clé si elle n'existe pas
                    if (-not (Test-Path $regPath)) {
                        New-Item -Path $regPath -Force | Out-Null
                    }
                    
                    # Définir NetbiosOptions = 2 (désactiver NetBIOS)
                    Set-ItemProperty -Path $regPath -Name "NetbiosOptions" -Value 2 -Force
                    $modifiedInterfaces += $interface.Name
                }
                catch {
                    Write-Warning "Impossible de modifier l'interface $($interface.Name): $($_.Exception.Message)"
                }
            }
        }
        
        if ($modifiedInterfaces.Count -gt 0) {
            Write-Host "[Remediation] NBT-NS désactivé sur les interfaces: $($modifiedInterfaces -join ', ')" -ForegroundColor Green
            Write-Host "Redémarrage requis pour appliquer les changements." -ForegroundColor Yellow
        } else {
            Write-Host "[Remediation] Aucune interface modifiée." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation NBT-NS : $($_.Exception.Message)"
    }
}
