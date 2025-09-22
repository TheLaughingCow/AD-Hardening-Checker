function Remediate-SMBv1 {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param([string]$SettingsPath="$PSScriptRoot\..\..\..\config\settings.json")

    if (Test-Path $SettingsPath) { $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json } else { $settings = @{ EnableWhatIfByDefault = $true } }
    Write-Host "[INFO] Starting SMBv1 remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("SMBv1 GPO", "Disable SMBv1 server and client")) {
            $gpoName="Harden_AD_SMBv1_Disable"
            $existingGPO=Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) { Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow; return }

            $gpo=New-GPO -Name $gpoName -Comment "Disable SMBv1 protocol (server+client)"
            $srvParam="HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            $polSrv="HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer"
            $client="HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10"

            Set-GPRegistryValue -Name $gpoName -Key $srvParam -ValueName "SMB1" -Value 0 -Type DWord -ErrorAction Stop
            Set-GPRegistryValue -Name $gpoName -Key $polSrv  -ValueName "SMB1" -Value 0 -Type DWord -ErrorAction Stop
            Set-GPRegistryValue -Name $gpoName -Key $client  -ValueName "Start" -Value 4 -Type DWord -ErrorAction Stop

            Write-Host "[Remediation] GPO '$gpoName' created and SMBv1 disabled" -ForegroundColor Green
            Write-Host "  _ $srvParam\SMB1 = 0" -ForegroundColor Cyan
            Write-Host "  _ $polSrv\SMB1 = 0" -ForegroundColor Cyan
            Write-Host "  _ $client\Start = 4 (Disabled)" -ForegroundColor Cyan
            Write-Host "  _ Reboot required to unload SMBv1 driver" -ForegroundColor Yellow
            return $gpoName
        }
    } catch { Write-Host "ERROR during SMBv1 remediation: $($_.Exception.Message)" -ForegroundColor Red }
}
