function Remediate-SMBNullSession {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param([string]$SettingsPath="$PSScriptRoot\..\..\..\config\settings.json")

    if (Test-Path $SettingsPath) { $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json } else { $settings = @{ EnableWhatIfByDefault = $true } }
    Write-Host "[INFO] Starting SMB Null Session remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("SMB Null Session GPO", "Harden null sessions")) {
            $gpoName="Harden_AD_SMBNullSession_Disable"
            $existingGPO=Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) { Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow; return }

            $gpo=New-GPO -Name $gpoName -Comment "Disable anonymous/null sessions for SMB"

            $srvParam="HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $srvParam -ValueName "RestrictNullSessAccess" -Value 1 -Type DWord -ErrorAction Stop
            Set-GPRegistryValue -Name $gpoName -Key $srvParam -ValueName "NullSessionPipes"  -Value @() -Type MultiString -ErrorAction Stop
            Set-GPRegistryValue -Name $gpoName -Key $srvParam -ValueName "NullSessionShares" -Value @() -Type MultiString -ErrorAction Stop

            Write-Host "[Remediation] GPO '$gpoName' created and SMB null session restrictions applied" -ForegroundColor Green
            Write-Host "  _ $srvParam\RestrictNullSessAccess = 1" -ForegroundColor Cyan
            Write-Host "  _ $srvParam\NullSessionPipes = (empty)" -ForegroundColor Cyan
            Write-Host "  _ $srvParam\NullSessionShares = (empty)" -ForegroundColor Cyan
            Write-Host "  _ gpupdate /force or reboot required" -ForegroundColor Yellow
            return $gpoName
        }
    } catch { Write-Host "[ERROR] SMB Null Session remediation failed: $($_.Exception.Message)" -ForegroundColor Red }
}
