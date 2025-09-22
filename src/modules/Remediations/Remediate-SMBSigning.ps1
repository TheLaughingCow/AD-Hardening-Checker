function Remediate-SMBSigning {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param([string]$SettingsPath="$PSScriptRoot\..\..\..\config\settings.json")

    if (Test-Path $SettingsPath) { $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json } else { $settings = @{ EnableWhatIfByDefault = $true } }
    Write-Host "[INFO] Starting SMB Signing remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("SMB Signing GPO", "Require SMB signing (server + client)")) {
            $gpoName="Harden_AD_SMBSigning_Enable"
            $existingGPO=Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) { Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow; return }

            $gpo=New-GPO -Name $gpoName -Comment "Require SMB signing both server and client"

            $srv="HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer"
            $cli="HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

            Set-GPRegistryValue -Name $gpoName -Key $srv -ValueName "RequireSecuritySignature" -Value 1 -Type DWord -ErrorAction Stop
            Set-GPRegistryValue -Name $gpoName -Key $srv -ValueName "EnableSecuritySignature"  -Value 1 -Type DWord -ErrorAction Stop

            Set-GPRegistryValue -Name $gpoName -Key $cli -ValueName "RequireSecuritySignature" -Value 1 -Type DWord -ErrorAction Stop
            Set-GPRegistryValue -Name $gpoName -Key $cli -ValueName "EnableSecuritySignature"  -Value 1 -Type DWord -ErrorAction Stop

            Write-Host "[Remediation] GPO '$gpoName' created and SMB signing required" -ForegroundColor Green
            Write-Host "  _ $srv\RequireSecuritySignature = 1" -ForegroundColor Cyan
            Write-Host "  _ $srv\EnableSecuritySignature  = 1" -ForegroundColor Cyan
            Write-Host "  _ $cli\RequireSecuritySignature = 1" -ForegroundColor Cyan
            Write-Host "  _ $cli\EnableSecuritySignature  = 1" -ForegroundColor Cyan
            Write-Host "  _ gpupdate /force or reboot required" -ForegroundColor Yellow
            return $gpoName
        }
    } catch { Write-Host "[ERROR] SMB Signing remediation failed: $($_.Exception.Message)" -ForegroundColor Red }
}
