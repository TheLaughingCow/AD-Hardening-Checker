function Remediate-RIDBruteForceMitigation {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param([string]$SettingsPath="$PSScriptRoot\..\..\..\config\settings.json")

    if (Test-Path $SettingsPath) { $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json } else { $settings = @{ EnableWhatIfByDefault = $true } }
    Write-Host "[INFO] Starting RID Brute Force Mitigation remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("RID Brute Force Mitigation GPO", "Harden Netlogon + restrict remote SAM")) {
            $gpoName="Harden_AD_RIDBruteForceMitigation_Enable"
            $existingGPO=Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) { Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow; return }

            $gpo=New-GPO -Name $gpoName -Comment "Harden Netlogon secure channel + Restrict remote SAM"

            $netlogon="HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
            $lsa="HKLM\SYSTEM\CurrentControlSet\Control\Lsa"

            Set-GPRegistryValue -Name $gpoName -Key $netlogon -ValueName "RequireStrongKey"   -Value 1 -Type DWord -ErrorAction Stop
            Set-GPRegistryValue -Name $gpoName -Key $netlogon -ValueName "RequireSignOrSeal" -Value 1 -Type DWord -ErrorAction Stop
            Set-GPRegistryValue -Name $gpoName -Key $netlogon -ValueName "SignSecureChannel" -Value 1 -Type DWord -ErrorAction Stop
            Set-GPRegistryValue -Name $gpoName -Key $netlogon -ValueName "SealSecureChannel" -Value 1 -Type DWord -ErrorAction Stop

            Set-GPRegistryValue -Name $gpoName -Key $lsa -ValueName "restrictremotesam" -Type String -Value "O:BAG:BAD:(A;;RC;;;BA)" -ErrorAction Stop

            Write-Host "[Remediation] GPO '$gpoName' created successfully" -ForegroundColor Green
            Write-Host "  _ $netlogon\RequireStrongKey = 1" -ForegroundColor Cyan
            Write-Host "  _ $netlogon\RequireSignOrSeal = 1" -ForegroundColor Cyan
            Write-Host "  _ $netlogon\SignSecureChannel = 1" -ForegroundColor Cyan
            Write-Host "  _ $netlogon\SealSecureChannel = 1" -ForegroundColor Cyan
            Write-Host "  _ $lsa\restrictremotesam = O:BAG:BAD:(A;;RC;;;BA)" -ForegroundColor Cyan
            Write-Host "  _ Netlogon/LSA restart or reboot required" -ForegroundColor Yellow
            return $gpoName
        }
    } catch { Write-Host "ERROR during RID Brute Force mitigation: $($_.Exception.Message)" -ForegroundColor Red; throw }
}
