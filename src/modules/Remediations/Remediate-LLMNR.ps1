function Remediate-LLMNR {
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

    Write-Host "[INFO] Starting LLMNR remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("LLMNR GPO", "Create GPO to disable LLMNR")) {
            $gpoName = "Harden_AD_LLMNR_Disable"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Disable LLMNR to prevent LLMNR poisoning attacks"

            $regPath = "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient"
            Set-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "EnableMulticast" -Value 0 -Type DWord -ErrorAction Stop

            $verify = Get-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "EnableMulticast" -ErrorAction SilentlyContinue
            if ($verify -and $verify.Value -eq 0) {
                Write-Host "  _ EnableMulticast correctly set to 0 (LLMNR disabled)" -ForegroundColor Green
            } else {
                Write-Host "  _ EnableMulticast could not be verified" -ForegroundColor Red
            }

            Write-Host "[Remediation] GPO '$gpoName' created successfully" -ForegroundColor Green
            Write-Host "  _ $regPath\EnableMulticast = 0" -ForegroundColor Cyan
            Write-Host "Note: gpupdate /force or reboot required on clients to apply." -ForegroundColor Yellow

            return $gpoName
        }
    }
    catch {
        Write-Host "ERROR during LLMNR remediation: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
