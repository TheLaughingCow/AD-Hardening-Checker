function Remediate-PrintSpooler {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    try {
        if (Test-Path $SettingsPath) {
            $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
        } else {
            $settings = @{ EnableWhatIfByDefault = $true }
        }

        Write-Host "[INFO] Starting Print Spooler remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

        if ($PSCmdlet.ShouldProcess("Print Spooler GPO", "Create GPO to disable Print Spooler")) {
            $gpoName = "Harden_AD_PrintSpooler_Disable"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Disable Print Spooler service to prevent PrintNightmare attacks"

            $servicePath = "HKLM\SYSTEM\CurrentControlSet\Services\Spooler"
            try {
                Set-GPRegistryValue -Name $gpoName -Key $servicePath -ValueName "Start" -Value 4 -Type DWord -ErrorAction Stop
                Write-Host "[Remediation] GPO '$gpoName' created successfully" -ForegroundColor Green
                Write-Host "  _ $servicePath\Start = 4 (Print Spooler service disabled)" -ForegroundColor Cyan
                Write-Host "  _ Printing functionality will be disabled on all targeted systems" -ForegroundColor Cyan
                Write-Host "  _ gpupdate /force or reboot required for full effect" -ForegroundColor Yellow
            } catch {
                Write-Host "  _ Failed to configure Spooler service: $($_.Exception.Message)" -ForegroundColor Red
            }

            Write-ADHCLog "Print Spooler GPO created and configured successfully"
            return $gpoName
        }
    }
    catch {
        Write-Host "ERROR during Print Spooler remediation: $($_.Exception.Message)" -ForegroundColor Red
    }
}
