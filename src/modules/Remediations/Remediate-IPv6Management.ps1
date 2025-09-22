function Remediate-IPv6Management {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-Host "[INFO] Starting IPv6 Management remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("IPv6 Management GPO", "Create GPO to disable IPv6 if not required")) {
            $gpoName = "Harden_AD_IPv6Management_Disable"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Disable IPv6 where not required and harden network stack"

            $regPath1 = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $regPath1 -ValueName "DisabledComponents" -Type DWord -Value 0xFF -ErrorAction Stop

            $regPath2 = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6"
            Set-GPRegistryValue -Name $gpoName -Key $regPath2 -ValueName "Start" -Type DWord -Value 4 -ErrorAction Stop

            $regPath3 = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $regPath3 -ValueName "DisableIPSourceRouting" -Type DWord -Value 2 -ErrorAction Stop

            $regPath4 = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $regPath4 -ValueName "EnableICMPRedirect" -Type DWord -Value 0 -ErrorAction Stop

            Write-Host "[Remediation] GPO '$gpoName' created successfully" -ForegroundColor Green
            Write-Host "IPv6 DISABLED and hardened using Group Policy Preferences:" -ForegroundColor Cyan
            Write-Host "  _ $regPath1\DisabledComponents = 0xFF (IPv6 disabled)" -ForegroundColor Cyan
            Write-Host "  _ $regPath2\Start = 4 (service disabled)" -ForegroundColor Cyan
            Write-Host "  _ $regPath3\DisableIPSourceRouting = 2 (drop all)" -ForegroundColor Cyan
            Write-Host "  _ $regPath4\EnableICMPRedirect = 0 (disabled)" -ForegroundColor Cyan
            Write-Host "Note: Restart is required after GPO application for full effect." -ForegroundColor Yellow

            return $gpoName
        }
    }
    catch {
        Write-Host "ERROR during IPv6 Management remediation: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
