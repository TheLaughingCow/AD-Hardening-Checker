function Remediate-IPv6Management {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting IPv6 Management remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("IPv6 Management GPO", "Create GPO to properly configure IPv6")) {
            $gpoName = "Harden_AD_IPv6Management_Configure"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Configure IPv6 properly for Active Directory compatibility"
            
            # Configure IPv6 registry settings
            $ipv6Path = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $ipv6Path -ValueName "DisabledComponents" -Value 0 -Type DWord
            
            # Configure IPv6 service startup
            $tcpip6ServicePath = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6"
            Set-GPRegistryValue -Name $gpoName -Key $tcpip6ServicePath -ValueName "Start" -Value 3 -Type DWord
            
            # Additional IPv6 security settings
            $ipv6SecurityPath = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $ipv6SecurityPath -ValueName "DisableIPSourceRouting" -Value 2 -Type DWord
            
            Write-Host "[Remediation] GPO '$gpoName' created and exported to: $gpoName" -ForegroundColor Green
            Write-Host "IPv6 settings:" -ForegroundColor Cyan
            Write-Host "  _ $ipv6Path\DisabledComponents = 0 (enabled)" -ForegroundColor Cyan
            Write-Host "  _ $tcpip6ServicePath\Start = 3 (manual)" -ForegroundColor Cyan
            Write-Host "  _ $ipv6SecurityPath\DisableIPSourceRouting = 2 (drop all)" -ForegroundColor Cyan
            Write-Host "Note: IPv6 is required for Active Directory. Restart recommended after GPO application." -ForegroundColor Yellow
            Write-ADHCLog "IPv6 Management GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during IPv6 Management remediation: $($_.Exception.Message)"
    }
}







