function Remediate-NBTNS {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs","")]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting NBT_NS remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("NBT_NS GPO", "Create GPO to disable NBT_NS")) {
            $gpoName = "Harden_AD_NBTNS_Disable"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Disable NBT_NS to prevent NBT_NS poisoning attacks"
            
            # Configure registry setting for all interfaces
            $regPath = "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "NetbiosOptions" -Value 2 -Type DWord
            
            Write-Host "[Remediation] GPO '$gpoName' created and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Registry setting: $regPath\NetbiosOptions = 2" -ForegroundColor Cyan
            Write-ADHCLog "NBT_NS GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during NBT_NS remediation: $($_.Exception.Message)"
    }
}






