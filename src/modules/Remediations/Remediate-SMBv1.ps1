function Remediate-SMBv1 {
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

    Write-ADHCLog "Starting SMBv1 remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("SMBv1 GPO", "Create GPO to disable SMBv1")) {
            $gpoName = "Harden_AD_SMBv1_Disable"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Disable SMBv1 protocol to prevent EternalBlue attacks"
            
            # Configure SMBv1 disable registry settings
            $regPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "SMB1" -Value 0 -Type DWord
            
            # Additional SMBv1 disable settings
            $smbClientPath = "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10"
            Set-GPRegistryValue -Name $gpoName -Key $smbClientPath -ValueName "Start" -Value 4 -Type DWord
            
            Write-Host "[Remediation] GPO '$gpoName' created and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Registry settings:" -ForegroundColor Cyan
            Write-Host "  _ $regPath\SMB1 = 0" -ForegroundColor Cyan
            Write-Host "  _ $smbClientPath\Start = 4 (Disabled)" -ForegroundColor Cyan
            Write-Host "WARNING: Ensure all clients support SMBv2/v3 before applying this GPO" -ForegroundColor Yellow
            Write-ADHCLog "SMBv1 GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during SMBv1 remediation: $($_.Exception.Message)"
    }
}






