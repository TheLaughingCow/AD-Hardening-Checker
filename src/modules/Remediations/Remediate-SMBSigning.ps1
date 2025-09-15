function Remediate-SMBSigning {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting SMB Signing remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("SMB Signing GPO", "Create GPO to enable SMB Signing")) {
            $gpoName = "Harden_AD_SMBSigning_Enable"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Enable SMB Signing to prevent man_in_the_middle attacks"
            
            # Configure SMB signing registry settings
            $regPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "RequireSecuritySignature" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "EnableSecuritySignature" -Value 1 -Type DWord
            
            Write-Host "[Remediation] GPO '$gpoName' created and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Registry settings:" -ForegroundColor Cyan
            Write-Host "  _ $regPath\RequireSecuritySignature = 1" -ForegroundColor Cyan
            Write-Host "  _ $regPath\EnableSecuritySignature = 1" -ForegroundColor Cyan
            Write-ADHCLog "SMB Signing GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during SMB Signing remediation: $($_.Exception.Message)"
    }
}







