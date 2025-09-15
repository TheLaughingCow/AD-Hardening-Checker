function Remediate-UnconstrainedDelegation {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting Unconstrained Delegation remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("Unconstrained Delegation GPO", "Create GPO to disable Unconstrained Delegation")) {
            $gpoName = "Harden_AD_UnconstrainedDelegation_Disable"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Disable Unconstrained Delegation to prevent Kerberoasting attacks"
            
            # Configure registry settings to disable unconstrained delegation
            $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\LanManServer"
            Set-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "RequireSecuritySignature" -Value 1 -Type DWord
            
            # Additional security settings
            $netlogonPath = "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $netlogonPath -ValueName "RequireSignOrSeal" -Value 1 -Type DWord
            
            Write-Host "[Remediation] GPO '$gpoName' created and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Registry settings:" -ForegroundColor Cyan
            Write-Host "  _ $regPath\RequireSecuritySignature = 1" -ForegroundColor Cyan
            Write-Host "  _ $netlogonPath\RequireSignOrSeal = 1" -ForegroundColor Cyan
            Write-Host "Note: This GPO provides additional security. Manual AD cleanup of existing unconstrained delegation accounts is required." -ForegroundColor Yellow
            Write-ADHCLog "Unconstrained Delegation GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during Unconstrained Delegation remediation: $($_.Exception.Message)"
    }
}







