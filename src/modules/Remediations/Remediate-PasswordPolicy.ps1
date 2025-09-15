function Remediate-PasswordPolicy {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting Password Policy remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("Password Policy GPO", "Create GPO to strengthen password policy")) {
            $gpoName = "Harden_AD_PasswordPolicy_Strengthen"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Strengthen password policy for enhanced security"
            
            # Configure password policy registry settings
            $policyPath = "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $policyPath -ValueName "MinPasswordLength" -Value 12 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $policyPath -ValueName "MaxPasswordAge" -Value 90 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $policyPath -ValueName "MinPasswordAge" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $policyPath -ValueName "PasswordComplexity" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $policyPath -ValueName "PasswordHistoryLength" -Value 12 -Type DWord
            
            # Additional account lockout settings
            $lockoutPath = "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $lockoutPath -ValueName "LockoutBadCount" -Value 5 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $lockoutPath -ValueName "LockoutDuration" -Value 30 -Type DWord
            
            Write-Host "[Remediation] GPO '$gpoName' created and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Password policy settings:" -ForegroundColor Cyan
            Write-Host "  _ MinPasswordLength = 12" -ForegroundColor Cyan
            Write-Host "  _ MaxPasswordAge = 90 days" -ForegroundColor Cyan
            Write-Host "  _ MinPasswordAge = 1 day" -ForegroundColor Cyan
            Write-Host "  _ PasswordComplexity = 1 (enabled)" -ForegroundColor Cyan
            Write-Host "  _ PasswordHistoryLength = 12" -ForegroundColor Cyan
            Write-Host "  _ LockoutBadCount = 5" -ForegroundColor Cyan
            Write-Host "  _ LockoutDuration = 30 minutes" -ForegroundColor Cyan
            Write-Host "Note: This GPO sets registry values. Domain_level password policy should also be configured." -ForegroundColor Yellow
            Write-ADHCLog "Password Policy GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during Password Policy remediation: $($_.Exception.Message)"
    }
}







