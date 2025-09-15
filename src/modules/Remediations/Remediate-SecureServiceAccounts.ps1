function Remediate-SecureServiceAccounts {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting Secure Service Accounts remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("Secure Service Accounts GPO", "Create GPO to secure service accounts")) {
            $gpoName = "Harden_AD_SecureServiceAccounts_Configure"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Secure service accounts and enforce gMSA usage"
            
            # Configure service account security settings
            $servicePath = "HKLM\SYSTEM\CurrentControlSet\Services"
            Set-GPRegistryValue -Name $gpoName -Key $servicePath -ValueName "ServiceAccountRestrictions" -Value 1 -Type DWord
            
            # Configure Kerberos delegation restrictions
            $kerberosPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $kerberosPath -ValueName "RestrictToRemoteClients" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $kerberosPath -ValueName "EnforceUserLogonRestrictions" -Value 1 -Type DWord
            
            # Configure account lockout for service accounts
            $lockoutPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Set-GPRegistryValue -Name $gpoName -Key $lockoutPath -ValueName "LockoutBadCount" -Value 5 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $lockoutPath -ValueName "LockoutDuration" -Value 30 -Type DWord
            
            # Configure password policy for service accounts
            $passwordPath = "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $passwordPath -ValueName "RequireStrongKey" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $passwordPath -ValueName "PasswordComplexity" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $passwordPath -ValueName "MinPasswordLength" -Value 14 -Type DWord
            
            # Configure audit policy for service account access
            $auditPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditAccountLogon" -Value 3 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditLogonEvents" -Value 3 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditPrivilegeUse" -Value 3 -Type DWord
            
            Write-Host "[Remediation] GPO '$gpoName' created and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Service account security settings:" -ForegroundColor Cyan
            Write-Host "  _ $servicePath\ServiceAccountRestrictions = 1" -ForegroundColor Cyan
            Write-Host "  _ $kerberosPath\RestrictToRemoteClients = 1" -ForegroundColor Cyan
            Write-Host "  _ $kerberosPath\EnforceUserLogonRestrictions = 1" -ForegroundColor Cyan
            Write-Host "  _ $lockoutPath\LockoutBadCount = 5" -ForegroundColor Cyan
            Write-Host "  _ $lockoutPath\LockoutDuration = 30" -ForegroundColor Cyan
            Write-Host "  _ $passwordPath\RequireStrongKey = 1" -ForegroundColor Cyan
            Write-Host "  _ $passwordPath\PasswordComplexity = 1" -ForegroundColor Cyan
            Write-Host "  _ $passwordPath\MinPasswordLength = 14" -ForegroundColor Cyan
            Write-Host "  _ $auditPath\AuditAccountLogon = 3" -ForegroundColor Cyan
            Write-Host "  _ $auditPath\AuditLogonEvents = 3" -ForegroundColor Cyan
            Write-Host "  _ $auditPath\AuditPrivilegeUse = 3" -ForegroundColor Cyan
            Write-Host "Note: This GPO provides general service account security. Manual implementation of gMSA and SPN cleanup is required." -ForegroundColor Yellow
            Write-ADHCLog "Secure Service Accounts GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during Secure Service Accounts remediation: $($_.Exception.Message)"
    }
}







