function Remediate-DefaultCredentials {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting Default Credentials remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("Default Credentials GPO", "Create GPO to secure default credentials")) {
            $gpoName = "Harden_AD_DefaultCredentials_Secure"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Secure default credentials and enforce password requirements"
            
            # Configure user rights assignments to deny logon for default accounts
            $userRightsPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Set-GPRegistryValue -Name $gpoName -Key $userRightsPath -ValueName "SeDenyInteractiveLogonRight" -Value "Administrator,Guest,Test,SA" -Type String
            
            # Configure password policy to enforce strong passwords
            $passwordPath = "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $passwordPath -ValueName "RequireStrongKey" -Value 1 -Type DWord
            
            # Configure account lockout policy
            $lockoutPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Set-GPRegistryValue -Name $gpoName -Key $lockoutPath -ValueName "LockoutBadCount" -Value 5 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $lockoutPath -ValueName "LockoutDuration" -Value 30 -Type DWord
            
            Write-Host "[Remediation] GPO '$gpoName' created and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Default credentials security settings:" -ForegroundColor Cyan
            Write-Host "  _ $userRightsPath\SeDenyInteractiveLogonRight = Administrator,Guest,Test,SA" -ForegroundColor Cyan
            Write-Host "  _ $passwordPath\RequireStrongKey = 1" -ForegroundColor Cyan
            Write-Host "  _ $lockoutPath\LockoutBadCount = 5" -ForegroundColor Cyan
            Write-Host "  _ $lockoutPath\LockoutDuration = 30" -ForegroundColor Cyan
            Write-Host "Note: This GPO provides general security. Manual review of service accounts and local users is required." -ForegroundColor Yellow
            Write-ADHCLog "Default Credentials GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during Default Credentials remediation: $($_.Exception.Message)"
    }
}







