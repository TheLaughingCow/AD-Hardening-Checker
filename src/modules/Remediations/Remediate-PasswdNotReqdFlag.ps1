function Remediate-PasswdNotReqdFlag {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting PasswdNotReqd Flag remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("PasswdNotReqd Flag GPO", "Create GPO with startup script to remove PASSWD_NOTREQD flag")) {
            $gpoName = "Harden_AD_PasswdNotReqdFlag_Enforce"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName -Comment "Remove PASSWD_NOTREQD flag via startup script with prerequisite checks"
            
            # Create startup script directory
            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }
            
            # Create the startup script with prerequisite checks
            $startupScript = @"
# PASSWD_NOTREQD Flag Removal Script
# This script removes the PASSWD_NOTREQD flag from all user accounts

Write-Host "Removing PASSWD_NOTREQD flag from user accounts..." -ForegroundColor Green

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrator privileges. Please run as administrator."
    exit 1
}

# Check if we're in a domain environment
`$isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq `$true
if (-not `$isDomainMember) {
    Write-Warning "PASSWD_NOTREQD flag is only relevant in domain environments. This computer is not domain-joined."
    exit 1
}

# Check if Active Directory module is available
if (-not (Get-Module -Name "ActiveDirectory" -ListAvailable)) {
    Write-Warning "Active Directory module not found. Installing RSAT-AD-PowerShell..."
    try {
        Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeManagementTools
        Import-Module -Name "ActiveDirectory"
    } catch {
        Write-Error "Failed to install Active Directory module: `$(`$_.Exception.Message)"
        exit 1
    }
} else {
    Import-Module -Name "ActiveDirectory"
}

# Check if we have sufficient privileges to modify user accounts
try {
    `$domain = Get-ADDomain -ErrorAction Stop
    Write-Host "Connected to domain: `$(`$domain.DNSRoot)" -ForegroundColor Cyan
} catch {
    Write-Error "Failed to connect to domain: `$(`$_.Exception.Message)"
    exit 1
}

# Find accounts with PASSWD_NOTREQD flag
Write-Host "Searching for accounts with PASSWD_NOTREQD flag..." -ForegroundColor Yellow

try {
    # Search for accounts with PASSWD_NOTREQD flag (0x0020)
    `$accountsWithFlag = Get-ADUser -Filter "userAccountControl -band 0x0020" -Properties userAccountControl, SamAccountName, DisplayName -ErrorAction Stop
    
    if (-not `$accountsWithFlag -or `$accountsWithFlag.Count -eq 0) {
        Write-Host "✓ No accounts found with PASSWD_NOTREQD flag" -ForegroundColor Green
        exit 0
    }
    
    Write-Host "Found `$(`$accountsWithFlag.Count) accounts with PASSWD_NOTREQD flag:" -ForegroundColor Yellow
    foreach (`$account in `$accountsWithFlag) {
        Write-Host "  - `$(`$account.SamAccountName) (`$(`$account.DisplayName))" -ForegroundColor White
    }
    
} catch {
    Write-Error "Failed to search for accounts with PASSWD_NOTREQD flag: `$(`$_.Exception.Message)"
    exit 1
}

# Process each account
`$successCount = 0
`$errorCount = 0

foreach (`$account in `$accountsWithFlag) {
    try {
        Write-Host "Processing account: `$(`$account.SamAccountName)..." -ForegroundColor Cyan
        
        # Remove the PASSWD_NOTREQD flag (0x0020)
        `$newUAC = `$account.userAccountControl -band (-bnot 0x0020)
        
        # Update the account
        Set-ADUser -Identity `$account.SamAccountName -Replace @{userAccountControl = `$newUAC} -ErrorAction Stop
        
        Write-Host "✓ Removed PASSWD_NOTREQD flag from: `$(`$account.SamAccountName)" -ForegroundColor Green
        `$successCount++
        
    } catch {
        Write-Warning "Failed to update `$(`$account.SamAccountName): `$(`$_.Exception.Message)"
        `$errorCount++
    }
}

# Verify the changes
Write-Host "Verifying changes..." -ForegroundColor Yellow
try {
    `$remainingAccounts = Get-ADUser -Filter "userAccountControl -band 0x0020" -Properties userAccountControl, SamAccountName -ErrorAction SilentlyContinue
    `$remainingCount = if (`$remainingAccounts) { `$remainingAccounts.Count } else { 0 }
    
    if (`$remainingCount -eq 0) {
        Write-Host "✓ All accounts now require passwords" -ForegroundColor Green
    } else {
        Write-Warning "`$remainingCount accounts still have PASSWD_NOTREQD flag:"
        foreach (`$account in `$remainingAccounts) {
            Write-Warning "  - `$(`$account.SamAccountName)"
        }
    }
} catch {
    Write-Warning "Could not verify changes: `$(`$_.Exception.Message)"
}

# Summary
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Successfully updated: `$successCount accounts" -ForegroundColor Green
Write-Host "  Failed to update: `$errorCount accounts" -ForegroundColor Red

# Additional security recommendations
Write-Host "Additional security recommendations:" -ForegroundColor Cyan
Write-Host "1. Monitor for new accounts that might be created without password requirements" -ForegroundColor White
Write-Host "2. Implement strong password policies via Group Policy" -ForegroundColor White
Write-Host "3. Consider implementing account lockout policies" -ForegroundColor White
Write-Host "4. Regularly audit user account settings and password policies" -ForegroundColor White
Write-Host "5. Implement multi-factor authentication where possible" -ForegroundColor White

# Log the change
try {
    `$logMessage = "PASSWD_NOTREQD flag removed via GPO startup script on `$(`$env:COMPUTERNAME). Updated `$successCount accounts."
    Write-EventLog -LogName Application -Source "HardenADCheck" -EventId 1005 -Message `$logMessage -EntryType Information -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Could not log the change to Event Log: `$(`$_.Exception.Message)"
}

Write-Host "PASSWD_NOTREQD flag removal completed." -ForegroundColor Green
"@
            
            $scriptPath = Join-Path $scriptDir "Remove-PasswdNotReqdFlag.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8
            
            # Configure GPO to run the startup script
            $gpoPath = "\\$env:COMPUTERNAME\SYSVOL\$env:USERDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoPath)) {
                New-Item -ItemType Directory -Path $gpoPath -Force | Out-Null
            }
            
            # Copy script to GPO directory
            Copy-Item -Path $scriptPath -Destination $gpoPath -Force
            
            # Configure startup script in GPO
            $scriptGpoPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Remove-PasswdNotReqdFlag.ps1" -Type String
            
            Write-Host "[Remediation] GPO '$gpoName' created with startup script and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Startup script created: $scriptPath" -ForegroundColor Cyan
            Write-Host "Prerequisites checked: Administrator privileges, domain environment, AD module" -ForegroundColor Cyan
            Write-Host "Note: This GPO uses a startup script. Manual account verification may be required." -ForegroundColor Yellow
            Write-ADHCLog "PasswdNotReqd Flag GPO with startup script created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during PasswdNotReqd Flag remediation: $($_.Exception.Message)"
    }
}






