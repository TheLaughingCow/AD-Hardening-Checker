function Remediate-KerberosPreAuth {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting Kerberos Pre-Authentication remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("Kerberos Pre-Authentication GPO", "Create GPO with startup script to enforce Kerberos pre-auth")) {
            $gpoName = "Harden_AD_KerberosPreAuth_Enforce"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName -Comment "Enforce Kerberos Pre-Authentication via startup script with prerequisite checks"
            
            # Create startup script directory
            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }
            
            # Create the startup script with prerequisite checks
            $startupScript = @"
# Kerberos Pre-Authentication Enforcement Script
# This script enforces Kerberos pre-authentication for all user accounts

Write-Host "Enforcing Kerberos Pre-Authentication..." -ForegroundColor Green

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrator privileges. Please run as administrator."
    exit 1
}

# Check if we're in a domain environment
`$isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq `$true
if (-not `$isDomainMember) {
    Write-Warning "Kerberos Pre-Authentication is only relevant in domain environments. This computer is not domain-joined."
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

# Find accounts without Kerberos pre-authentication
Write-Host "Searching for accounts without Kerberos pre-authentication..." -ForegroundColor Yellow

try {
    # Search for accounts with DONT_REQ_PREAUTH flag (0x400000)
    `$accountsWithoutPreAuth = Get-ADUser -Filter "userAccountControl -band 0x400000" -Properties userAccountControl, SamAccountName, DisplayName -ErrorAction Stop
    
    if (-not `$accountsWithoutPreAuth -or `$accountsWithoutPreAuth.Count -eq 0) {
        Write-Host "✓ All accounts already require Kerberos pre-authentication" -ForegroundColor Green
        exit 0
    }
    
    Write-Host "Found `$(`$accountsWithoutPreAuth.Count) accounts without Kerberos pre-authentication:" -ForegroundColor Yellow
    foreach (`$account in `$accountsWithoutPreAuth) {
        Write-Host "  - `$(`$account.SamAccountName) (`$(`$account.DisplayName))" -ForegroundColor White
    }
    
} catch {
    Write-Error "Failed to search for accounts without pre-authentication: `$(`$_.Exception.Message)"
    exit 1
}

# Process each account
`$successCount = 0
`$errorCount = 0

foreach (`$account in `$accountsWithoutPreAuth) {
    try {
        Write-Host "Processing account: `$(`$account.SamAccountName)..." -ForegroundColor Cyan
        
        # Remove the DONT_REQ_PREAUTH flag (0x400000)
        `$newUAC = `$account.userAccountControl -band (-bnot 0x400000)
        
        # Update the account
        Set-ADUser -Identity `$account.SamAccountName -Replace @{userAccountControl = `$newUAC} -ErrorAction Stop
        
        Write-Host "✓ Enabled Kerberos pre-authentication for: `$(`$account.SamAccountName)" -ForegroundColor Green
        `$successCount++
        
    } catch {
        Write-Warning "Failed to update `$(`$account.SamAccountName): `$(`$_.Exception.Message)"
        `$errorCount++
    }
}

# Verify the changes
Write-Host "Verifying changes..." -ForegroundColor Yellow
try {
    `$remainingAccounts = Get-ADUser -Filter "userAccountControl -band 0x400000" -Properties userAccountControl, SamAccountName -ErrorAction SilentlyContinue
    `$remainingCount = if (`$remainingAccounts) { `$remainingAccounts.Count } else { 0 }
    
    if (`$remainingCount -eq 0) {
        Write-Host "✓ All accounts now require Kerberos pre-authentication" -ForegroundColor Green
    } else {
        Write-Warning "`$remainingCount accounts still do not require pre-authentication:"
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
Write-Host "1. Monitor for new accounts that might be created without pre-authentication" -ForegroundColor White
Write-Host "2. Implement account creation policies to prevent this in the future" -ForegroundColor White
Write-Host "3. Consider implementing AS-REP roasting detection" -ForegroundColor White
Write-Host "4. Regularly audit user account settings" -ForegroundColor White

# Log the change
try {
    `$logMessage = "Kerberos Pre-Authentication enforced via GPO startup script on `$(`$env:COMPUTERNAME). Updated `$successCount accounts."
    Write-EventLog -LogName Application -Source "HardenADCheck" -EventId 1004 -Message `$logMessage -EntryType Information -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Could not log the change to Event Log: `$(`$_.Exception.Message)"
}

Write-Host "Kerberos Pre-Authentication enforcement completed." -ForegroundColor Green
"@
            
            $scriptPath = Join-Path $scriptDir "Enforce-KerberosPreAuth.ps1"
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
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Enforce-KerberosPreAuth.ps1" -Type String
            
            Write-Host "[Remediation] GPO '$gpoName' created with startup script and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Startup script created: $scriptPath" -ForegroundColor Cyan
            Write-Host "Prerequisites checked: Administrator privileges, domain environment, AD module" -ForegroundColor Cyan
            Write-Host "Note: This GPO uses a startup script. Manual account verification may be required." -ForegroundColor Yellow
            Write-ADHCLog "Kerberos Pre-Authentication GPO with startup script created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during Kerberos Pre-Authentication remediation: $($_.Exception.Message)"
    }
}






