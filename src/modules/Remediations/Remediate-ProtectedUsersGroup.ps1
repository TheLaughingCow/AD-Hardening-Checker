function Remediate-ProtectedUsersGroup {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting Protected Users Group remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("Protected Users Group GPO", "Create GPO with startup script to add sensitive accounts to Protected Users group")) {
            $gpoName = "Harden_AD_ProtectedUsersGroup_Configure"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName -Comment "Configure Protected Users Group via startup script with prerequisite checks"
            
            # Create startup script directory
            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }
            
            # Create the startup script with prerequisite checks
            $startupScript = @"
# Protected Users Group Configuration Script
# This script adds sensitive accounts to the Protected Users group

Write-Host "Configuring Protected Users Group..." -ForegroundColor Green

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrator privileges. Please run as administrator."
    exit 1
}

# Check if we're in a domain environment
`$isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq `$true
if (-not `$isDomainMember) {
    Write-Warning "Protected Users Group is only relevant in domain environments. This computer is not domain-joined."
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

# Check if we have sufficient privileges to modify group memberships
try {
    `$domain = Get-ADDomain -ErrorAction Stop
    Write-Host "Connected to domain: `$(`$domain.DNSRoot)" -ForegroundColor Cyan
} catch {
    Write-Error "Failed to connect to domain: `$(`$_.Exception.Message)"
    exit 1
}

# Define the Protected Users group name (it might have different names in different languages)
`$protectedUsersGroupNames = @(
    "Protected Users",
    "Utilisateurs protégés",
    "Geschützte Benutzer"
)

`$protectedUsersGroup = `$null
foreach (`$groupName in `$protectedUsersGroupNames) {
    try {
        `$group = Get-ADGroup -Identity `$groupName -ErrorAction SilentlyContinue
        if (`$group) {
            `$protectedUsersGroup = `$group
            Write-Host "Found Protected Users group: `$(`$group.Name)" -ForegroundColor Cyan
            break
        }
    } catch {
        # Continue to next group name
    }
}

if (-not `$protectedUsersGroup) {
    Write-Warning "Protected Users group not found."
    Write-Warning "This group may not exist in this domain. Skipping remediation."
    exit 0
}

# Define sensitive groups to check for members
`$sensitiveGroups = @(
    "Domain Admins",
    "Enterprise Admins", 
    "Schema Admins",
    "Administrateurs du domaine",
    "Administrateurs d'entreprise",
    "Administrateurs de schéma",
    "Domänen-Admins",
    "Unternehmens-Admins",
    "Schema-Admins"
)

# Find sensitive accounts
Write-Host "Searching for sensitive accounts..." -ForegroundColor Yellow
`$sensitiveAccounts = @()

foreach (`$groupName in `$sensitiveGroups) {
    try {
        `$group = Get-ADGroup -Identity `$groupName -ErrorAction SilentlyContinue
        if (`$group) {
            Write-Host "Checking group: `$(`$group.Name)" -ForegroundColor Cyan
            `$members = Get-ADGroupMember -Identity `$group.DistinguishedName -ErrorAction SilentlyContinue
            if (`$members) {
                foreach (`$member in `$members) {
                    if (`$member.ObjectClass -eq "user") {
                        `$sensitiveAccounts += `$member
                    }
                }
            }
        }
    } catch {
        Write-Warning "Could not check group `$groupName`: `$(`$_.Exception.Message)"
    }
}

# Remove duplicates
`$sensitiveAccounts = `$sensitiveAccounts | Sort-Object DistinguishedName -Unique

if (`$sensitiveAccounts.Count -eq 0) {
    Write-Host "No sensitive accounts found to add to Protected Users group." -ForegroundColor Yellow
    Write-Host "This might indicate that sensitive groups are empty or not accessible." -ForegroundColor Yellow
    exit 0
}

Write-Host "Found `$(`$sensitiveAccounts.Count) sensitive accounts:" -ForegroundColor Yellow
foreach (`$account in `$sensitiveAccounts) {
    Write-Host "  - `$(`$account.Name) (`$(`$account.SamAccountName))" -ForegroundColor White
}

# Get current members of Protected Users group
try {
    `$currentMembers = Get-ADGroupMember -Identity `$protectedUsersGroup.DistinguishedName -ErrorAction SilentlyContinue
    `$currentMemberSids = if (`$currentMembers) { `$currentMembers.SID } else { @() }
} catch {
    Write-Warning "Could not retrieve current Protected Users group members: `$(`$_.Exception.Message)"
    `$currentMemberSids = @()
}

# Add sensitive accounts to Protected Users group
`$successCount = 0
`$errorCount = 0
`$alreadyMemberCount = 0

foreach (`$account in `$sensitiveAccounts) {
    try {
        # Check if already a member
        if (`$currentMemberSids -contains `$account.SID) {
            Write-Host "✓ Already member: `$(`$account.SamAccountName)" -ForegroundColor Green
            `$alreadyMemberCount++
            continue
        }
        
        Write-Host "Adding to Protected Users: `$(`$account.SamAccountName)..." -ForegroundColor Cyan
        
        # Add to Protected Users group
        Add-ADGroupMember -Identity `$protectedUsersGroup.DistinguishedName -Members `$account.DistinguishedName -ErrorAction Stop
        
        Write-Host "✓ Added to Protected Users: `$(`$account.SamAccountName)" -ForegroundColor Green
        `$successCount++
        
    } catch {
        Write-Warning "Failed to add `$(`$account.SamAccountName) to Protected Users: `$(`$_.Exception.Message)"
        `$errorCount++
    }
}

# Verify the changes
Write-Host "Verifying changes..." -ForegroundColor Yellow
try {
    `$updatedMembers = Get-ADGroupMember -Identity `$protectedUsersGroup.DistinguishedName -ErrorAction SilentlyContinue
    `$updatedMemberCount = if (`$updatedMembers) { `$updatedMembers.Count } else { 0 }
    
    Write-Host "Protected Users group now has `$updatedMemberCount members" -ForegroundColor Cyan
    
    if (`$updatedMembers) {
        Write-Host "Current members:" -ForegroundColor Cyan
        foreach (`$member in `$updatedMembers) {
            Write-Host "  - `$(`$member.Name) (`$(`$member.SamAccountName))" -ForegroundColor White
        }
    }
} catch {
    Write-Warning "Could not verify Protected Users group membership: `$(`$_.Exception.Message)"
}

# Summary
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Successfully added: `$successCount accounts" -ForegroundColor Green
Write-Host "  Already members: `$alreadyMemberCount accounts" -ForegroundColor Yellow
Write-Host "  Failed to add: `$errorCount accounts" -ForegroundColor Red

# Additional security recommendations
Write-Host "Additional security recommendations:" -ForegroundColor Cyan
Write-Host "1. Monitor for attempts to remove accounts from Protected Users group" -ForegroundColor White
Write-Host "2. Implement regular audits of Protected Users group membership" -ForegroundColor White
Write-Host "3. Consider adding service accounts to Protected Users if appropriate" -ForegroundColor White
Write-Host "4. Implement privileged access management (PAM) solutions" -ForegroundColor White
Write-Host "5. Regularly review and update group memberships" -ForegroundColor White

# Log the change
try {
    `$logMessage = "Protected Users Group configured via GPO startup script on `$(`$env:COMPUTERNAME). Added `$successCount accounts."
    Write-EventLog -LogName Application -Source "HardenADCheck" -EventId 1007 -Message `$logMessage -EntryType Information -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Could not log the change to Event Log: `$(`$_.Exception.Message)"
}

Write-Host "Protected Users Group configuration completed." -ForegroundColor Green
"@
            
            $scriptPath = Join-Path $scriptDir "Configure-ProtectedUsersGroup.ps1"
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
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Configure-ProtectedUsersGroup.ps1" -Type String
            
            Write-Host "[Remediation] GPO '$gpoName' created with startup script and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Startup script created: $scriptPath" -ForegroundColor Cyan
            Write-Host "Prerequisites checked: Administrator privileges, domain environment, AD module" -ForegroundColor Cyan
            Write-Host "Note: This GPO uses a startup script. Manual group verification may be required." -ForegroundColor Yellow
            Write-ADHCLog "Protected Users Group GPO with startup script created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during Protected Users Group remediation: $($_.Exception.Message)"
    }
}






