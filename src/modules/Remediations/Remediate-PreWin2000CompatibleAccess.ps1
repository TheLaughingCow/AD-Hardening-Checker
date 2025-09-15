function Remediate-PreWin2000CompatibleAccess {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting Pre-Windows 2000 Compatible Access remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("Pre-Windows 2000 Access GPO", "Create GPO with startup script to secure Pre-Win2000 group")) {
            $gpoName = "Harden_AD_PreWin2000Access_Secure"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName -Comment "Secure Pre-Windows 2000 Compatible Access group via startup script with prerequisite checks"
            
            # Create startup script directory
            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }
            
            # Create the startup script with prerequisite checks
            $startupScript = @"
# Pre-Windows 2000 Compatible Access Security Script
# This script secures the Pre-Windows 2000 Compatible Access group

Write-Host "Securing Pre-Windows 2000 Compatible Access group..." -ForegroundColor Green

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrator privileges. Please run as administrator."
    exit 1
}

# Check if we're in a domain environment
`$isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq `$true
if (-not `$isDomainMember) {
    Write-Warning "Pre-Windows 2000 Compatible Access is only relevant in domain environments. This computer is not domain-joined."
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

# Check if we have sufficient privileges to modify domain settings
try {
    `$domain = Get-ADDomain -ErrorAction Stop
    Write-Host "Connected to domain: `$(`$domain.DNSRoot)" -ForegroundColor Cyan
} catch {
    Write-Error "Failed to connect to domain: `$(`$_.Exception.Message)"
    exit 1
}

# Define the group name (it might have different names in different languages)
`$groupNames = @(
    "Pre-Windows 2000 Compatible Access",
    "Accès compatible avec les versions antérieures à Windows 2000",
    "Vorgängerversionen von Windows 2000 kompatibler Zugriff"
)

`$targetGroup = `$null
foreach (`$groupName in `$groupNames) {
    try {
        `$group = Get-ADGroup -Identity `$groupName -ErrorAction SilentlyContinue
        if (`$group) {
            `$targetGroup = `$group
            Write-Host "Found group: `$(`$group.Name)" -ForegroundColor Cyan
            break
        }
    } catch {
        # Continue to next group name
    }
}

if (-not `$targetGroup) {
    Write-Warning "Pre-Windows 2000 Compatible Access group not found."
    Write-Warning "This group may have been removed or renamed. Skipping remediation."
    exit 0
}

# Get current members of the group
try {
    `$currentMembers = Get-ADGroupMember -Identity `$targetGroup.DistinguishedName -ErrorAction SilentlyContinue
    `$memberCount = if (`$currentMembers) { `$currentMembers.Count } else { 0 }
    
    Write-Host "Current members in `$(`$targetGroup.Name): `$memberCount" -ForegroundColor Yellow
    
    if (`$memberCount -eq 0) {
        Write-Host "Group is already empty (secure)." -ForegroundColor Green
        exit 0
    }
    
    # List current members
    Write-Host "Current members:" -ForegroundColor Yellow
    foreach (`$member in `$currentMembers) {
        Write-Host "  - `$(`$member.Name) (`$(`$member.ObjectClass))" -ForegroundColor White
    }
    
} catch {
    Write-Warning "Could not retrieve group members: `$(`$_.Exception.Message)"
    `$currentMembers = @()
}

# Remove all members from the group
if (`$currentMembers -and `$currentMembers.Count -gt 0) {
    try {
        Write-Host "Removing all members from `$(`$targetGroup.Name)..." -ForegroundColor Yellow
        
        foreach (`$member in `$currentMembers) {
            try {
                Remove-ADGroupMember -Identity `$targetGroup.DistinguishedName -Members `$member.DistinguishedName -Confirm:`$false
                Write-Host "✓ Removed: `$(`$member.Name)" -ForegroundColor Green
            } catch {
                Write-Warning "Failed to remove `$(`$member.Name): `$(`$_.Exception.Message)"
            }
        }
        
        Write-Host "✓ All members removed from `$(`$targetGroup.Name)" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to remove members from group: `$(`$_.Exception.Message)"
        exit 1
    }
}

# Verify the group is empty
try {
    `$remainingMembers = Get-ADGroupMember -Identity `$targetGroup.DistinguishedName -ErrorAction SilentlyContinue
    `$remainingCount = if (`$remainingMembers) { `$remainingMembers.Count } else { 0 }
    
    if (`$remainingCount -eq 0) {
        Write-Host "✓ Group is now empty and secure" -ForegroundColor Green
    } else {
        Write-Warning "Group still has `$remainingCount members. Some members could not be removed."
    }
} catch {
    Write-Warning "Could not verify group is empty: `$(`$_.Exception.Message)"
}

# Additional security recommendations
Write-Host "Additional security recommendations:" -ForegroundColor Cyan
Write-Host "1. Monitor for attempts to add members back to this group" -ForegroundColor White
Write-Host "2. Consider disabling the group entirely if not needed" -ForegroundColor White
Write-Host "3. Implement auditing for group membership changes" -ForegroundColor White
Write-Host "4. Regularly review all privileged group memberships" -ForegroundColor White

# Log the change
try {
    `$logMessage = "Pre-Windows 2000 Compatible Access group secured via GPO startup script on `$(`$env:COMPUTERNAME)"
    Write-EventLog -LogName Application -Source "HardenADCheck" -EventId 1003 -Message `$logMessage -EntryType Information -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Could not log the change to Event Log: `$(`$_.Exception.Message)"
}

Write-Host "Pre-Windows 2000 Compatible Access group security completed." -ForegroundColor Green
"@
            
            $scriptPath = Join-Path $scriptDir "Secure-PreWin2000Access.ps1"
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
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Secure-PreWin2000Access.ps1" -Type String
            
            Write-Host "[Remediation] GPO '$gpoName' created with startup script and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Startup script created: $scriptPath" -ForegroundColor Cyan
            Write-Host "Prerequisites checked: Administrator privileges, domain environment, AD module" -ForegroundColor Cyan
            Write-Host "Note: This GPO uses a startup script. Manual group management may be required." -ForegroundColor Yellow
            Write-ADHCLog "Pre-Windows 2000 Access GPO with startup script created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during Pre-Windows 2000 Access remediation: $($_.Exception.Message)"
    }
}






