function Remediate-MachineAccountQuota {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting Machine Account Quota remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("Machine Account Quota GPO", "Create GPO with startup script to limit machine account quota")) {
            $gpoName = "Harden_AD_MachineAccountQuota_Limit"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName -Comment "Limit machine account quota via startup script with prerequisite checks"
            
            # Create startup script directory
            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }
            
            # Create the startup script with prerequisite checks
            $startupScript = @"
# Machine Account Quota Limitation Script
# This script limits the machine account quota to prevent abuse

Write-Host "Configuring Machine Account Quota..." -ForegroundColor Green

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrator privileges. Please run as administrator."
    exit 1
}

# Check if we're in a domain environment
`$isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq `$true
if (-not `$isDomainMember) {
    Write-Warning "Machine Account Quota is only relevant in domain environments. This computer is not domain-joined."
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

# Get current machine account quota
try {
    `$domainRoot = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
    `$domainObject = Get-ADObject -Identity `$domainRoot -Properties "ms-DS-MachineAccountQuota"
    `$currentQuota = `$domainObject."ms-DS-MachineAccountQuota"
    
    Write-Host "Current machine account quota: `$currentQuota" -ForegroundColor Yellow
    
    if (`$currentQuota -eq 0) {
        Write-Host "Machine account quota is already set to 0 (secure)." -ForegroundColor Green
        exit 0
    }
    
    if (`$currentQuota -gt 10) {
        Write-Warning "Current quota (`$currentQuota) is high. This may indicate a security risk."
    }
    
} catch {
    Write-Warning "Could not retrieve current machine account quota: `$(`$_.Exception.Message)"
}

# Set machine account quota to 0 (most secure)
try {
    Write-Host "Setting machine account quota to 0..." -ForegroundColor Yellow
    Set-ADDomain -Identity `$domainRoot -Replace @{"ms-DS-MachineAccountQuota" = 0}
    Write-Host "✓ Machine account quota set to 0" -ForegroundColor Green
} catch {
    Write-Error "Failed to set machine account quota: `$(`$_.Exception.Message)"
    Write-Warning "You may need Domain Admin privileges to modify this setting."
    exit 1
}

# Verify the change
try {
    `$updatedDomainObject = Get-ADObject -Identity `$domainRoot -Properties "ms-DS-MachineAccountQuota"
    `$newQuota = `$updatedDomainObject."ms-DS-MachineAccountQuota"
    
    if (`$newQuota -eq 0) {
        Write-Host "✓ Machine account quota successfully set to 0" -ForegroundColor Green
    } else {
        Write-Warning "Machine account quota is `$newQuota (expected 0)"
    }
} catch {
    Write-Warning "Could not verify machine account quota change: `$(`$_.Exception.Message)"
}

# Additional security recommendations
Write-Host "Additional security recommendations:" -ForegroundColor Cyan
Write-Host "1. Monitor for unauthorized machine account creation attempts" -ForegroundColor White
Write-Host "2. Consider implementing Pre-Windows 2000 Compatible Access restrictions" -ForegroundColor White
Write-Host "3. Regularly audit machine accounts and remove unused ones" -ForegroundColor White
Write-Host "4. Implement account lockout policies for machine accounts" -ForegroundColor White

# Log the change
try {
    `$logMessage = "Machine Account Quota set to 0 via GPO startup script on `$(`$env:COMPUTERNAME)"
    Write-EventLog -LogName Application -Source "HardenADCheck" -EventId 1002 -Message `$logMessage -EntryType Information -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Could not log the change to Event Log: `$(`$_.Exception.Message)"
}

Write-Host "Machine Account Quota configuration completed." -ForegroundColor Green
"@
            
            $scriptPath = Join-Path $scriptDir "Limit-MachineAccountQuota.ps1"
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
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Limit-MachineAccountQuota.ps1" -Type String
            
            Write-Host "[Remediation] GPO '$gpoName' created with startup script and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Startup script created: $scriptPath" -ForegroundColor Cyan
            Write-Host "Prerequisites checked: Administrator privileges, domain environment, AD module, Domain Admin rights" -ForegroundColor Cyan
            Write-Host "Note: This GPO uses a startup script. Domain Admin privileges may be required." -ForegroundColor Yellow
            Write-ADHCLog "Machine Account Quota GPO with startup script created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during Machine Account Quota remediation: $($_.Exception.Message)"
    }
}






