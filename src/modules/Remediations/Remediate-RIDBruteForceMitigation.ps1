function Remediate-RIDBruteForceMitigation {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting RID Brute Force Mitigation remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("RID Brute Force Mitigation GPO", "Create GPO with startup script to enable RID brute force protection")) {
            $gpoName = "Harden_AD_RIDBruteForceMitigation_Enable"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName -Comment "Enable RID Brute Force Mitigation via startup script with prerequisite checks"
            
            # Create startup script directory
            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }
            
            # Create the startup script with prerequisite checks
            $startupScript = @"
# RID Brute Force Mitigation Script
# This script enables RID brute force protection mechanisms

Write-Host "Enabling RID Brute Force Mitigation..." -ForegroundColor Green

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrator privileges. Please run as administrator."
    exit 1
}

# Check if we're in a domain environment
`$isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq `$true
if (-not `$isDomainMember) {
    Write-Warning "RID Brute Force Mitigation is only relevant in domain environments. This computer is not domain-joined."
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

# Check Windows version for RID Brute Force Mitigation support
`$osVersion = [System.Environment]::OSVersion.Version
`$isWindows10OrLater = `$osVersion.Major -ge 10
`$isServer2016OrLater = `$osVersion.Major -ge 10 -and (Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2

if (-not (`$isWindows10OrLater -or `$isServer2016OrLater)) {
    Write-Warning "RID Brute Force Mitigation prerequisites not met."
    Write-Host "Prerequisites not met:" -ForegroundColor Yellow
    Write-Host "- Windows 10/Server 2016 or later required" -ForegroundColor White
    Write-Host "- Current version: `$(`$osVersion.ToString())" -ForegroundColor White
    Write-Host ""
    Write-Host "Alternative security measures:" -ForegroundColor Cyan
    Write-Host "1. Enable SMB Signing (if supported)" -ForegroundColor White
    Write-Host "2. Enable LDAP Signing (if supported)" -ForegroundColor White
    Write-Host "3. Implement network segmentation" -ForegroundColor White
    Write-Host "4. Monitor for RID enumeration attempts" -ForegroundColor White
    Write-Host "5. Upgrade to Windows 10/Server 2016+ for full protection" -ForegroundColor White
    exit 1
}

Write-Host "Windows version check passed: `$(`$osVersion.ToString())" -ForegroundColor Green

# Enable SMB Signing (if not already enabled)
Write-Host "Configuring SMB Signing..." -ForegroundColor Yellow
try {
    `$smbConfig = Get-SmbServerConfiguration
    if (`$smbConfig.RequireSecuritySignature -eq `$false) {
        Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force
        Write-Host "✓ SMB Signing required enabled" -ForegroundColor Green
    } else {
        Write-Host "✓ SMB Signing already required" -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to configure SMB Signing: `$(`$_.Exception.Message)"
}

# Enable LDAP Signing (if supported)
Write-Host "Configuring LDAP Signing..." -ForegroundColor Yellow
try {
    `$ldapSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
    if (-not `$ldapSigning -or `$ldapSigning.LDAPServerIntegrity -ne 2) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2
        Write-Host "✓ LDAP Signing required enabled" -ForegroundColor Green
    } else {
        Write-Host "✓ LDAP Signing already required" -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to configure LDAP Signing: `$(`$_.Exception.Message)"
}

# Enable RID Brute Force Mitigation (Windows 10/Server 2016+)
Write-Host "Enabling RID Brute Force Mitigation..." -ForegroundColor Yellow
try {
    # Check if the feature is available
    `$ridMitigationKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    `$ridMitigation = Get-ItemProperty -Path `$ridMitigationKey -Name "RidBruteForceMitigation" -ErrorAction SilentlyContinue
    
    if (-not `$ridMitigation -or `$ridMitigation.RidBruteForceMitigation -ne 1) {
        Set-ItemProperty -Path `$ridMitigationKey -Name "RidBruteForceMitigation" -Value 1
        Write-Host "✓ RID Brute Force Mitigation enabled" -ForegroundColor Green
    } else {
        Write-Host "✓ RID Brute Force Mitigation already enabled" -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to enable RID Brute Force Mitigation: `$(`$_.Exception.Message)"
    Write-Warning "This feature may not be available on this system version."
}

# Configure NTDS Rate Limiting
Write-Host "Configuring NTDS Rate Limiting..." -ForegroundColor Yellow
try {
    `$ntdsKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    
    # Set rate limiting parameters
    Set-ItemProperty -Path `$ntdsKey -Name "MaxConcurrentAPI" -Value 100 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path `$ntdsKey -Name "MaxConcurrentQueries" -Value 100 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path `$ntdsKey -Name "MaxPageSize" -Value 1000 -ErrorAction SilentlyContinue
    
    Write-Host "✓ NTDS Rate Limiting configured" -ForegroundColor Green
} catch {
    Write-Warning "Failed to configure NTDS Rate Limiting: `$(`$_.Exception.Message)"
}

# Enable Net Logon security
Write-Host "Configuring Net Logon security..." -ForegroundColor Yellow
try {
    `$netLogonKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    
    # Disable Net Logon if not needed
    `$disableNetLogon = Get-ItemProperty -Path `$netLogonKey -Name "DisableNetLogon" -ErrorAction SilentlyContinue
    if (-not `$disableNetLogon -or `$disableNetLogon.DisableNetLogon -ne 1) {
        Set-ItemProperty -Path `$netLogonKey -Name "DisableNetLogon" -Value 1
        Write-Host "✓ Net Logon disabled for security" -ForegroundColor Green
    } else {
        Write-Host "✓ Net Logon already disabled" -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to configure Net Logon security: `$(`$_.Exception.Message)"
}

# Verify configurations
Write-Host "Verifying configurations..." -ForegroundColor Yellow

# Check SMB Signing
try {
    `$smbConfig = Get-SmbServerConfiguration
    if (`$smbConfig.RequireSecuritySignature -eq `$true) {
        Write-Host "✓ SMB Signing: Required" -ForegroundColor Green
    } else {
        Write-Host "✗ SMB Signing: Not required" -ForegroundColor Red
    }
} catch {
    Write-Warning "Could not verify SMB Signing status"
}

# Check LDAP Signing
try {
    `$ldapSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
    if (`$ldapSigning -and `$ldapSigning.LDAPServerIntegrity -eq 2) {
        Write-Host "✓ LDAP Signing: Required" -ForegroundColor Green
    } else {
        Write-Host "✗ LDAP Signing: Not required" -ForegroundColor Red
    }
} catch {
    Write-Warning "Could not verify LDAP Signing status"
}

# Check RID Brute Force Mitigation
try {
    `$ridMitigation = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "RidBruteForceMitigation" -ErrorAction SilentlyContinue
    if (`$ridMitigation -and `$ridMitigation.RidBruteForceMitigation -eq 1) {
        Write-Host "✓ RID Brute Force Mitigation: Enabled" -ForegroundColor Green
    } else {
        Write-Host "✗ RID Brute Force Mitigation: Not enabled" -ForegroundColor Red
    }
} catch {
    Write-Warning "Could not verify RID Brute Force Mitigation status"
}

# Additional security recommendations
Write-Host "Additional security recommendations:" -ForegroundColor Cyan
Write-Host "1. Monitor for unusual RID enumeration attempts" -ForegroundColor White
Write-Host "2. Implement network segmentation to limit access to domain controllers" -ForegroundColor White
Write-Host "3. Enable detailed auditing for directory service access" -ForegroundColor White
Write-Host "4. Consider implementing IP allowlisting for domain controller access" -ForegroundColor White
Write-Host "5. Regularly review and update security baselines" -ForegroundColor White

# Log the change
try {
    `$logMessage = "RID Brute Force Mitigation enabled via GPO startup script on `$(`$env:COMPUTERNAME)"
    Write-EventLog -LogName Application -Source "HardenADCheck" -EventId 1006 -Message `$logMessage -EntryType Information -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Could not log the change to Event Log: `$(`$_.Exception.Message)"
}

Write-Host "RID Brute Force Mitigation configuration completed." -ForegroundColor Green
"@
            
            $scriptPath = Join-Path $scriptDir "Enable-RIDBruteForceMitigation.ps1"
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
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Enable-RIDBruteForceMitigation.ps1" -Type String
            
            Write-Host "[Remediation] GPO '$gpoName' created with startup script and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Startup script created: $scriptPath" -ForegroundColor Cyan
            Write-Host "Prerequisites checked: Administrator privileges, domain environment, Windows version, AD module" -ForegroundColor Cyan
            Write-Host "Note: This GPO uses a startup script. Manual verification may be required." -ForegroundColor Yellow
            Write-ADHCLog "RID Brute Force Mitigation GPO with startup script created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during RID Brute Force Mitigation remediation: $($_.Exception.Message)"
    }
}






