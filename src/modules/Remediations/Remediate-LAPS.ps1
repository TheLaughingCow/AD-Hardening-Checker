function Remediate-LAPS {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting LAPS remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("LAPS GPO", "Create GPO with startup script to install and configure LAPS")) {
            $gpoName = "Harden_AD_LAPS_Configure"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName -Comment "Install and configure LAPS via startup script with prerequisite checks"
            
            # Create startup script directory
            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }
            
            # Create the startup script with prerequisite checks
            $startupScript = @"
# LAPS Installation and Configuration Script
# This script installs LAPS and configures it with prerequisite checks

Write-Host "Installing and configuring LAPS..." -ForegroundColor Green

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrator privileges. Please run as administrator."
    exit 1
}

# Check if we're on a domain controller or member server
`$isDomainController = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -in @(4, 5)
`$isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq `$true

if (-not `$isDomainController -and -not `$isDomainMember) {
    Write-Warning "LAPS requires a domain environment. This computer is not domain-joined."
    exit 1
}

# Check Windows version for LAPS availability
`$osVersion = [System.Environment]::OSVersion.Version
`$isServer2016 = `$osVersion.Major -eq 10 -and `$osVersion.Build -lt 14393 -and (Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2
`$isServer2019OrLater = `$osVersion.Major -eq 10 -and `$osVersion.Build -ge 14393 -and (Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2
`$isWindows11OrServer2022 = `$osVersion.Major -eq 10 -and `$osVersion.Build -ge 22000

# Check if LAPS is available as Windows Feature
`$lapsFeature = Get-WindowsFeature -Name "LAPS" -ErrorAction SilentlyContinue
`$lapsAvailable = `$lapsFeature -ne `$null

if (-not `$lapsAvailable) {
    Write-Warning "LAPS is not available as a Windows Feature on this system."
    Write-Host "Prerequisites not met:" -ForegroundColor Yellow
    Write-Host "- Windows Server 2019/2022 or Windows 11 required for built-in LAPS" -ForegroundColor White
    Write-Host "- Windows Server 2016 requires manual LAPS installation" -ForegroundColor White
    Write-Host ""
    Write-Host "Manual installation required for Windows Server 2016:" -ForegroundColor Yellow
    Write-Host "1. Download LAPS from Microsoft Download Center" -ForegroundColor White
    Write-Host "2. Install LAPS on all domain controllers" -ForegroundColor White
    Write-Host "3. Extend the Active Directory schema" -ForegroundColor White
    Write-Host "4. Configure LAPS GPO settings" -ForegroundColor White
    Write-Host "5. Deploy LAPS client to managed computers" -ForegroundColor White
    Write-Host "Download link: https://www.microsoft.com/en-us/download/details.aspx?id=46899" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Alternative: Use Windows LAPS (built-in on Windows 11/Server 2022+)" -ForegroundColor Cyan
    exit 1
}

# Check if LAPS is already installed
`$lapsInstalled = Get-WindowsFeature -Name "LAPS" -ErrorAction SilentlyContinue
if (`$lapsInstalled -and `$lapsInstalled.InstallState -eq "Installed") {
    Write-Host "LAPS is already installed." -ForegroundColor Green
} else {
    Write-Host "Installing LAPS..." -ForegroundColor Yellow
    try {
        Install-WindowsFeature -Name "LAPS" -IncludeManagementTools
        Write-Host "LAPS installed successfully." -ForegroundColor Green
    } catch {
        Write-Error "Failed to install LAPS: `$(`$_.Exception.Message)"
        Write-Host "LAPS may not be available on this Windows version." -ForegroundColor Yellow
        Write-Host "Consider using Windows LAPS (built-in on Windows 11/Server 2022+)" -ForegroundColor Yellow
        exit 1
    }
}

# Check if LAPS PowerShell module is available
if (-not (Get-Module -Name "LAPS" -ListAvailable)) {
    Write-Warning "LAPS PowerShell module not found. Installing..."
    try {
        Install-Module -Name "LAPS" -Force -AllowClobber -Scope CurrentUser
        Import-Module -Name "LAPS"
    } catch {
        Write-Warning "Failed to install LAPS PowerShell module: `$(`$_.Exception.Message)"
    }
} else {
    Import-Module -Name "LAPS"
}

# Check if AD schema is extended for LAPS
try {
    `$lapsSchema = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter "Name -eq 'ms-Mcs-AdmPwd'" -ErrorAction SilentlyContinue
    if (-not `$lapsSchema) {
        Write-Warning "LAPS schema extension not found. This must be done manually on a domain controller."
        Write-Warning "Please run the following command on a domain controller:"
        Write-Warning "Import-Module AdmPwd.PS; Update-AdmPwdADSchema"
        Write-Warning "Or download and run LAPS.x64.msi on a domain controller."
    } else {
        Write-Host "LAPS schema extension found." -ForegroundColor Green
    }
} catch {
    Write-Warning "Could not check LAPS schema extension: `$(`$_.Exception.Message)"
}

# Configure LAPS registry settings
`$lapsRegPath = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
if (-not (Test-Path `$lapsRegPath)) {
    New-Item -Path `$lapsRegPath -Force | Out-Null
}

# Set LAPS configuration
`$lapsSettings = @{
    "AdmPwdEnabled" = 1
    "PasswordComplexity" = 4
    "PasswordLength" = 14
    "PasswordAgeDays" = 30
    "PwdExpirationProtectionEnabled" = 1
}

foreach (`$setting in `$lapsSettings.GetEnumerator()) {
    try {
        Set-ItemProperty -Path `$lapsRegPath -Name `$setting.Key -Value `$setting.Value -Force
        Write-Host "Set `$(`$setting.Key) = `$(`$setting.Value)" -ForegroundColor Cyan
    } catch {
        Write-Warning "Failed to set `$(`$setting.Key): `$(`$_.Exception.Message)"
    }
}

# Check if LAPS is working
try {
    `$testResult = Get-AdmPwdPassword -ComputerName `$env:COMPUTERNAME -ErrorAction SilentlyContinue
    if (`$testResult) {
        Write-Host "LAPS is working correctly." -ForegroundColor Green
    } else {
        Write-Warning "LAPS may not be working correctly. Check permissions and schema extension."
    }
} catch {
    Write-Warning "Could not test LAPS functionality: `$(`$_.Exception.Message)"
}

# Set permissions for LAPS (if on domain controller)
if (`$isDomainController) {
    try {
        Write-Host "Setting LAPS permissions..." -ForegroundColor Yellow
        `$domain = Get-ADDomain
        `$lapsContainer = "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,`$(`$domain.DistinguishedName)"
        
        # Grant read permissions to Domain Computers
        `$domainComputers = Get-ADGroup -Identity "Domain Computers"
        `$acl = Get-Acl -Path "AD:`$lapsContainer"
        `$accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            `$domainComputers.SID, "ReadProperty", "Allow", "Descendents", "All"
        )
        `$acl.SetAccessRule(`$accessRule)
        Set-Acl -Path "AD:`$lapsContainer" -AclObject `$acl
        
        Write-Host "LAPS permissions configured." -ForegroundColor Green
    } catch {
        Write-Warning "Could not set LAPS permissions: `$(`$_.Exception.Message)"
    }
}

Write-Host "LAPS installation and configuration completed." -ForegroundColor Green
Write-Host "Note: Schema extension must be done manually on a domain controller if not already done." -ForegroundColor Yellow
"@
            
            $scriptPath = Join-Path $scriptDir "Install-Configure-LAPS.ps1"
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
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Install-Configure-LAPS.ps1" -Type String
            
            Write-Host "[Remediation] GPO '$gpoName' created with startup script and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Startup script created: $scriptPath" -ForegroundColor Cyan
            Write-Host "Prerequisites checked: Administrator privileges, domain environment, LAPS schema extension" -ForegroundColor Cyan
            Write-Host "Note: This GPO uses a startup script. Manual schema extension may be required on domain controllers." -ForegroundColor Yellow
            Write-ADHCLog "LAPS GPO with startup script created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during LAPS remediation: $($_.Exception.Message)"
    }
}






