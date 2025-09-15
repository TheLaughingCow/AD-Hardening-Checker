function Remediate-mDNSBonjour {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting mDNS/Bonjour remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("mDNS/Bonjour GPO", "Create GPO with startup script to disable mDNS/Bonjour")) {
            $gpoName = "Harden_AD_mDNSBonjour_Disable"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName -Comment "Disable mDNS/Bonjour services via startup script with prerequisite checks"
            
            # Create startup script directory
            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }
            
            # Create the startup script with prerequisite checks
            $startupScript = @"
# mDNS/Bonjour Disable Script
# This script disables mDNS and Bonjour services to prevent information disclosure

Write-Host "Disabling mDNS/Bonjour services..." -ForegroundColor Green

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrator privileges. Please run as administrator."
    exit 1
}

# List of services to disable
`$servicesToDisable = @(
    "Bonjour Service",
    "mDNSResponder", 
    "Apple Mobile Device Service",
    "iTunes Helper",
    "iPod Service"
)

# List of registry keys to modify for mDNS
`$mDNSRegKeys = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
)

# Disable Bonjour services
foreach (`$serviceName in `$servicesToDisable) {
    `$service = Get-Service -Name `$serviceName -ErrorAction SilentlyContinue
    if (`$service) {
        Write-Host "Found service: `$serviceName" -ForegroundColor Yellow
        
        # Stop the service if running
        if (`$service.Status -eq "Running") {
            Write-Host "Stopping `$serviceName..." -ForegroundColor Yellow
            try {
                Stop-Service -Name `$serviceName -Force -ErrorAction Stop
                Write-Host "✓ `$serviceName stopped" -ForegroundColor Green
            } catch {
                Write-Warning "Failed to stop `$serviceName: `$(`$_.Exception.Message)"
            }
        }
        
        # Disable the service
        try {
            Set-Service -Name `$serviceName -StartupType Disabled -ErrorAction Stop
            Write-Host "✓ `$serviceName disabled" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to disable `$serviceName: `$(`$_.Exception.Message)"
        }
    } else {
        Write-Host "Service `$serviceName not found (already disabled or not installed)" -ForegroundColor Gray
    }
}

# Disable mDNS via registry
foreach (`$regKey in `$mDNSRegKeys) {
    if (Test-Path `$regKey) {
        try {
            Write-Host "Configuring mDNS settings in `$regKey..." -ForegroundColor Yellow
            Set-ItemProperty -Path `$regKey -Name "EnableMulticast" -Value 0 -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path `$regKey -Name "DisableIPSourceRouting" -Value 2 -Force -ErrorAction SilentlyContinue
            Write-Host "✓ mDNS settings configured in `$regKey" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to configure mDNS settings in `$regKey: `$(`$_.Exception.Message)"
        }
    }
}

# Disable LLMNR (Link-Local Multicast Name Resolution)
try {
    Write-Host "Disabling LLMNR..." -ForegroundColor Yellow
    `$dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path `$dnsClientPath)) {
        New-Item -Path `$dnsClientPath -Force | Out-Null
    }
    Set-ItemProperty -Path `$dnsClientPath -Name "EnableMulticast" -Value 0 -Force
    Write-Host "✓ LLMNR disabled" -ForegroundColor Green
} catch {
    Write-Warning "Failed to disable LLMNR: `$(`$_.Exception.Message)"
}

# Disable NetBIOS over TCP/IP
try {
    Write-Host "Disabling NetBIOS over TCP/IP..." -ForegroundColor Yellow
    `$netBTKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
    if (Test-Path `$netBTKey) {
        Set-ItemProperty -Path `$netBTKey -Name "NetbiosOptions" -Value 2 -Force
        Write-Host "✓ NetBIOS over TCP/IP disabled" -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to disable NetBIOS over TCP/IP: `$(`$_.Exception.Message)"
}

# Check for Bonjour installation and attempt removal
`$bonjourPrograms = @(
    "Bonjour",
    "Apple Bonjour",
    "iTunes",
    "QuickTime"
)

foreach (`$program in `$bonjourPrograms) {
    `$installedProgram = Get-WmiObject -Class Win32_Product | Where-Object { `$_.Name -like "*`$program*" }
    if (`$installedProgram) {
        Write-Host "Found installed program: `$(`$installedProgram.Name)" -ForegroundColor Yellow
        Write-Warning "Consider uninstalling `$(`$installedProgram.Name) to completely remove Bonjour."
        Write-Warning "Uninstall command: `$(`$installedProgram.Name) /S"
    }
}

# Verify changes
Write-Host "Verifying changes..." -ForegroundColor Yellow
`$activeServices = Get-Service | Where-Object { `$_.Name -in `$servicesToDisable -and `$_.Status -eq "Running" }
if (`$activeServices) {
    Write-Warning "The following services are still running: `$(`$activeServices.Name -join ', ')"
} else {
    Write-Host "✓ All mDNS/Bonjour services are disabled" -ForegroundColor Green
}

Write-Host "mDNS/Bonjour disable completed." -ForegroundColor Green
Write-Host "Note: Some changes may require a system restart to take full effect." -ForegroundColor Yellow
"@
            
            $scriptPath = Join-Path $scriptDir "Disable-mDNSBonjour.ps1"
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
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Disable-mDNSBonjour.ps1" -Type String
            
            Write-Host "[Remediation] GPO '$gpoName' created with startup script and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Startup script created: $scriptPath" -ForegroundColor Cyan
            Write-Host "Prerequisites checked: Administrator privileges, service detection" -ForegroundColor Cyan
            Write-Host "Note: This GPO uses a startup script. Manual program uninstallation may be required." -ForegroundColor Yellow
            Write-ADHCLog "mDNS/Bonjour GPO with startup script created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during mDNS/Bonjour remediation: $($_.Exception.Message)"
    }
}






