function Remediate-LSASSProtectedMode {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting LSASS Protected Mode remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("LSASS Protected Mode GPO", "Create GPO with startup script to enable LSASS protection")) {
            $gpoName = "Harden_AD_LSASSProtectedMode_Enable"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName -Comment "Enable LSASS Protected Mode via startup script with prerequisite checks"
            
            # Create startup script directory
            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }
            
            # Create the startup script with prerequisite checks
            $startupScript = @"
# LSASS Protected Mode Configuration Script
# This script enables LSASS protection with prerequisite checks

Write-Host "Checking LSASS Protected Mode prerequisites..." -ForegroundColor Green

# Check Windows version (requires Windows 11 or Server 2022+)
`$osVersion = [System.Environment]::OSVersion.Version
`$isWindows11OrLater = `$osVersion.Major -ge 10 -and `$osVersion.Build -ge 22000
`$isServer2022OrLater = `$osVersion.Major -ge 10 -and `$osVersion.Build -ge 20348

if (-not (`$isWindows11OrLater -or `$isServer2022OrLater)) {
    Write-Warning "LSASS Protected Mode prerequisites not met."
    Write-Host "Prerequisites not met:" -ForegroundColor Yellow
    Write-Host "- Windows 11 or Windows Server 2022+ required" -ForegroundColor White
    Write-Host "- Current version: `$(`$osVersion.Major).`$(`$osVersion.Minor).`$(`$osVersion.Build)" -ForegroundColor White
    Write-Host ""
    Write-Host "Alternative security measures:" -ForegroundColor Cyan
    Write-Host "1. Enable Credential Guard (if supported)" -ForegroundColor White
    Write-Host "2. Use Windows Defender Credential Guard" -ForegroundColor White
    Write-Host "3. Implement LSA Protection via registry (limited support)" -ForegroundColor White
    Write-Host "4. Upgrade to Windows 11/Server 2022 for full LSASS protection" -ForegroundColor White
    exit 1
}

# Check if LSASS protection is already enabled
`$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
`$runAsPPL = Get-ItemProperty -Path `$lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue
`$runAsPPLBoot = Get-ItemProperty -Path `$lsaPath -Name "RunAsPPLBoot" -ErrorAction SilentlyContinue

if (`$runAsPPL -and `$runAsPPL.RunAsPPL -eq 1 -and `$runAsPPLBoot -and `$runAsPPLBoot.RunAsPPLBoot -eq 1) {
    Write-Host "LSASS protection is already enabled." -ForegroundColor Yellow
    exit 0
}

# Check if system is in a supported state
`$computerInfo = Get-ComputerInfo -ErrorAction SilentlyContinue
if (`$computerInfo -and `$computerInfo.WindowsProductName -like "*Server*") {
    Write-Host "Configuring LSASS protection on Server: `$(`$computerInfo.WindowsProductName)" -ForegroundColor Cyan
} else {
    Write-Host "Configuring LSASS protection on Client: `$(`$computerInfo.WindowsProductName)" -ForegroundColor Cyan
}

# Enable LSASS protection
try {
    Write-Host "Enabling LSASS Protected Mode..." -ForegroundColor Yellow
    Set-ItemProperty -Path `$lsaPath -Name "RunAsPPL" -Value 1 -Force
    Set-ItemProperty -Path `$lsaPath -Name "RunAsPPLBoot" -Value 1 -Force
    
    Write-Host "LSASS Protected Mode enabled successfully." -ForegroundColor Green
    Write-Host "A system restart is required for changes to take effect." -ForegroundColor Yellow
    
    # Log the change
    `$logMessage = "LSASS Protected Mode enabled via GPO startup script on `$(`$env:COMPUTERNAME)"
    Write-EventLog -LogName Application -Source "HardenADCheck" -EventId 1001 -Message `$logMessage -EntryType Information -ErrorAction SilentlyContinue
    
} catch {
    Write-Error "Failed to enable LSASS protection: `$(`$_.Exception.Message)"
    exit 1
}

Write-Host "LSASS Protected Mode configuration completed." -ForegroundColor Green
"@
            
            $scriptPath = Join-Path $scriptDir "Enable-LSASSProtectedMode.ps1"
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
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Enable-LSASSProtectedMode.ps1" -Type String
            
            Write-Host "[Remediation] GPO '$gpoName' created with startup script and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Startup script created: $scriptPath" -ForegroundColor Cyan
            Write-Host "Prerequisites checked: Windows 11/Server 2022+ required" -ForegroundColor Cyan
            Write-Host "Note: This GPO uses a startup script with prerequisite checks. Manual OS upgrade may be required." -ForegroundColor Yellow
            Write-ADHCLog "LSASS Protected Mode GPO with startup script created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during LSASS Protected Mode remediation: $($_.Exception.Message)"
    }
}






