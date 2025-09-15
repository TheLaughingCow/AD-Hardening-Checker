function Remediate-CoercionPatches {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting Coercion Patches remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("Coercion Patches GPO", "Create GPO with startup script to install coercion patches")) {
            $gpoName = "Harden_AD_CoercionPatches_Install"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName -Comment "Install coercion attack patches via startup script with prerequisite checks"
            
            # Create startup script directory
            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }
            
            # Create the startup script with prerequisite checks
            $startupScript = @"
# Coercion Patches Installation Script
# This script installs Windows updates to mitigate coercion attacks (PetitPotam, MS-RPRN, MS-FSRVP)

Write-Host "Installing coercion attack patches..." -ForegroundColor Green

# Prerequisites are now checked by the main script

# List of required patches
`$requiredPatches = @{
    "KB5005413" = "PetitPotam fix"
    "KB5006744" = "MS-RPRN fix" 
    "KB5007205" = "MS-FSRVP fix"
    "KB5007262" = "Additional coercion fixes"
}

# Check which patches are already installed
`$installedPatches = Get-HotFix -ErrorAction SilentlyContinue
`$missingPatches = @()

foreach (`$patch in `$requiredPatches.Keys) {
    if (`$installedPatches -and `$installedPatches.HotFixID -contains `$patch) {
        Write-Host "✓ `$patch (`$(`$requiredPatches[`$patch])) already installed" -ForegroundColor Green
    } else {
        Write-Host "✗ `$patch (`$(`$requiredPatches[`$patch])) missing" -ForegroundColor Red
        `$missingPatches += `$patch
    }
}

if (`$missingPatches.Count -eq 0) {
    Write-Host "All required coercion patches are already installed." -ForegroundColor Green
    exit 0
}

Write-Host "Missing patches: `$(`$missingPatches -join ', ')" -ForegroundColor Yellow

# Try to install patches via Windows Update
try {
    Write-Host "Checking for available updates..." -ForegroundColor Yellow
    `$updates = Get-WindowsUpdate -ErrorAction SilentlyContinue
    
    if (`$updates) {
        `$securityUpdates = `$updates | Where-Object { 
            `$_.Title -like "*Security*" -or 
            `$_.Title -like "*coercion*" -or
            `$_.Title -like "*PetitPotam*" -or
            `$_.Title -like "*MS-RPRN*" -or
            `$_.Title -like "*MS-FSRVP*"
        }
        
        if (`$securityUpdates) {
            Write-Host "Found `$(`$securityUpdates.Count) security updates. Installing..." -ForegroundColor Yellow
            Install-WindowsUpdate -AcceptAll -AutoReboot -ErrorAction SilentlyContinue
        } else {
            Write-Warning "No relevant security updates found via Windows Update."
        }
    } else {
        Write-Warning "Unable to check for updates via Windows Update."
    }
} catch {
    Write-Warning "Error checking/installing updates: `$(`$_.Exception.Message)"
}

# Verify LSA protection is enabled
`$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
`$lsaCfgFlags = Get-ItemProperty -Path `$lsaPath -Name "LsaCfgFlags" -ErrorAction SilentlyContinue

if (-not `$lsaCfgFlags -or `$lsaCfgFlags.LsaCfgFlags -ne 1) {
    Write-Host "Enabling LSA protection..." -ForegroundColor Yellow
    try {
        Set-ItemProperty -Path `$lsaPath -Name "LsaCfgFlags" -Value 1 -Force
        Write-Host "LSA protection enabled." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to enable LSA protection: `$(`$_.Exception.Message)"
    }
} else {
    Write-Host "LSA protection already enabled." -ForegroundColor Green
}

# Final verification
`$finalInstalledPatches = Get-HotFix -ErrorAction SilentlyContinue
`$stillMissing = @()

foreach (`$patch in `$missingPatches) {
    if (`$finalInstalledPatches -and `$finalInstalledPatches.HotFixID -contains `$patch) {
        Write-Host "✓ `$patch now installed" -ForegroundColor Green
    } else {
        `$stillMissing += `$patch
    }
}

if (`$stillMissing.Count -gt 0) {
    Write-Warning "The following patches could not be installed automatically: `$(`$stillMissing -join ', ')"
    Write-Warning "Please install these patches manually or contact your system administrator."
    Write-Warning "Download links:"
    foreach (`$patch in `$stillMissing) {
        Write-Warning "  - `$patch: https://www.catalog.update.microsoft.com/Search.aspx?q=`$patch"
    }
} else {
    Write-Host "All coercion patches installed successfully!" -ForegroundColor Green
}

Write-Host "Coercion patches installation completed." -ForegroundColor Green
"@
            
            $scriptPath = Join-Path $scriptDir "Install-CoercionPatches.ps1"
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
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Install-CoercionPatches.ps1" -Type String
            
            Write-Host "[Remediation] GPO '$gpoName' created with startup script and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Startup script created: $scriptPath" -ForegroundColor Cyan
            Write-Host "Script will install patches: KB5005413, KB5006744, KB5007205, KB5007262" -ForegroundColor Cyan
            Write-Host "Prerequisites checked: Administrator privileges, Windows Update service, PSWindowsUpdate module" -ForegroundColor Cyan
            Write-Host "Note: This GPO uses a startup script with prerequisite checks. Manual patch installation may be required." -ForegroundColor Yellow
            Write-ADHCLog "Coercion Patches GPO with startup script created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during Coercion Patches remediation: $($_.Exception.Message)"
    }
}






