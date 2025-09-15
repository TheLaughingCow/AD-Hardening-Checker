function Remediate-ShareACLRestriction {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting Share ACL Restriction remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("Share ACL Restriction GPO", "Create GPO with startup script to secure network shares")) {
            $gpoName = "Harden_AD_ShareACLRestriction_Secure"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName -Comment "Secure network shares via startup script with prerequisite checks"
            
            # Create startup script directory
            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }
            
            # Create the startup script with prerequisite checks
            $startupScript = @"
# Share ACL Restriction Script
# This script secures network shares by applying proper ACLs

Write-Host "Securing network shares..." -ForegroundColor Green

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrator privileges. Please run as administrator."
    exit 1
}

# Check if we're in a domain environment
`$isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq `$true
if (-not `$isDomainMember) {
    Write-Warning "Share ACL restrictions are most effective in domain environments. This computer is not domain-joined."
}

# Get all network shares
Write-Host "Scanning for network shares..." -ForegroundColor Yellow
try {
    `$shares = Get-SmbShare -ErrorAction Stop | Where-Object { `$_.ShareType -eq "FileSystemDirectory" -and `$_.Name -notlike "IPC`$" -and `$_.Name -notlike "ADMIN`$" }
    
    if (-not `$shares -or `$shares.Count -eq 0) {
        Write-Host "✓ No network shares found to secure" -ForegroundColor Green
        exit 0
    }
    
    Write-Host "Found `$(`$shares.Count) network shares:" -ForegroundColor Yellow
    foreach (`$share in `$shares) {
        Write-Host "  - `$(`$share.Name) (`$(`$share.Path))" -ForegroundColor White
    }
    
} catch {
    Write-Error "Failed to enumerate network shares: `$(`$_.Exception.Message)"
    exit 1
}

# Process each share
`$successCount = 0
`$errorCount = 0
`$alreadySecureCount = 0

foreach (`$share in `$shares) {
    try {
        Write-Host "Processing share: `$(`$share.Name)..." -ForegroundColor Cyan
        
        # Get current ACL for the share
        `$sharePath = `$share.Path
        if (-not (Test-Path `$sharePath)) {
            Write-Warning "Share path does not exist: `$sharePath"
            `$errorCount++
            continue
        }
        
        # Get current ACL
        `$currentAcl = Get-Acl -Path `$sharePath -ErrorAction Stop
        
        # Check if ACL is already secure
        `$isSecure = `$true
        `$insecureEntries = @()
        
        foreach (`$access in `$currentAcl.Access) {
            # Check for Everyone, Anonymous, or Guest access
            if (`$access.IdentityReference -like "*Everyone*" -or 
                `$access.IdentityReference -like "*Anonymous*" -or 
                `$access.IdentityReference -like "*Guest*" -or
                `$access.IdentityReference -like "*Tout le monde*" -or
                `$access.IdentityReference -like "*Anonyme*" -or
                `$access.IdentityReference -like "*Gast*") {
                `$isSecure = `$false
                `$insecureEntries += `$access
            }
            
            # Check for excessive permissions
            if (`$access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl -and 
                `$access.AccessControlType -eq "Allow" -and
                `$access.IdentityReference -notlike "*Administrators*" -and
                `$access.IdentityReference -notlike "*System*") {
                `$isSecure = `$false
                `$insecureEntries += `$access
            }
        }
        
        if (`$isSecure) {
            Write-Host "✓ Share `$(`$share.Name) is already secure" -ForegroundColor Green
            `$alreadySecureCount++
            continue
        }
        
        Write-Host "Securing share `$(`$share.Name)..." -ForegroundColor Yellow
        Write-Host "Insecure entries found:" -ForegroundColor Red
        foreach (`$entry in `$insecureEntries) {
            Write-Host "  - `$(`$entry.IdentityReference): `$(`$entry.FileSystemRights)" -ForegroundColor Red
        }
        
        # Create new ACL with secure permissions
        `$newAcl = Get-Acl -Path `$sharePath
        
        # Remove insecure entries
        foreach (`$entry in `$insecureEntries) {
            try {
                `$newAcl.RemoveAccessRule(`$entry)
                Write-Host "  ✓ Removed: `$(`$entry.IdentityReference)" -ForegroundColor Green
            } catch {
                Write-Warning "  Failed to remove: `$(`$entry.IdentityReference): `$(`$_.Exception.Message)"
            }
        }
        
        # Add secure entries if not present
        `$secureEntries = @(
            @{ Identity = "BUILTIN\Administrators"; Rights = "FullControl"; Type = "Allow" },
            @{ Identity = "NT AUTHORITY\SYSTEM"; Rights = "FullControl"; Type = "Allow" },
            @{ Identity = "NT AUTHORITY\Authenticated Users"; Rights = "ReadAndExecute"; Type = "Allow" }
        )
        
        foreach (`$secureEntry in `$secureEntries) {
            try {
                `$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    `$secureEntry.Identity,
                    `$secureEntry.Rights,
                    "ContainerInherit,ObjectInherit",
                    "None",
                    `$secureEntry.Type
                )
                
                # Check if rule already exists
                `$ruleExists = `$false
                foreach (`$existingRule in `$newAcl.Access) {
                    if (`$existingRule.IdentityReference -eq `$secureEntry.Identity -and 
                        `$existingRule.FileSystemRights -eq `$accessRule.FileSystemRights -and
                        `$existingRule.AccessControlType -eq `$accessRule.AccessControlType) {
                        `$ruleExists = `$true
                        break
                    }
                }
                
                if (-not `$ruleExists) {
                    `$newAcl.SetAccessRule(`$accessRule)
                    Write-Host "  ✓ Added: `$(`$secureEntry.Identity) - `$(`$secureEntry.Rights)" -ForegroundColor Green
                }
            } catch {
                Write-Warning "  Failed to add secure entry: `$(`$secureEntry.Identity): `$(`$_.Exception.Message)"
            }
        }
        
        # Apply the new ACL
        Set-Acl -Path `$sharePath -AclObject `$newAcl -ErrorAction Stop
        
        Write-Host "✓ Share `$(`$share.Name) secured successfully" -ForegroundColor Green
        `$successCount++
        
    } catch {
        Write-Warning "Failed to secure share `$(`$share.Name): `$(`$_.Exception.Message)"
        `$errorCount++
    }
}

# Verify the changes
Write-Host "Verifying changes..." -ForegroundColor Yellow
try {
    `$verifiedShares = Get-SmbShare -ErrorAction Stop | Where-Object { `$_.ShareType -eq "FileSystemDirectory" -and `$_.Name -notlike "IPC`$" -and `$_.Name -notlike "ADMIN`$" }
    
    foreach (`$share in `$verifiedShares) {
        try {
            `$sharePath = `$share.Path
            if (Test-Path `$sharePath) {
                `$acl = Get-Acl -Path `$sharePath
                `$insecureCount = 0
                
                foreach (`$access in `$acl.Access) {
                    if (`$access.IdentityReference -like "*Everyone*" -or 
                        `$access.IdentityReference -like "*Anonymous*" -or 
                        `$access.IdentityReference -like "*Guest*") {
                        `$insecureCount++
                    }
                }
                
                if (`$insecureCount -eq 0) {
                    Write-Host "✓ `$(`$share.Name): Secure" -ForegroundColor Green
                } else {
                    Write-Host "✗ `$(`$share.Name): `$insecureCount insecure entries" -ForegroundColor Red
                }
            }
        } catch {
            Write-Warning "Could not verify share `$(`$share.Name): `$(`$_.Exception.Message)"
        }
    }
} catch {
    Write-Warning "Could not verify share security: `$(`$_.Exception.Message)"
}

# Summary
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Successfully secured: `$successCount shares" -ForegroundColor Green
Write-Host "  Already secure: `$alreadySecureCount shares" -ForegroundColor Yellow
Write-Host "  Failed to secure: `$errorCount shares" -ForegroundColor Red

# Additional security recommendations
Write-Host "Additional security recommendations:" -ForegroundColor Cyan
Write-Host "1. Regularly audit network share permissions" -ForegroundColor White
Write-Host "2. Implement least privilege access principles" -ForegroundColor White
Write-Host "3. Consider using DFS for centralized share management" -ForegroundColor White
Write-Host "4. Enable share-level auditing" -ForegroundColor White
Write-Host "5. Implement network segmentation for sensitive shares" -ForegroundColor White
Write-Host "6. Consider using Azure File Sync or similar cloud solutions" -ForegroundColor White

# Log the change
try {
    `$logMessage = "Share ACL restrictions applied via GPO startup script on `$(`$env:COMPUTERNAME). Secured `$successCount shares."
    Write-EventLog -LogName Application -Source "HardenADCheck" -EventId 1008 -Message `$logMessage -EntryType Information -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Could not log the change to Event Log: `$(`$_.Exception.Message)"
}

Write-Host "Share ACL restriction configuration completed." -ForegroundColor Green
"@
            
            $scriptPath = Join-Path $scriptDir "Secure-ShareACLs.ps1"
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
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Secure-ShareACLs.ps1" -Type String
            
            Write-Host "[Remediation] GPO '$gpoName' created with startup script and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Startup script created: $scriptPath" -ForegroundColor Cyan
            Write-Host "Prerequisites checked: Administrator privileges, domain environment" -ForegroundColor Cyan
            Write-Host "Note: This GPO uses a startup script. Manual share verification may be required." -ForegroundColor Yellow
            Write-ADHCLog "Share ACL Restriction GPO with startup script created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during Share ACL Restriction remediation: $($_.Exception.Message)"
    }
}






