function Remediate-PreWin2000CompatibleAccess {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    try {
        if (Test-Path $SettingsPath) {
            $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
        } else {
            $settings = @{ EnableWhatIfByDefault = $true }
        }

        Write-Host "[INFO] Starting Pre-Windows 2000 Compatible Access remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

        Import-Module ActiveDirectory -ErrorAction Stop
        $domain = Get-ADDomain -ErrorAction Stop

        $groupNames = @(
            "Pre-Windows 2000 Compatible Access",
            "Accès compatible avec les versions antérieures à Windows 2000",
            "Vorgängerversionen von Windows 2000 kompatibler Zugriff"
        )

        $targetGroup = $null
        foreach ($groupName in $groupNames) {
            $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
            if ($group) {
                $targetGroup = $group
                break
            }
        }

        if (-not $targetGroup) {
            Write-Host "  _ Pre-Windows 2000 Compatible Access group not found, skipping remediation" -ForegroundColor Yellow
            return
        }

        if ($PSCmdlet.ShouldProcess("Pre-Windows 2000 Compatible Access GPO", "Create GPO with startup script to empty the group")) {
            $gpoName = "Harden_AD_PreWin2000CompatibleAccess_Empty"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Empty Pre-Windows 2000 Compatible Access group via startup script"

            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }

            $startupScript = @"
Write-Host "Emptying Pre-Windows 2000 Compatible Access group..." -ForegroundColor Yellow
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "  _ Administrator privileges required" -ForegroundColor Red
}
`$isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq `$true
if (-not `$isDomainMember) {
    Write-Host "  _ Machine not joined to a domain, skipping" -ForegroundColor Yellow
}
if (-not (Get-Module -Name "ActiveDirectory" -ListAvailable)) {
    try {
        Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeManagementTools
        Import-Module ActiveDirectory
    } catch {
        Write-Host "  _ Could not load Active Directory module" -ForegroundColor Red
    }
} else {
    Import-Module ActiveDirectory
}
try {
    `$groupNames = @(
        "Pre-Windows 2000 Compatible Access",
        "Accès compatible avec les versions antérieures à Windows 2000",
        "Vorgängerversionen von Windows 2000 kompatibler Zugriff"
    )
    `$targetGroup = `$null
    foreach (`$groupName in `$groupNames) {
        `$group = Get-ADGroup -Identity `$groupName -ErrorAction SilentlyContinue
        if (`$group) { `$targetGroup = `$group; break }
    }
    if (-not `$targetGroup) {
        Write-Host "  _ Group not found, skipping" -ForegroundColor Yellow
    } else {
        `$currentMembers = Get-ADGroupMember -Identity `$targetGroup.DistinguishedName -ErrorAction SilentlyContinue
        if (-not `$currentMembers -or `$currentMembers.Count -eq 0) {
            Write-Host "  _ Group is already empty" -ForegroundColor Green
        } else {
            Write-Host "  _ Found `$(`$currentMembers.Count) members to remove from `$(`$targetGroup.Name)" -ForegroundColor Cyan
            `$success = 0; `$failed = 0
            foreach (`$member in `$currentMembers) {
                try {
                    Remove-ADGroupMember -Identity `$targetGroup.DistinguishedName -Members `$member.DistinguishedName -Confirm:`$false -ErrorAction Stop
                    Write-Host "    _ Removed `$(`$member.Name)" -ForegroundColor Green
                    `$success++
                } catch {
                    Write-Host "    _ Failed to remove `$(`$member.Name): `$($_.Exception.Message)" -ForegroundColor Red
                    `$failed++
                }
            }
            `$remaining = Get-ADGroupMember -Identity `$targetGroup.DistinguishedName -ErrorAction SilentlyContinue
            if (`$remaining -and `$remaining.Count -gt 0) {
                Write-Host "  _ Some members could not be removed, remaining count: `$(`$remaining.Count)" -ForegroundColor Yellow
            } else {
                Write-Host "  _ Group is now empty" -ForegroundColor Green
            }
            Write-Host "  _ Summary: `$success removed, `$failed failed" -ForegroundColor Cyan
        }
    }
} catch {
    Write-Host "  _ Failed to process group: `$($_.Exception.Message)" -ForegroundColor Red
}
"@

            $scriptPath = Join-Path $scriptDir "Empty-PreWin2000Group.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoSysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoSysvolPath)) {
                New-Item -ItemType Directory -Path $gpoSysvolPath -Force | Out-Null
            }
            Copy-Item -Path $scriptPath -Destination $gpoSysvolPath -Force

            Set-GPStartupScript -Name $gpoName -ScriptName "Empty-PreWin2000Group.ps1" -ScriptParameters ""

            Write-Host "[Remediation] GPO '$gpoName' created and startup script deployed" -ForegroundColor Green
            Write-Host "  _ SYSVOL Path: $gpoSysvolPath" -ForegroundColor Cyan
            Write-Host "  _ The script will empty the Pre-Windows 2000 Compatible Access group when the GPO is applied" -ForegroundColor Yellow

            return $gpoName
        }
    }
    catch {
        Write-Host "ERROR during Pre-Windows 2000 Compatible Access remediation: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
