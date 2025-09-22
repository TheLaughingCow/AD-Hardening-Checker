function Remediate-ProtectedUsersGroup {
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

        Write-Host "[INFO] Starting Protected Users Group remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

        if ($PSCmdlet.ShouldProcess("Protected Users Group GPO", "Create GPO with startup script to add accounts")) {
            $gpoName = "Harden_AD_ProtectedUsersGroup_Configure"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Configure Protected Users Group via startup script"

            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }

            $startupScript = @"
Write-Host "Adding sensitive accounts to Protected Users group..." -ForegroundColor Yellow
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "  _ Administrator privileges required" -ForegroundColor Red
    exit 1
}
`$isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq `$true
if (-not `$isDomainMember) {
    Write-Host "  _ Machine not joined to a domain, skipping" -ForegroundColor Yellow
    exit 0
}
if (-not (Get-Module -Name "ActiveDirectory" -ListAvailable)) {
    try {
        Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeManagementTools
        Import-Module ActiveDirectory
    } catch {
        Write-Host "  _ Could not load Active Directory module" -ForegroundColor Red
        exit 1
    }
} else {
    Import-Module ActiveDirectory
}
`$protectedGroup = Get-ADGroup -Filter { Name -eq "Protected Users" } -ErrorAction SilentlyContinue
if (-not `$protectedGroup) {
    Write-Host "  _ Protected Users group not found, skipping" -ForegroundColor Yellow
} else {
    `$sensitiveGroups = "Domain Admins","Enterprise Admins","Schema Admins"
    `$accounts = foreach (`$grp in `$sensitiveGroups) {
        Get-ADGroupMember -Identity `$grp -ErrorAction SilentlyContinue | Where-Object { `$_.ObjectClass -eq "user" }
    }
    if (-not `$accounts) {
        Write-Host "  _ No sensitive accounts found to add" -ForegroundColor Yellow
    } else {
        foreach (`$acct in `$accounts) {
            try {
                Add-ADGroupMember -Identity `$protectedGroup -Members `$acct -ErrorAction Stop
                Write-Host "  _ Added `$(`$acct.SamAccountName) to Protected Users group" -ForegroundColor Green
            } catch {
                Write-Host "  _ Failed to add `$(`$acct.SamAccountName): `$($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}
Write-Host "  _ Protected Users Group configuration completed" -ForegroundColor Cyan
"@

            $scriptPath = Join-Path $scriptDir "Configure-ProtectedUsersGroup.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoSysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoSysvolPath)) {
                New-Item -ItemType Directory -Path $gpoSysvolPath -Force | Out-Null
            }
            Copy-Item -Path $scriptPath -Destination $gpoSysvolPath -Force

            $scriptGpoPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Configure-ProtectedUsersGroup.ps1" -Type String

            Write-Host "[Remediation] GPO '$gpoName' created and startup script deployed" -ForegroundColor Green
            Write-Host "  _ SYSVOL Path: $gpoSysvolPath" -ForegroundColor Cyan
            Write-Host "  _ All Domain/Enterprise/Schema Admin accounts will be added to Protected Users group at GPO application" -ForegroundColor Yellow

            Write-ADHCLog "Protected Users Group GPO created and configured"
            return $gpoName
        }
    }
    catch {
        Write-Host "ERROR during Protected Users Group remediation: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
