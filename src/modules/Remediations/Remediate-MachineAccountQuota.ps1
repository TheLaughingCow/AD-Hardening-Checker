function Remediate-MachineAccountQuota {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json",
        [int]$DesiredQuota = 0
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-Host "[INFO] Starting Machine Account Quota remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("Machine Account Quota GPO", "Create GPO with startup script to set MachineAccountQuota to $DesiredQuota")) {
            $gpoName = "Harden_AD_MachineAccountQuota_Secure"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Set MachineAccountQuota to $DesiredQuota to prevent unauthorized machine account creation"

            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }

            $startupScript = @"
Write-Host "Setting MachineAccountQuota to $DesiredQuota..." -ForegroundColor Yellow
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
    `$domain = Get-ADDomain
    `$currentQuota = `$domain.MachineAccountQuota
    if (`$currentQuota -eq $DesiredQuota) {
        Write-Host "  _ MachineAccountQuota is already set to $DesiredQuota" -ForegroundColor Green
    } else {
        Write-Host "  _ Current MachineAccountQuota: `$currentQuota, setting to: $DesiredQuota" -ForegroundColor Cyan
        Set-ADDomain -Identity `$domain.DNSRoot -Replace @{ "ms-DS-MachineAccountQuota" = $DesiredQuota } -ErrorAction Stop
        `$updatedDomain = Get-ADDomain
        `$newQuota = `$updatedDomain.MachineAccountQuota
        if (`$newQuota -eq $DesiredQuota) {
            Write-Host "  _ MachineAccountQuota successfully set to $DesiredQuota" -ForegroundColor Green
        } else {
            Write-Host "  _ Failed to verify MachineAccountQuota change, current value: `$newQuota" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "  _ Failed to set MachineAccountQuota: `$($_.Exception.Message)" -ForegroundColor Red
}
"@

            $scriptPath = Join-Path $scriptDir "Set-MachineAccountQuota.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoSysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoSysvolPath)) {
                New-Item -ItemType Directory -Path $gpoSysvolPath -Force | Out-Null
            }
            Copy-Item -Path $scriptPath -Destination $gpoSysvolPath -Force

            Set-GPStartupScript -Name $gpoName -ScriptName "Set-MachineAccountQuota.ps1" -ScriptParameters ""

            Write-Host "[Remediation] GPO '$gpoName' created and startup script deployed" -ForegroundColor Green
            Write-Host "  _ SYSVOL Path: $gpoSysvolPath" -ForegroundColor Cyan
            Write-Host "  _ The script will set MachineAccountQuota to $DesiredQuota when the GPO is applied" -ForegroundColor Yellow

            return $gpoName
        }
    }
    catch {
        Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
