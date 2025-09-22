function Remediate-PasswordPolicy {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json",
        [int]$MinPasswordLength = 12,
        [int]$MaxPasswordAgeDays = 90,
        [int]$MinPasswordAgeDays = 1,
        [int]$PasswordHistoryCount = 12,
        [int]$LockoutThreshold = 5,
        [int]$LockoutDurationMins = 30,
        [int]$LockoutObservationWindowMins = 30
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-Host "[INFO] Starting Password Policy remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("Password Policy GPO", "Create GPO with startup script to update domain password policy")) {
            $gpoName = "Harden_AD_PasswordPolicy_Enforce"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Update domain password policy via startup script"

            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }

            $startupScript = @"
Write-Host "Updating domain password policy..." -ForegroundColor Yellow
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
    `$domain = Get-ADDomain -ErrorAction Stop
    Write-Host "  _ Updating password policy for domain: `$(`$domain.DNSRoot)" -ForegroundColor Cyan
    Set-ADDefaultDomainPasswordPolicy `
        -Identity `$domain.DNSRoot `
        -MinPasswordLength $MinPasswordLength `
        -MaxPasswordAge (New-TimeSpan -Days $MaxPasswordAgeDays) `
        -MinPasswordAge (New-TimeSpan -Days $MinPasswordAgeDays) `
        -PasswordHistoryCount $PasswordHistoryCount `
        -ComplexityEnabled `$true `
        -LockoutThreshold $LockoutThreshold `
        -LockoutDuration (New-TimeSpan -Minutes $LockoutDurationMins) `
        -LockoutObservationWindow (New-TimeSpan -Minutes $LockoutObservationWindowMins) `
        -ErrorAction Stop
    Write-Host "  _ Domain password policy updated successfully" -ForegroundColor Green
    Write-Host "  _ Min Password Length: $MinPasswordLength" -ForegroundColor Cyan
    Write-Host "  _ Max Password Age: $MaxPasswordAgeDays days" -ForegroundColor Cyan
    Write-Host "  _ Min Password Age: $MinPasswordAgeDays days" -ForegroundColor Cyan
    Write-Host "  _ Password History: $PasswordHistoryCount" -ForegroundColor Cyan
    Write-Host "  _ Complexity Enabled: True" -ForegroundColor Cyan
    Write-Host "  _ Lockout Threshold: $LockoutThreshold" -ForegroundColor Cyan
    Write-Host "  _ Lockout Duration: $LockoutDurationMins minutes" -ForegroundColor Cyan
    Write-Host "  _ Lockout Window: $LockoutObservationWindowMins minutes" -ForegroundColor Cyan
} catch {
    Write-Host "  _ Failed to update password policy: `$($_.Exception.Message)" -ForegroundColor Red
}
"@

            $scriptPath = Join-Path $scriptDir "Update-PasswordPolicy.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoSysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoSysvolPath)) {
                New-Item -ItemType Directory -Path $gpoSysvolPath -Force | Out-Null
            }
            Copy-Item -Path $scriptPath -Destination $gpoSysvolPath -Force

            Set-GPStartupScript -Name $gpoName -ScriptName "Update-PasswordPolicy.ps1" -ScriptParameters ""

            Write-Host "[Remediation] GPO '$gpoName' created and startup script deployed" -ForegroundColor Green
            Write-Host "  _ SYSVOL Path: $gpoSysvolPath" -ForegroundColor Cyan
            Write-Host "  _ The script will update the domain password policy when the GPO is applied" -ForegroundColor Yellow

            return $gpoName
        }
    }
    catch {
        Write-Host "ERROR during Password Policy remediation: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
