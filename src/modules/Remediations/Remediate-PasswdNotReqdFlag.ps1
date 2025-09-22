function Remediate-PasswdNotReqdFlag {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    try {
        if (Test-Path $SettingsPath) {
            $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
        } else {
            $settings = @{ EnableWhatIfByDefault = $true }
        }

        Write-Host "[INFO] Starting PasswdNotReqd Flag remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

        if ($PSCmdlet.ShouldProcess("PasswdNotReqd Flag GPO", "Create GPO with startup script to remove PASSWD_NOTREQD flag")) {
            $gpoName = "Harden_AD_PasswdNotReqdFlag_Enforce"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Remove PASSWD_NOTREQD flag from all accounts via startup script"

            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }

            $startupScript = @"
Write-Host "Removing PASSWD_NOTREQD flag from all accounts..." -ForegroundColor Yellow
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
    `$users = Get-ADUser -Filter * -Properties SamAccountName,userAccountControl | Where-Object { `$_.userAccountControl -band 0x0020 }
    if (-not `$users) {
        Write-Host "  _ No accounts found with PASSWD_NOTREQD flag" -ForegroundColor Green
    } else {
        Write-Host "  _ Found `$(`$users.Count) accounts with PASSWD_NOTREQD flag" -ForegroundColor Cyan
        `$users | ForEach-Object { Write-Host "    _ `$(`$_.SamAccountName)" -ForegroundColor Cyan }
        `$successCount = 0
        `$errorCount = 0
        foreach (`$user in `$users) {
            try {
                `$newUAC = `$user.userAccountControl -band (-bnot 0x0020)
                Set-ADUser -Identity `$user.DistinguishedName -Replace @{userAccountControl = `$newUAC} -ErrorAction Stop
                Write-Host "  _ PASSWD_NOTREQD flag removed for `$(`$user.SamAccountName)" -ForegroundColor Green
                `$successCount++
            } catch {
                Write-Host "  _ Failed to clear PASSWD_NOTREQD for `$(`$user.SamAccountName): `$($_.Exception.Message)" -ForegroundColor Red
                `$errorCount++
            }
        }
        Write-Host "  _ PASSWD_NOTREQD flag removed from `$successCount accounts, `$errorCount errors" -ForegroundColor Cyan
    }
} catch {
    Write-Host "  _ Failed to process accounts: `$($_.Exception.Message)" -ForegroundColor Red
}
"@

            $scriptPath = Join-Path $scriptDir "Remove-PasswdNotReqdFlag.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoSysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoSysvolPath)) {
                New-Item -ItemType Directory -Path $gpoSysvolPath -Force | Out-Null
            }
            Copy-Item -Path $scriptPath -Destination $gpoSysvolPath -Force

            Set-GPStartupScript -Name $gpoName -ScriptName "Remove-PasswdNotReqdFlag.ps1" -ScriptParameters ""

            Write-Host "[Remediation] GPO '$gpoName' created and startup script deployed" -ForegroundColor Green
            Write-Host "  _ SYSVOL Path: $gpoSysvolPath" -ForegroundColor Cyan
            Write-Host "  _ The script will remove PASSWD_NOTREQD flag from all accounts when the GPO is applied" -ForegroundColor Yellow

            return $gpoName
        }
    }
    catch {
        Write-Host "ERROR during PasswdNotReqd Flag remediation: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
