function Remediate-KerberosPreAuth {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-Host "[INFO] Starting Kerberos Pre-Authentication remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("Kerberos Pre-Authentication GPO", "Create GPO with startup script to enable Kerberos PreAuth")) {
            $gpoName = "Harden_AD_KerberosPreAuth_Enforce"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Enable Kerberos Pre-Authentication for all accounts via startup script"

            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }

            $startupScript = @"
Write-Host "Enabling Kerberos Pre-Authentication for all accounts..." -ForegroundColor Yellow
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
    `$accounts = Get-ADUser -Filter { userAccountControl -band 0x400000 } -Properties userAccountControl
    if (-not `$accounts) {
        Write-Host "  _ All accounts already require Kerberos pre-authentication" -ForegroundColor Green
    } else {
        Write-Host "  _ Found `$(`$accounts.Count) accounts without Kerberos pre-authentication" -ForegroundColor Yellow
        foreach (`$acct in `$accounts) {
            Write-Host "    _ `$(`$acct.SamAccountName)" -ForegroundColor White
        }
        `$success = 0
        `$failed = 0
        foreach (`$acct in `$accounts) {
            try {
                Set-ADAccountControl -Identity `$acct.SamAccountName -KerberosPreAuthentication `$true -ErrorAction Stop
                Write-Host "    _ Enabled Kerberos PreAuth for `$(`$acct.SamAccountName)" -ForegroundColor Green
                `$success++
            } catch {
                Write-Host "    _ Failed to update `$(`$acct.SamAccountName): `$(`$_.Exception.Message)" -ForegroundColor Red
                `$failed++
            }
        }
        Write-Host "  _ Summary: `$success accounts fixed, `$failed failed" -ForegroundColor Cyan
    }
} catch {
    Write-Host "  _ Failed to process accounts: `$(`$_.Exception.Message)" -ForegroundColor Red
}
"@

            $scriptPath = Join-Path $scriptDir "Enable-KerberosPreAuth.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoSysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoSysvolPath)) {
                New-Item -ItemType Directory -Path $gpoSysvolPath -Force | Out-Null
            }
            Copy-Item -Path $scriptPath -Destination $gpoSysvolPath -Force

            Set-GPStartupScript -Name $gpoName -ScriptName "Enable-KerberosPreAuth.ps1" -ScriptParameters ""

            Write-Host "[Remediation] GPO '$gpoName' created and startup script deployed" -ForegroundColor Green
            Write-Host "SYSVOL Path: $gpoSysvolPath" -ForegroundColor Cyan
            Write-Host "Note: The script will enable Kerberos Pre-Authentication for all accounts when the GPO is applied." -ForegroundColor Yellow

            return $gpoName
        }
    }
    catch {
        Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
