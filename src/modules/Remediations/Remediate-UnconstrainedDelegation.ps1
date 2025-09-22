function Remediate-UnconstrainedDelegation {
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

        Write-Host "[INFO] Starting Unconstrained Delegation remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Host "[INFO] Account modifications will be handled by startup script when GPO is applied" -ForegroundColor Cyan

        if ($PSCmdlet.ShouldProcess("Unconstrained Delegation GPO", "Create GPO with startup script to disable unconstrained delegation")) {
            $gpoName = "Harden_AD_UnconstrainedDelegation_Disable"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Disable unconstrained delegation via startup script and enforce secure channel protection"

            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) { New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null }

            $startupScript = @"
Write-Host "Disabling Unconstrained Delegation for all accounts..." -ForegroundColor Yellow

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERROR] Administrator privileges required." -ForegroundColor Red
    exit 1
}

`$isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq `$true
if (-not `$isDomainMember) {
    Write-Host "[INFO] Machine not joined to a domain. Skipping." -ForegroundColor Yellow
    exit 0
}

if (-not (Get-Module -Name "ActiveDirectory" -ListAvailable)) {
    try {
        Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeManagementTools
        Import-Module ActiveDirectory
    } catch {
        Write-Host "[ERROR] Could not load Active Directory module." -ForegroundColor Red
        exit 1
    }
} else {
    Import-Module ActiveDirectory
}

try {
    `$delegationTargets = Get-ADComputer -Filter {TrustedForDelegation -eq `$true} -Properties TrustedForDelegation
    if (-not `$delegationTargets -or `$delegationTargets.Count -eq 0) {
        Write-Host "[INFO] No accounts with Unconstrained Delegation found" -ForegroundColor Green
    } else {
        Write-Host "[INFO] Found `$(`$delegationTargets.Count) accounts with Unconstrained Delegation:" -ForegroundColor Yellow
        `$delegationTargets | ForEach-Object { Write-Host "  - `$(`$_.Name)" -ForegroundColor White }
        `$success = 0; `$failed = 0
        foreach (`$target in `$delegationTargets) {
            try {
                Set-ADComputer -Identity `$target.DistinguishedName -TrustedForDelegation `$false -ErrorAction Stop
                Write-Host "[Remediation] Disabled Unconstrained Delegation for `$(`$target.Name)" -ForegroundColor Green
                `$success++
            } catch {
                Write-Host "[ERROR] Failed to disable delegation for `$(`$target.Name): `$(`$_.Exception.Message)" -ForegroundColor Red
                `$failed++
            }
        }
        Write-Host "[SUMMARY] `$success accounts fixed, `$failed failed" -ForegroundColor Cyan
    }
} catch {
    Write-Host "[ERROR] Failed to process accounts: `$(`$_.Exception.Message)" -ForegroundColor Red
    exit 1
}
"@

            $scriptPath = Join-Path $scriptDir "Disable-UnconstrainedDelegation.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoSysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoSysvolPath)) { New-Item -ItemType Directory -Path $gpoSysvolPath -Force | Out-Null }
            Copy-Item -Path $scriptPath -Destination $gpoSysvolPath -Force
            Set-GPStartupScript -Name $gpoName -ScriptName "Disable-UnconstrainedDelegation.ps1" -ScriptParameters ""

            $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer"
            $netlogonPath = "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "RequireSecuritySignature" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $netlogonPath -ValueName "RequireSignOrSeal" -Value 1 -Type DWord

            Write-Host "[Remediation] GPO '$gpoName' created and startup script deployed" -ForegroundColor Green
            Write-Host "SYSVOL Path: $gpoSysvolPath" -ForegroundColor Cyan
            Write-Host "Configured registry values:" -ForegroundColor Cyan
            Write-Host "  _ $regPath\RequireSecuritySignature = 1" -ForegroundColor Cyan
            Write-Host "  _ $netlogonPath\RequireSignOrSeal = 1" -ForegroundColor Cyan
            Write-Host "Note: Manual review of service accounts is recommended to replace unconstrained delegation with constrained delegation (Kerberos-only)" -ForegroundColor Yellow

            Write-ADHCLog "Unconstrained Delegation GPO created successfully"
            return $gpoName
        }
    }
    catch {
        Write-Host "[ERROR] Unconstrained Delegation remediation failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
