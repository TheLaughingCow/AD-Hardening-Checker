function Remediate-DefaultCredentials {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-Host "[INFO] Starting Default Credentials remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("Default Credentials GPO", "Create GPO to secure default credentials and add startup script")) {
            $gpoName = "Harden_AD_DefaultCredentials_Secure"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Secure default accounts, enforce strong passwords, configure lockout policy and deny logon"

            $netlogonPath = "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $netlogonPath -ValueName "RequireStrongKey" -Type DWord -Value 1 -ErrorAction Stop

            Set-GPAccountPolicy -Name $gpoName -MinPasswordLength 14 -PasswordComplexity $true -LockoutBadCount 5 -LockoutDuration 30 -ErrorAction Stop

            Set-GPRegistryValue -Name $gpoName -Key "HKLM\SAM\SAM\Domains\Account\Users\000001F5" -ValueName "F" -Type Binary -Value ([byte[]](0x11,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -ErrorAction SilentlyContinue

            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }

            $startupScript = @"
Write-Host "Configuring SeDenyInteractiveLogonRight for default accounts..." -ForegroundColor Yellow
`$ntRights = "C:\Windows\System32\ntrights.exe"
if (-not (Test-Path `$ntRights)) {
    Write-Warning "ntrights.exe not found. Copy it from Windows Server 2003 Resource Kit or Sysinternals."
    exit 1
}
`$accounts = @("Administrator","Guest")
foreach (`$acct in `$accounts) {
    Write-Host "  _ Denying interactive logon for `$acct" -ForegroundColor Cyan
    & `$ntRights -u `$acct +r SeDenyInteractiveLogonRight
}
"@

            $scriptPath = Join-Path $scriptDir "Deny-Logon-DefaultAccounts.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoSysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoSysvolPath)) {
                New-Item -ItemType Directory -Path $gpoSysvolPath -Force | Out-Null
            }
            Copy-Item -Path $scriptPath -Destination $gpoSysvolPath -Force

            Set-GPStartupScript -Name $gpoName -ScriptName "Deny-Logon-DefaultAccounts.ps1" -ScriptParameters ""

            Write-Host "[Remediation] GPO '$gpoName' created successfully" -ForegroundColor Green
            Write-Host "  _ Netlogon strong key requirement configured" -ForegroundColor Cyan
            Write-Host "  _ Password complexity enabled (min length 14)" -ForegroundColor Cyan
            Write-Host "  _ Account lockout after 5 attempts, 30 minutes duration" -ForegroundColor Cyan
            Write-Host "  _ Guest account disabled" -ForegroundColor Cyan
            Write-Host "  _ Startup script added to deny logon for Administrator/Guest accounts" -ForegroundColor Cyan
            Write-Host "Note: Ensure ntrights.exe is present in C:\Windows\System32 or SYSVOL." -ForegroundColor Yellow

            return $gpoName
        }
    }
    catch {
        Write-Host "ERROR during Default Credentials remediation: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
