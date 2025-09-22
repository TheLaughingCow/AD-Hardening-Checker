function Remediate-ShareACLRestriction {
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

        Write-Host "[INFO] Starting Share ACL Restriction remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

        if ($PSCmdlet.ShouldProcess("Share ACL Restriction GPO", "Create GPO with startup script to secure network shares")) {
            $gpoName = "Harden_AD_ShareACLRestriction_Secure"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Secure network shares via startup script"

            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }

            $startupScript = @"
Write-Host "[INFO] Securing network shares..." -ForegroundColor Cyan

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERROR] Administrator privileges required." -ForegroundColor Red
    exit 1
}

`$isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq `$true
if (-not `$isDomainMember) {
    Write-Host "[INFO] System not domain-joined. ACL restrictions will still be applied locally." -ForegroundColor Yellow
}

try {
    `$shares = Get-SmbShare -ErrorAction Stop | Where-Object { `$_.ShareType -eq "FileSystemDirectory" -and `$_.Name -notlike "IPC`$" -and `$_.Name -notlike "ADMIN`$" }
    if (-not `$shares) {
        Write-Host "[INFO] No network shares found to secure." -ForegroundColor Green
        exit 0
    }
} catch {
    Write-Host "[ERROR] Failed to enumerate network shares: `$($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

`$successCount = 0
`$errorCount = 0
`$alreadySecureCount = 0

foreach (`$share in `$shares) {
    try {
        `$sharePath = `$share.Path
        if (-not (Test-Path `$sharePath)) {
            Write-Host "[INFO] Path not found for share `$($share.Name)" -ForegroundColor Yellow
            `$errorCount++
            continue
        }

        `$currentAcl = Get-Acl -Path `$sharePath
        `$isSecure = `$true
        `$insecureEntries = @()

        foreach (`$access in `$currentAcl.Access) {
            if (`$access.IdentityReference -match "Everyone|Anonymous|Guest|Tout le monde|Anonyme|Gast" -or
                (`$access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl -and
                `$access.IdentityReference -notmatch "Administrators|SYSTEM")) {
                `$isSecure = `$false
                `$insecureEntries += `$access
            }
        }

        if (`$isSecure) {
            `$alreadySecureCount++
            continue
        }

        `$newAcl = Get-Acl -Path `$sharePath
        foreach (`$entry in `$insecureEntries) {
            `$newAcl.RemoveAccessRule(`$entry) | Out-Null
        }

        `$secureEntries = @(
            @{ Identity = "BUILTIN\Administrators"; Rights = "FullControl" },
            @{ Identity = "NT AUTHORITY\SYSTEM"; Rights = "FullControl" },
            @{ Identity = "NT AUTHORITY\Authenticated Users"; Rights = "ReadAndExecute" }
        )

        foreach (`$entry in `$secureEntries) {
            `$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                `$entry.Identity,
                `$entry.Rights,
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )
            `$newAcl.SetAccessRule(`$rule)
        }

        Set-Acl -Path `$sharePath -AclObject `$newAcl -ErrorAction Stop
        `$successCount++
    } catch {
        `$errorCount++
    }
}

Write-Host "[Remediation] Network share ACL remediation completed" -ForegroundColor Green
Write-Host "  _ Shares secured: `$successCount" -ForegroundColor Cyan
Write-Host "  _ Shares already secure: `$alreadySecureCount" -ForegroundColor Cyan
Write-Host "  _ Errors: `$errorCount" -ForegroundColor Yellow
"@

            $scriptPath = Join-Path $scriptDir "Secure-ShareACLs.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoPath)) {
                New-Item -ItemType Directory -Path $gpoPath -Force | Out-Null
            }

            Copy-Item -Path $scriptPath -Destination $gpoPath -Force
            $scriptGpoPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Secure-ShareACLs.ps1" -Type String -ErrorAction Stop

            Write-Host "[Remediation] GPO '$gpoName' created and startup script deployed" -ForegroundColor Green
            Write-Host "SYSVOL Path: $gpoPath" -ForegroundColor Cyan
            Write-Host "Note: ACL changes will be applied at next policy refresh and may require a reboot." -ForegroundColor Yellow
            Write-ADHCLog "Share ACL Restriction GPO created successfully"

            return $gpoName
        }
    }
    catch {
        Write-Host "ERROR during Share ACL Restriction remediation: $($_.Exception.Message)" -ForegroundColor Red
    }
}
