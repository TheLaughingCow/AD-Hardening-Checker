function Remediate-LDAPAnonymousBind {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-Host "[INFO] Starting LDAP Anonymous Bind hard-disable remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("LDAP Anonymous Bind GPO", "Create GPO with startup script to clear dSHeuristics and remove ANONYMOUS LOGON read on CN=Users")) {
            $gpoName = "Harden_AD_LDAPAnonymousBind_Disable"

            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Disable anonymous LDAP by clearing dSHeuristics entirely and removing ANONYMOUS LOGON read on CN=Users; enforce server signing"

            $ntdsPath = "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $ntdsPath -ValueName "LDAPServerIntegrity" -Type DWord -Value 2 -ErrorAction Stop
            Set-GPRegistryValue -Name $gpoName -Key $ntdsPath -ValueName "RequireSecureSimpleBind" -Type DWord -Value 1 -ErrorAction Stop

            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }

$startupScript = @"
Write-Host "[INFO] Enforcing LDAP anonymous bind hard disable..." -ForegroundColor Yellow

try {
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "[ERROR] Administrator privileges required" -ForegroundColor Red
        exit 1
    }

    `\$isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq `\$true
    if (-not `\$isDomainMember) {
        Write-Host "[INFO] Machine not joined to a domain. Skipping." -ForegroundColor Yellow
        exit 0
    }

    if (-not (Get-Module -Name "ActiveDirectory" -ListAvailable)) {
        try {
            Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeManagementTools
            Import-Module ActiveDirectory
        } catch {
            Write-Host "[ERROR] Could not load Active Directory module" -ForegroundColor Red
            exit 1
        }
    } else {
        Import-Module ActiveDirectory
    }

    `\$root = [ADSI]"LDAP://RootDSE"
    `\$configNC = `\$root.configurationNamingContext
    `\$domainDN = (Get-ADDomain).DistinguishedName

    Write-Host "[INFO] Clearing dSHeuristics entirely (remove attribute)..." -ForegroundColor Cyan
    try {
        `\$dsObj = [ADSI]("LDAP://CN=Directory Service,CN=Windows NT,CN=Services,`\$configNC")
        try {
            `\$null = `\$dsObj.Get("dSHeuristics")
            `\$dsObj.Properties["dSHeuristics"].Clear()
            `\$dsObj.SetInfo()
            Write-Host "[Remediation] dSHeuristics attribute cleared (removed)" -ForegroundColor Green
        } catch {
            Write-Host "[Verification] dSHeuristics not present (already absent)" -ForegroundColor Green
        }
    } catch {
        Write-Host "[ERROR] Failed to clear dSHeuristics: `$(\`$_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host "[INFO] Removing ANONYMOUS LOGON GenericRead on CN=Users if present..." -ForegroundColor Cyan
    try {
        `\$usersAdsi = [ADSI]("LDAP://CN=Users,`\$domainDN")
        `\$anon = New-Object System.Security.Principal.NTAccount("ANONYMOUS LOGON")
        `\$sid = `\$anon.Translate([System.Security.Principal.SecurityIdentifier])
        `\$acl = `\$usersAdsi.PSBase.ObjectSecurity

        `\$toRemove = @()
        foreach (`\$rule in `\$acl.GetAccessRules(`$true,`$true,[System.Security.Principal.SecurityIdentifier])) {
            if (`\$rule.IdentityReference -eq `\$sid -and `\$rule.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericRead)) {
                `\$toRemove += `\$rule
            }
        }

        if (`\$toRemove.Count -gt 0) {
            foreach (`\$r in `\$toRemove) {
                [void]`\$acl.RemoveAccessRule(`\$r)
            }
            `\$usersAdsi.PSBase.ObjectSecurity = `\$acl
            `\$usersAdsi.PSBase.CommitChanges()
            Write-Host "[Remediation] Removed ANONYMOUS LOGON GenericRead ACE(s) on CN=Users" -ForegroundColor Green
        } else {
            Write-Host "[Verification] No ANONYMOUS LOGON GenericRead ACE found on CN=Users" -ForegroundColor Green
        }
    } catch {
        Write-Host "[ERROR] Failed to adjust CN=Users ACL: `$(\`$_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host "[INFO] LDAP anonymous bind hard-disable enforcement completed" -ForegroundColor Cyan
} catch {
    Write-Host "[ERROR] Unhandled error: `$(\`$_.Exception.Message)" -ForegroundColor Red
    exit 1
}
"@

            $scriptPath = Join-Path $scriptDir "Disable-LDAP-AnonymousHard.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoSysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoSysvolPath)) {
                New-Item -ItemType Directory -Path $gpoSysvolPath -Force | Out-Null
            }
            Copy-Item -Path $scriptPath -Destination $gpoSysvolPath -Force

            $canUseCmd = Get-Command -Name Set-GPStartupScript -ErrorAction SilentlyContinue
            if ($canUseCmd) {
                Set-GPStartupScript -Name $gpoName -ScriptName "Disable-LDAP-AnonymousHard.ps1" -ScriptParameters ""
            } else {
                $scriptGpoPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"
                Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Disable-LDAP-AnonymousHard.ps1" -Type String
            }

            Write-Host "[Remediation] GPO '$gpoName' created and startup script configured" -ForegroundColor Green
            Write-Host "  _ $ntdsPath\LDAPServerIntegrity = 2" -ForegroundColor Cyan
            Write-Host "  _ $ntdsPath\RequireSecureSimpleBind = 1" -ForegroundColor Cyan
            Write-Host "  _ Startup script clears dSHeuristics entirely and removes ANONYMOUS LOGON GenericRead on CN=Users" -ForegroundColor Cyan
            Write-Host "Note: Reboot of DC recommended to ensure NTDS settings fully applied." -ForegroundColor Yellow

            return $gpoName
        }
    }
    catch {
        Write-Host "[ERROR] LDAP Anonymous Bind hard-disable remediation failed: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
