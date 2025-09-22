function Remediate-SecurityBaseline {
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

        Write-Host "[INFO] Starting Security Baseline remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

        if ($PSCmdlet.ShouldProcess("Security Baseline GPO", "Create GPO to apply security baseline")) {
            $gpoName = "Harden_AD_SecurityBaseline_Apply"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Apply comprehensive security baseline based on Microsoft and CIS recommendations"

            try {
                $uacPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Set-GPRegistryValue -Name $gpoName -Key $uacPath -ValueName "EnableLUA" -Value 1 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $uacPath -ValueName "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $uacPath -ValueName "ConsentPromptBehaviorUser" -Value 1 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $uacPath -ValueName "EnableInstallerDetection" -Value 1 -Type DWord -ErrorAction Stop

                $defenderPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
                Set-GPRegistryValue -Name $gpoName -Key $defenderPath -ValueName "DisableAntiSpyware" -Value 0 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $defenderPath -ValueName "DisableRealtimeMonitoring" -Value 0 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $defenderPath -ValueName "DisableBehaviorMonitoring" -Value 0 -Type DWord -ErrorAction Stop

                $firewallPath = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
                Set-GPRegistryValue -Name $gpoName -Key $firewallPath -ValueName "EnableFirewall" -Value 1 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $firewallPath -ValueName "DefaultInboundAction" -Value 1 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $firewallPath -ValueName "DefaultOutboundAction" -Value 0 -Type DWord -ErrorAction Stop

                $auditPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
                Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditAccountLogon" -Value 3 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditLogonEvents" -Value 3 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditPrivilegeUse" -Value 3 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditSystemEvents" -Value 3 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditObjectAccess" -Value 3 -Type DWord -ErrorAction Stop

                $securityPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
                Set-GPRegistryValue -Name $gpoName -Key $securityPath -ValueName "RestrictAnonymous" -Value 1 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $securityPath -ValueName "EveryoneIncludesAnonymous" -Value 0 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $securityPath -ValueName "LmCompatibilityLevel" -Value 5 -Type DWord -ErrorAction Stop

                $networkPath = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
                Set-GPRegistryValue -Name $gpoName -Key $networkPath -ValueName "EnableICMPRedirect" -Value 0 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $networkPath -ValueName "DisableIPSourceRouting" -Value 2 -Type DWord -ErrorAction Stop

                Write-Host "[Remediation] GPO '$gpoName' created successfully" -ForegroundColor Green
                Write-Host "  _ $uacPath\EnableLUA = 1" -ForegroundColor Cyan
                Write-Host "  _ $uacPath\ConsentPromptBehaviorAdmin = 2" -ForegroundColor Cyan
                Write-Host "  _ $uacPath\ConsentPromptBehaviorUser = 1" -ForegroundColor Cyan
                Write-Host "  _ $uacPath\EnableInstallerDetection = 1" -ForegroundColor Cyan
                Write-Host "  _ $defenderPath\DisableAntiSpyware = 0" -ForegroundColor Cyan
                Write-Host "  _ $defenderPath\DisableRealtimeMonitoring = 0" -ForegroundColor Cyan
                Write-Host "  _ $defenderPath\DisableBehaviorMonitoring = 0" -ForegroundColor Cyan
                Write-Host "  _ $firewallPath\EnableFirewall = 1" -ForegroundColor Cyan
                Write-Host "  _ $firewallPath\DefaultInboundAction = 1" -ForegroundColor Cyan
                Write-Host "  _ $firewallPath\DefaultOutboundAction = 0" -ForegroundColor Cyan
                Write-Host "  _ $auditPath\AuditAccountLogon = 3" -ForegroundColor Cyan
                Write-Host "  _ $auditPath\AuditLogonEvents = 3" -ForegroundColor Cyan
                Write-Host "  _ $auditPath\AuditPrivilegeUse = 3" -ForegroundColor Cyan
                Write-Host "  _ $auditPath\AuditSystemEvents = 3" -ForegroundColor Cyan
                Write-Host "  _ $auditPath\AuditObjectAccess = 3" -ForegroundColor Cyan
                Write-Host "  _ $securityPath\RestrictAnonymous = 1" -ForegroundColor Cyan
                Write-Host "  _ $securityPath\EveryoneIncludesAnonymous = 0" -ForegroundColor Cyan
                Write-Host "  _ $securityPath\LmCompatibilityLevel = 5" -ForegroundColor Cyan
                Write-Host "  _ $networkPath\EnableICMPRedirect = 0" -ForegroundColor Cyan
                Write-Host "  _ $networkPath\DisableIPSourceRouting = 2" -ForegroundColor Cyan
                Write-Host "  _ gpupdate /force required on clients after GPO application" -ForegroundColor Yellow

                Write-ADHCLog "Security Baseline GPO created successfully"
            }
            catch {
                Write-Host "ERROR during Security Baseline configuration: $($_.Exception.Message)" -ForegroundColor Red
                throw
            }

            return $gpoName
        }
    }
    catch {
        Write-Host "ERROR during Security Baseline remediation: $($_.Exception.Message)" -ForegroundColor Red
    }
}
