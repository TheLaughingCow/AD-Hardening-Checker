function Remediate-SecurityBaseline {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting Security Baseline remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("Security Baseline GPO", "Create GPO to apply security baseline")) {
            $gpoName = "Harden_AD_SecurityBaseline_Apply"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Apply comprehensive security baseline based on Microsoft and CIS recommendations"
            
            # Configure UAC settings
            $uacPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Set-GPRegistryValue -Name $gpoName -Key $uacPath -ValueName "EnableLUA" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $uacPath -ValueName "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $uacPath -ValueName "ConsentPromptBehaviorUser" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $uacPath -ValueName "EnableInstallerDetection" -Value 1 -Type DWord
            
            # Configure Windows Defender settings
            $defenderPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
            Set-GPRegistryValue -Name $gpoName -Key $defenderPath -ValueName "DisableAntiSpyware" -Value 0 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $defenderPath -ValueName "DisableRealtimeMonitoring" -Value 0 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $defenderPath -ValueName "DisableBehaviorMonitoring" -Value 0 -Type DWord
            
            # Configure firewall settings
            $firewallPath = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
            Set-GPRegistryValue -Name $gpoName -Key $firewallPath -ValueName "EnableFirewall" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $firewallPath -ValueName "DefaultInboundAction" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $firewallPath -ValueName "DefaultOutboundAction" -Value 0 -Type DWord
            
            # Configure audit policy
            $auditPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditAccountLogon" -Value 3 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditLogonEvents" -Value 3 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditPrivilegeUse" -Value 3 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditSystemEvents" -Value 3 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditObjectAccess" -Value 3 -Type DWord
            
            # Configure security options
            $securityPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
            Set-GPRegistryValue -Name $gpoName -Key $securityPath -ValueName "RestrictAnonymous" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $securityPath -ValueName "EveryoneIncludesAnonymous" -Value 0 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $securityPath -ValueName "LmCompatibilityLevel" -Value 5 -Type DWord
            
            # Configure network security
            $networkPath = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $networkPath -ValueName "EnableICMPRedirect" -Value 0 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $networkPath -ValueName "DisableIPSourceRouting" -Value 2 -Type DWord
            
            Write-Host "[Remediation] GPO '$gpoName' created and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Security baseline settings:" -ForegroundColor Cyan
            Write-Host "  _ $uacPath\EnableLUA = 1" -ForegroundColor Cyan
            Write-Host "  _ $uacPath\ConsentPromptBehaviorAdmin = 2" -ForegroundColor Cyan
            Write-Host "  _ $uacPath\ConsentPromptBehaviorUser = 1" -ForegroundColor Cyan
            Write-Host "  _ $defenderPath\DisableAntiSpyware = 0" -ForegroundColor Cyan
            Write-Host "  _ $defenderPath\DisableRealtimeMonitoring = 0" -ForegroundColor Cyan
            Write-Host "  _ $firewallPath\EnableFirewall = 1" -ForegroundColor Cyan
            Write-Host "  _ $firewallPath\DefaultInboundAction = 1" -ForegroundColor Cyan
            Write-Host "  _ $auditPath\AuditAccountLogon = 3" -ForegroundColor Cyan
            Write-Host "  _ $auditPath\AuditLogonEvents = 3" -ForegroundColor Cyan
            Write-Host "  _ $auditPath\AuditPrivilegeUse = 3" -ForegroundColor Cyan
            Write-Host "  _ $securityPath\RestrictAnonymous = 1" -ForegroundColor Cyan
            Write-Host "  _ $securityPath\LmCompatibilityLevel = 5" -ForegroundColor Cyan
            Write-Host "  _ $networkPath\EnableICMPRedirect = 0" -ForegroundColor Cyan
            Write-Host "  _ $networkPath\DisableIPSourceRouting = 2" -ForegroundColor Cyan
            Write-Host "Note: This GPO provides a comprehensive security baseline. Additional hardening may be required based on specific requirements." -ForegroundColor Yellow
            Write-ADHCLog "Security Baseline GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during Security Baseline remediation: $($_.Exception.Message)"
    }
}







