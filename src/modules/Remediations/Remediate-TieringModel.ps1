function Remediate-TieringModel {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting Tiered Admin Model remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("Tiered Admin Model GPO", "Create GPO to implement tiered admin structure")) {
            $gpoName = "Harden_AD_TieredAdminModel_Implement"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Implement Tiered Admin Model with separate OUs and GPOs for different privilege levels"
            
            # Configure user rights assignments for tiered access
            $userRightsPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Set-GPRegistryValue -Name $gpoName -Key $userRightsPath -ValueName "SeDenyNetworkLogonRight" -Value "Tier 0 Admins,Tier 1 Admins" -Type String
            Set-GPRegistryValue -Name $gpoName -Key $userRightsPath -ValueName "SeDenyInteractiveLogonRight" -Value "Tier 0 Admins" -Type String
            
            # Configure restricted groups for tiered admin groups
            $restrictedGroupsPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\RestrictedGroups"
            Set-GPRegistryValue -Name $gpoName -Key $restrictedGroupsPath -ValueName "Tier 0 Admins" -Value "Domain Admins,Enterprise Admins" -Type String
            Set-GPRegistryValue -Name $gpoName -Key $restrictedGroupsPath -ValueName "Tier 1 Admins" -Value "Server Operators,Backup Operators" -Type String
            Set-GPRegistryValue -Name $gpoName -Key $restrictedGroupsPath -ValueName "Tier 2 Admins" -Value "Account Operators,Print Operators" -Type String
            
            # Configure audit policy for privileged access
            $auditPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditPrivilegeUse" -Value 3 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditAccountLogon" -Value 3 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditLogonEvents" -Value 3 -Type DWord
            
            Write-Host "[Remediation] GPO '$gpoName' created and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Tiered Admin Model settings:" -ForegroundColor Cyan
            Write-Host "  _ $userRightsPath\SeDenyNetworkLogonRight = Tier 0 Admins,Tier 1 Admins" -ForegroundColor Cyan
            Write-Host "  _ $userRightsPath\SeDenyInteractiveLogonRight = Tier 0 Admins" -ForegroundColor Cyan
            Write-Host "  _ $restrictedGroupsPath\Tier 0 Admins = Domain Admins,Enterprise Admins" -ForegroundColor Cyan
            Write-Host "  _ $restrictedGroupsPath\Tier 1 Admins = Server Operators,Backup Operators" -ForegroundColor Cyan
            Write-Host "  _ $restrictedGroupsPath\Tier 2 Admins = Account Operators,Print Operators" -ForegroundColor Cyan
            Write-Host "  _ $auditPath\AuditPrivilegeUse = 3 (Success and Failure)" -ForegroundColor Cyan
            Write-Host "  _ $auditPath\AuditAccountLogon = 3 (Success and Failure)" -ForegroundColor Cyan
            Write-Host "  _ $auditPath\AuditLogonEvents = 3 (Success and Failure)" -ForegroundColor Cyan
            Write-Host "Note: This GPO provides basic tiered admin structure. Manual creation of OUs and additional GPOs is required." -ForegroundColor Yellow
            Write-ADHCLog "Tiered Admin Model GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during Tiered Admin Model remediation: $($_.Exception.Message)"
    }
}







