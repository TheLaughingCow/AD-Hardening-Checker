function Remediate-TieringModel {
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

        Write-Host "[INFO] Starting Tiering Admin Model remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

        if ($PSCmdlet.ShouldProcess("Tiering Admin Model GPO", "Create GPO to prepare tiering model configuration")) {
            $gpoName = "Harden_AD_TieringAdminModel_Implement"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Prepare Tiering Admin Model registry hints and audit settings"

            $auditPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            try {
                Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditPrivilegeUse" -Value 3 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditAccountLogon" -Value 3 -Type DWord -ErrorAction Stop
                Set-GPRegistryValue -Name $gpoName -Key $auditPath -ValueName "AuditLogonEvents" -Value 3 -Type DWord -ErrorAction Stop

                Write-Host "[Remediation] GPO '$gpoName' created and audit policy configured" -ForegroundColor Green
                Write-Host "Configured registry values:" -ForegroundColor Cyan
                Write-Host "  _ $auditPath\AuditPrivilegeUse = 3" -ForegroundColor Cyan
                Write-Host "  _ $auditPath\AuditAccountLogon = 3" -ForegroundColor Cyan
                Write-Host "  _ $auditPath\AuditLogonEvents = 3" -ForegroundColor Cyan
                Write-Host "Note: User Rights Assignments (SeDenyLogon...) and Restricted Groups must still be configured manually using GPMC or LGPO.exe." -ForegroundColor Yellow
                Write-Host "Suggested Tiering Model groups:" -ForegroundColor Cyan
                Write-Host "  Tier 0 Admins → Domain Admins, Enterprise Admins" -ForegroundColor White
                Write-Host "  Tier 1 Admins → Server Operators, Backup Operators" -ForegroundColor White
                Write-Host "  Tier 2 Admins → Account Operators, Print Operators" -ForegroundColor White
            }
            catch {
                Write-Host "[ERROR] Failed to configure audit policy: $($_.Exception.Message)" -ForegroundColor Red
                return
            }

            Write-ADHCLog "Tiering Model GPO '$gpoName' created with audit policy; manual completion required for full implementation"
            return $gpoName
        }
    }
    catch {
        Write-Host "[ERROR] Tiering Admin Model remediation failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
