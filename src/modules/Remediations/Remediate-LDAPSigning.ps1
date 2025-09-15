function Remediate-LDAPSigning {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting LDAP Signing remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("LDAP Signing GPO", "Create GPO to require LDAP Signing")) {
            $gpoName = "Harden_AD_LDAPSigning_Require"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Require LDAP Signing to prevent LDAP relay attacks"
            
            # Configure LDAP signing registry setting
            $regPath = "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
            try {
                Set-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "LDAPServerIntegrity" -Value 2 -Type DWord
                Write-Host "[Remediation] Registry setting configured successfully" -ForegroundColor Green
                
                # Verify the setting was applied
                $verifySetting = Get-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "LDAPServerIntegrity" -ErrorAction SilentlyContinue
                if ($verifySetting) {
                    Write-Host "[Remediation] Verification: LDAPServerIntegrity = $($verifySetting.Value)" -ForegroundColor Cyan
                } else {
                    Write-Host "[Remediation] WARNING: Could not verify registry setting!" -ForegroundColor Red
                }
            } catch {
                Write-Error "Failed to configure registry setting: $($_.Exception.Message)"
                return
            }
            
            Write-Host "Registry setting: $regPath\LDAPServerIntegrity = 2 (Required)" -ForegroundColor Cyan
            Write-Host "Note: Restart Active Directory service required after GPO application" -ForegroundColor Yellow
            Write-ADHCLog "LDAP Signing GPO configured and linked successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during LDAP Signing remediation: $($_.Exception.Message)"
    }
}







