function Remediate-LDAPAnonymousBind {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting LDAP Anonymous Bind remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("LDAP Anonymous Bind GPO", "Create GPO to disable LDAP Anonymous Bind")) {
            $gpoName = "Harden_AD_LDAPAnonymousBind_Disable"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Disable LDAP Anonymous Bind to prevent unauthorized access"
            
            # Configure LDAP anonymous bind disable registry settings
            $ntdsPath = "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
            Set-GPRegistryValue -Name $gpoName -Key $ntdsPath -ValueName "LDAPServerIntegrityRequired" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $ntdsPath -ValueName "LDAPServerIntegrity" -Value 2 -Type DWord
            
            Write-Host "[Remediation] GPO '$gpoName' created and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Registry settings:" -ForegroundColor Cyan
            Write-Host "  _ $ntdsPath\LDAPServerIntegrityRequired = 1" -ForegroundColor Cyan
            Write-Host "  _ $ntdsPath\LDAPServerIntegrity = 2" -ForegroundColor Cyan
            Write-Host "Note: Restart Active Directory service required after GPO application" -ForegroundColor Yellow
            Write-ADHCLog "LDAP Anonymous Bind GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during LDAP Anonymous Bind remediation: $($_.Exception.Message)"
    }
}







