function Remediate-NTLMRestriction {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting NTLM Restriction remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("NTLM Restriction GPO", "Create GPO to enable NTLM restrictions")) {
            $gpoName = "Harden_AD_NTLMRestriction_Enable"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Enable NTLM restrictions and auditing for enhanced security"
            
            # Configure NTLM restriction registry settings
            $lsaPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
            Set-GPRegistryValue -Name $gpoName -Key $lsaPath -ValueName "AuditNTLMInDomain" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $lsaPath -ValueName "RestrictNTLMInDomain" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $lsaPath -ValueName "LmCompatibilityLevel" -Value 5 -Type DWord
            
            # Configure NTLM traffic restrictions
            $msv1Path = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
            Set-GPRegistryValue -Name $gpoName -Key $msv1Path -ValueName "RestrictSendingNTLMTraffic" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $msv1Path -ValueName "RestrictReceivingNTLMTraffic" -Value 1 -Type DWord
            
            Write-Host "[Remediation] GPO '$gpoName' created successfully" -ForegroundColor Green
            Write-Host "NTLM restriction settings:" -ForegroundColor Cyan
            Write-Host "  _ $lsaPath\AuditNTLMInDomain = 1" -ForegroundColor Cyan
            Write-Host "  _ $lsaPath\RestrictNTLMInDomain = 1" -ForegroundColor Cyan
            Write-Host "  _ $lsaPath\LmCompatibilityLevel = 5" -ForegroundColor Cyan
            Write-Host "  _ $msv1Path\RestrictSendingNTLMTraffic = 1" -ForegroundColor Cyan
            Write-Host "  _ $msv1Path\RestrictReceivingNTLMTraffic = 1" -ForegroundColor Cyan
            Write-Host "Note: Restart required after GPO application. Monitor for NTLM authentication issues." -ForegroundColor Yellow
            Write-ADHCLog "NTLM Restriction GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during NTLM Restriction remediation: $($_.Exception.Message)"
    }
}







