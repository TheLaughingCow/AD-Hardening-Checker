function Remediate-NTLMRestriction {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json",
        [switch]$Enforce
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-Host "[INFO] Starting NTLM Restriction remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("NTLM Restriction GPO", "Create GPO to configure NTLM restrictions")) {
            $gpoName = "Harden_AD_NTLMRestriction"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Configure NTLM auditing/restrictions"

            $lsaPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
            $msv1Path = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"

            Set-GPRegistryValue -Name $gpoName -Key $lsaPath -ValueName "LmCompatibilityLevel" -Value 5 -Type DWord

            if ($Enforce) {
                Set-GPRegistryValue -Name $gpoName -Key $lsaPath -ValueName "RestrictNTLMInDomain" -Value 2 -Type DWord
                Set-GPRegistryValue -Name $gpoName -Key $msv1Path -ValueName "RestrictSendingNTLMTraffic" -Value 2 -Type DWord
                Write-Host "  _ NTLM restrictions set to ENFORCE mode" -ForegroundColor Red
            } else {
                Set-GPRegistryValue -Name $gpoName -Key $lsaPath -ValueName "RestrictNTLMInDomain" -Value 1 -Type DWord
                Set-GPRegistryValue -Name $gpoName -Key $msv1Path -ValueName "RestrictSendingNTLMTraffic" -Value 1 -Type DWord
                Write-Host "  _ NTLM restrictions set to AUDIT mode" -ForegroundColor Yellow
            }

            Set-GPRegistryValue -Name $gpoName -Key $lsaPath -ValueName "AuditNTLMInDomain" -Value 1 -Type DWord

            Write-Host "[Remediation] GPO '$gpoName' created successfully" -ForegroundColor Green
            Write-Host "  _ $lsaPath\LmCompatibilityLevel = 5 (NTLMv2 only)" -ForegroundColor Cyan
            Write-Host "  _ $lsaPath\RestrictNTLMInDomain = $([int]($Enforce.IsPresent) * 2 + 1)" -ForegroundColor Cyan
            Write-Host "  _ $msv1Path\RestrictSendingNTLMTraffic = $([int]($Enforce.IsPresent) * 2 + 1)" -ForegroundColor Cyan
            Write-Host "  _ $lsaPath\AuditNTLMInDomain = 1" -ForegroundColor Cyan
            Write-Host "  _ Restart required, start with audit mode and switch to enforce after log review" -ForegroundColor Yellow

            return $gpoName
        }
    }
    catch {
        Write-Host "ERROR during NTLM Restriction remediation: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
