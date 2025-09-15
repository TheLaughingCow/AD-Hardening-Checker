function Remediate-LLMNR {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs","")]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting LLMNR remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("LLMNR GPO", "Create GPO to disable LLMNR")) {
            $gpoName = "Harden_AD_LLMNR_Disable"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Disable LLMNR to prevent LLMNR poisoning attacks"
            
            # Configure registry setting
            $regPath = "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient"
            Set-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "EnableMulticast" -Value 0 -Type DWord
            
            Write-Host "[Remediation] GPO '$gpoName' created successfully" -ForegroundColor Green
            Write-Host "Registry setting: $regPath\EnableMulticast = 0" -ForegroundColor Cyan
            Write-ADHCLog "LLMNR GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during LLMNR remediation: $($_.Exception.Message)"
    }
}





