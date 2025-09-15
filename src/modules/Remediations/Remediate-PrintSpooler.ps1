function Remediate-PrintSpooler {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting Print Spooler remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("Print Spooler GPO", "Create GPO to disable Print Spooler")) {
            $gpoName = "Harden_AD_PrintSpooler_Disable"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Disable Print Spooler service to prevent PrintNightmare attacks"
            
            # Configure service startup to Disabled
            $servicePath = "HKLM\SYSTEM\CurrentControlSet\Services\Spooler"
            Set-GPRegistryValue -Name $gpoName -Key $servicePath -ValueName "Start" -Value 4 -Type DWord
            
            Write-Host "[Remediation] GPO '$gpoName' created and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Service setting: Spooler Start = 4 (Disabled)" -ForegroundColor Cyan
            Write-Host "WARNING: This will disable printing functionality. Apply only to Domain Controllers." -ForegroundColor Yellow
            Write-ADHCLog "Print Spooler GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during Print Spooler remediation: $($_.Exception.Message)"
    }
}







