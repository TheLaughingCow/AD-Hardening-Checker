function Remediate-SMBNullSession {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath  -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting SMB Null Session remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if ($PSCmdlet.ShouldProcess("SMB Null Session GPO", "Create GPO to disable SMB Null Session")) {
            $gpoName = "Harden_AD_SMBNullSession_Disable"
            
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            # Create GPO
            $gpo = New-GPO -Name $gpoName  -Comment "Disable SMB Null Session to prevent anonymous access"
            
            # Configure SMB null session disable registry settings
            $lanmanPath = "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"
            Set-GPRegistryValue -Name $gpoName -Key $lanmanPath -ValueName "RestrictNullSessAccess" -Value 1 -Type DWord
            Set-GPRegistryValue -Name $gpoName -Key $lanmanPath -ValueName "NullSessionPipes" -Value "" -Type String
            Set-GPRegistryValue -Name $gpoName -Key $lanmanPath -ValueName "NullSessionShares" -Value "" -Type String
            
            Write-Host "[Remediation] GPO '$gpoName' created and exported to: $gpoName" -ForegroundColor Green
            Write-Host "Registry settings:" -ForegroundColor Cyan
            Write-Host "  _ $lanmanPath\RestrictNullSessAccess = 1" -ForegroundColor Cyan
            Write-Host "  _ $lanmanPath\NullSessionPipes = (empty)" -ForegroundColor Cyan
            Write-Host "  _ $lanmanPath\NullSessionShares = (empty)" -ForegroundColor Cyan
            Write-ADHCLog "SMB Null Session GPO created successfully"
            
            return $gpoName
        }
    }
    catch {
        Write-Error "Error during SMB Null Session remediation: $($_.Exception.Message)"
    }
}







