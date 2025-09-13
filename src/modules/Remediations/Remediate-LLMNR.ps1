function Remediate-LLMNR {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs","")]
    param(
        [string]$SettingsPath = "$PSScriptRoot/../../config/settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting LLMNR remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    $regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"

    try {
        $current = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        $currentValue = if ($null -ne $current) { $current.EnableMulticast } else { "NotConfigured" }

        if ($PSCmdlet.ShouldProcess("LLMNR", "Disable LLMNR via registry")) {
            if ($currentValue -ne 0) {
                # Créer la clé si elle n'existe pas
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }

                Set-ItemProperty -Path $regPath -Name "EnableMulticast" -Value 0 -Force
                Write-Host "[Remediation] LLMNR désactivé (EnableMulticast=0)." -ForegroundColor Green
                Write-ADHCLog "LLMNR successfully disabled via registry"
            }
            else {
                Write-Host "[Remediation] LLMNR déjà désactivé, aucune action nécessaire." -ForegroundColor Yellow
                Write-ADHCLog "No change needed, LLMNR already disabled"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation LLMNR : $($_.Exception.Message)"
    }
}
