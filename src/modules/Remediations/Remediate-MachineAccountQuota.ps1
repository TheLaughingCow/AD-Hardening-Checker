function Remediate-MachineAccountQuota {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs","")]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting MachineAccountQuota remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            Write-Error "Module Active Directory non disponible. Impossible d'appliquer la remédiation."
            return
        }

        # Obtenir le domaine actuel
        $domain = Get-ADDomain -ErrorAction SilentlyContinue
        if (-not $domain) {
            Write-Error "Impossible d'accéder au domaine Active Directory"
            return
        }

        $currentValue = $domain."msDS-MachineAccountQuota"
        if ($PSCmdlet.ShouldProcess("MachineAccountQuota", "Set msDS-MachineAccountQuota to 0")) {
            if ($currentValue -ne 0) {
                Set-ADDomain -Identity $domain.DNSRoot -Replace @{ "msDS-MachineAccountQuota" = 0 }
                Write-Host "[Remediation] msDS-MachineAccountQuota mis à 0" -ForegroundColor Green
                Write-ADHCLog "msDS-MachineAccountQuota successfully set to 0"
            } else {
                Write-Host "[Remediation] msDS-MachineAccountQuota est déjà 0" -ForegroundColor Yellow
                Write-ADHCLog "No change needed, already 0"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation MachineAccountQuota : $($_.Exception.Message)"
    }
}
