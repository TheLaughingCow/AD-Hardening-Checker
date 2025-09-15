function Remediate-<Name> {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs","")]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json",
        [string]$GPOName = "AD-Hardening-<Name>",
        [string]$GPODescription = "Security hardening policy for <Name>",
        [switch]$LinkToDomain,
        [switch]$LinkToOU,
        [string]$TargetOU
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting <Name> GPO remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        # Vérifier que le module GroupPolicy est disponible
        if (-not (Get-Module -Name GroupPolicy -ListAvailable)) {
            Write-Error "Group Policy module not available. Install RSAT tools."
            return
        }

        Import-Module GroupPolicy -Force

        if ($PSCmdlet.ShouldProcess("GPO: $GPOName", "Create Group Policy Object for <Name> hardening")) {
            
            # Vérifier si la GPO existe déjà
            $existingGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[GPO] Policy '$GPOName' already exists. Updating..." -ForegroundColor Yellow
                $gpo = $existingGPO
            } else {
                # Créer la nouvelle GPO
                $gpo = New-GPO -Name $GPOName -Comment $GPODescription
                Write-Host "[GPO] Created policy: $GPOName" -ForegroundColor Green
            }

            # Configurer les paramètres de la GPO
            # Exemple pour LLMNR :
            # Set-GPRegistryValue -Guid $gpo.Id -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Value 0 -Type DWord

            # Lier la GPO si demandé
            if ($LinkToDomain) {
                if ($PSCmdlet.ShouldProcess("Domain", "Link GPO to domain root")) {
                    $domain = Get-ADDomain
                    New-GPLink -Guid $gpo.Id -Target $domain.DistinguishedName
                    Write-Host "[GPO] Linked to domain: $($domain.DNSRoot)" -ForegroundColor Green
                }
            }

            if ($LinkToOU -and $TargetOU) {
                if ($PSCmdlet.ShouldProcess("OU: $TargetOU", "Link GPO to Organizational Unit")) {
                    New-GPLink -Guid $gpo.Id -Target $TargetOU
                    Write-Host "[GPO] Linked to OU: $TargetOU" -ForegroundColor Green
                }
            }

            Write-Host "[GPO] Policy '$GPOName' configured successfully" -ForegroundColor Green
            Write-Host "[GPO] GUID: $($gpo.Id)" -ForegroundColor Cyan
            Write-Host "[GPO] You can now link this policy to any OU or domain as needed" -ForegroundColor Yellow
            
            Write-ADHCLog "GPO '$GPOName' created/updated successfully (GUID: $($gpo.Id))"
        }

    } catch {
        Write-Error "Failed to create GPO for <Name>: $($_.Exception.Message)"
        Write-ADHCLog "Error creating GPO for <Name>: $($_.Exception.Message)"
    }
}
