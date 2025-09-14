function Remediate-LLMNR {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs","")]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json",
        [string]$GPOName = "AD-Hardening-LLMNR-Disable",
        [string]$GPODescription = "Disables LLMNR (Link-Local Multicast Name Resolution) to prevent NBT-NS poisoning attacks",
        [switch]$LinkToDomain,
        [switch]$LinkToOU,
        [string]$TargetOU
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-ADHCLog "Starting LLMNR GPO remediation (WhatIf: $($settings.EnableWhatIfByDefault))"

    try {
        if (-not (Get-Module -Name GroupPolicy -ListAvailable)) {
            Write-Error "Group Policy module not available. Install RSAT tools."
            return
        }

        Import-Module GroupPolicy -Force

        if ($PSCmdlet.ShouldProcess("GPO: $GPOName", "Create Group Policy Object for LLMNR hardening")) {
            
            $existingGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[GPO] Policy '$GPOName' already exists. Updating..." -ForegroundColor Yellow
                $gpo = $existingGPO
            } else {
                $gpo = New-GPO -Name $GPOName -Comment $GPODescription
                Write-Host "[GPO] Created policy: $GPOName" -ForegroundColor Green
            }

            Set-GPRegistryValue -Guid $gpo.Id -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Value 0 -Type DWord
            
            Write-Host "[GPO] Configured registry setting: EnableMulticast = 0" -ForegroundColor Green

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
        Write-Error "Failed to create GPO for LLMNR: $($_.Exception.Message)"
        Write-ADHCLog "Error creating GPO for LLMNR: $($_.Exception.Message)"
    }
}
