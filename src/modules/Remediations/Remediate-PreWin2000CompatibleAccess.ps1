function Remediate-PreWin2000CompatibleAccess {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        Write-Verbose "Fichier settings.json introuvable, utilisation des valeurs par défaut."
        $settings = @{ EnableWhatIfByDefault = $true }
    
    Write-ADHCLog "Starting remediation (WhatIf: $($settings.EnableWhatIfByDefault))"
    }

    try {
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            Write-Error "Module Active Directory non disponible. Impossible d'appliquer la remédiation."
            return
        }

        if ($PSCmdlet.ShouldProcess("Pre-Windows 2000 Compatible Access Group", "Remove all members")) {
            try {
                $groupMembers = Get-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" -ErrorAction SilentlyContinue
                
                if (-not $groupMembers) {
                    Write-Host "[Remediation] Groupe Pre-Windows 2000 Compatible Access déjà vide" -ForegroundColor Yellow
                    return
                }
                
                Write-Host "[Remediation] Suppression de $($groupMembers.Count) membres du groupe Pre-Windows 2000 Compatible Access..." -ForegroundColor Green
                
                foreach ($member in $groupMembers) {
                    try {
                        Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" -Members $member.SamAccountName -Confirm:$false
                        Write-Host "  - Supprimé: $($member.Name)" -ForegroundColor Cyan
                    }
                    catch {
                        Write-Warning "Impossible de supprimer $($member.Name) du groupe : $($_.Exception.Message)"
                    }
                }
                
                Write-Host "[Remediation] Groupe Pre-Windows 2000 Compatible Access vidé" -ForegroundColor Green
            }
            catch {
                Write-Error "Erreur lors de la vidage du groupe Pre-Windows 2000 Compatible Access : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation Pre-Windows 2000 Compatible Access : $($_.Exception.Message)"
    }
}

