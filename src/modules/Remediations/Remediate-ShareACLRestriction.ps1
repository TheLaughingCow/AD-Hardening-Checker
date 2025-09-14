function Remediate-ShareACLRestriction {
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
        if ($PSCmdlet.ShouldProcess("Share ACLs", "Restrict to least privilege")) {
            try {
                $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {$_.ShareType -eq "FileSystemDirectory"}
                
                $modifiedShares = @()
                
                foreach ($share in $shares) {
                    try {
                        $shareAccess = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                        
                        $hasEveryone = $shareAccess | Where-Object {$_.AccountName -eq "Everyone" -and $_.AccessRight -eq "Full"}
                        $hasAnonymous = $shareAccess | Where-Object {$_.AccountName -eq "ANONYMOUS LOGON"}
                        $hasDomainUsers = $shareAccess | Where-Object {$_.AccountName -eq "Domain Users" -and $_.AccessRight -eq "Full"}
                        
                        if ($hasEveryone -or $hasAnonymous -or $hasDomainUsers) {
                            Write-Host "  - Modification des permissions pour: $($share.Name)" -ForegroundColor Cyan
                            
                            if ($hasEveryone) {
                                Revoke-SmbShareAccess -Name $share.Name -AccountName "Everyone" -Force -ErrorAction SilentlyContinue
                            }
                            if ($hasAnonymous) {
                                Revoke-SmbShareAccess -Name $share.Name -AccountName "ANONYMOUS LOGON" -Force -ErrorAction SilentlyContinue
                            }
                            if ($hasDomainUsers) {
                                Revoke-SmbShareAccess -Name $share.Name -AccountName "Domain Users" -Force -ErrorAction SilentlyContinue
                            }
                            
                            $modifiedShares += $share.Name
                        }
                    }
                    catch {
                        Write-Warning "Impossible de modifier les permissions du partage $($share.Name): $($_.Exception.Message)"
                    }
                }
                
                if ($modifiedShares.Count -gt 0) {
                    Write-Host "[Remediation] Permissions restrictives appliquées sur $($modifiedShares.Count) partages"
                Write-ADHCLog "Remediation applied successfully" -ForegroundColor Green
                    Write-Host "Partages modifiés: $($modifiedShares -join ', ')" -ForegroundColor Cyan
                } else {
                    Write-Host "[Remediation] Tous les partages ont déjà des permissions restrictives" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Error "Erreur lors de la modification des permissions des partages : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation Share ACL Restriction : $($_.Exception.Message)"
    }
}

