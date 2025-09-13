[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
function Remediate-SMBSigning {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [string]$SettingsPath = "$PSScriptRoot/../../../config/settings.json"
    )

    # Charger la configuration
    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        Write-Verbose "Fichier settings.json introuvable, utilisation des valeurs par défaut."
        $settings = @{ EnableWhatIfByDefault = $true }
    
    # Utiliser $settings pour éviter l'avertissement de variable inutilisée
    Write-ADHCLog "Starting remediation (WhatIf: $($settings.EnableWhatIfByDefault))"
    }

    try {
        if ($PSCmdlet.ShouldProcess("SMB Server Configuration", "Enable Security Signing")) {
            try {
                # Activer SMB Signing
                Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
                Set-SmbServerConfiguration -EnableSecuritySignature $true -Force
                
                Write-Host "[Remediation] SMB Signing activé et requis" -ForegroundColor Green
                Write-Host "Redémarrage requis pour appliquer les changements." -ForegroundColor Yellow
            }
            catch {
                Write-Error "Erreur lors de l'activation de SMB Signing : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation SMB Signing : $($_.Exception.Message)"
    }
}

