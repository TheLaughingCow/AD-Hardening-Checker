function Remediate-SecurityBaseline {
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
        if ($PSCmdlet.ShouldProcess("Security Baseline", "Apply basic security configurations")) {
            try {
                $actions = @()
                
                $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                $uacEnabled = Get-ItemProperty -Path $uacPath -Name "EnableLUA" -ErrorAction SilentlyContinue
                if (-not $uacEnabled -or $uacEnabled.EnableLUA -ne 1) {
                    if ($PSCmdlet.ShouldProcess("UAC", "Enable")) {
                        Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -Force
                        $actions += "UAC activé"
                    }
                }
                
                try {
                    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
                    if ($defenderStatus -and -not $defenderStatus.AntivirusEnabled) {
                        $actions += "Windows Defender désactivé - activation recommandée"
                    }
                }
                catch {
                    $actions += "Windows Defender non accessible"
                }
                
                $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                $disabledProfiles = $firewallProfiles | Where-Object {$_.Enabled -eq $false}
                if ($disabledProfiles) {
                    $actions += "Pare-feu désactivé sur: $($disabledProfiles.Name -join ', ')"
                }
                
                try {
                    $securityUpdates = Get-HotFix | Where-Object {$_.InstalledOn -gt (Get-Date).AddDays(-30)} | Where-Object {$_.Description -like "*Security*"}
                    if ($securityUpdates.Count -eq 0) {
                        $actions += "Aucune mise à jour de sécurité récente"
                    }
                }
                catch {
                    $actions += "Impossible de vérifier les mises à jour"
                }
                
                try {
                    $securityLogs = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
                    if (-not $securityLogs) {
                        $actions += "Logs de sécurité non accessibles"
                    }
                }
                catch {
                    $actions += "Logs de sécurité non configurés"
                }
                
                if ($actions.Count -gt 0) {
                    Write-Host "[Remediation] Problèmes de sécurité détectés:" -ForegroundColor Green
                    foreach ($action in $actions) {
                        Write-Host "  - $action" -ForegroundColor Cyan
                    }
                } else {
                    Write-Host "[Remediation] Configuration de sécurité de base déjà en place" -ForegroundColor Yellow
                }
                
                Write-Host "`nRecommandations pour améliorer la baseline de sécurité:" -ForegroundColor Yellow
                Write-Host "1. Installer toutes les mises à jour de sécurité Windows" -ForegroundColor Cyan
                Write-Host "2. Configurer les GPO de sécurité Microsoft\CIS" -ForegroundColor Cyan
                Write-Host "3. Activer l'audit de sécurité avancé" -ForegroundColor Cyan
                Write-Host "4. Configurer Windows Defender avec des règles avancées" -ForegroundColor Cyan
                Write-Host "5. Implémenter la surveillance continue (SIEM)" -ForegroundColor Cyan
                Write-Host "6. Configurer la sauvegarde et la récupération" -ForegroundColor Cyan
                
                if ($PSCmdlet.ShouldProcess("Security Commands", "Show examples")) {
                    Write-Host "`nExemples de commandes de sécurité:" -ForegroundColor Green
                    Write-Host "Get-WindowsUpdate -Install -AcceptAll -AutoReboot" -ForegroundColor Cyan
                    Write-Host "Set-MpPreference -DisableRealtimeMonitoring `$false" -ForegroundColor Cyan
                    Write-Host "Enable-NetFirewallRule -DisplayGroup 'Windows Defender Firewall'" -ForegroundColor Cyan
                }
            }
            catch {
                Write-Error "Erreur lors de l'application de la baseline de sécurité : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Erreur lors de la remédiation Security Baseline : $($_.Exception.Message)"
    }
}

