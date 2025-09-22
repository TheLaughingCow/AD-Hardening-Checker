function Remediate-LAPS {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param([string]$SettingsPath="$PSScriptRoot\..\..\..\config\settings.json")

    if (Test-Path $SettingsPath) { $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json } else { $settings = @{ EnableWhatIfByDefault = $true } }
    Write-Host "[INFO] Starting LAPS remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("LAPS GPO", "Install and configure Windows/Legacy LAPS via startup script")) {
            $gpoName="Harden_AD_LAPS_Configure"
            $existingGPO=Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) { Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow; return }

            $gpo=New-GPO -Name $gpoName -Comment "Install and configure LAPS via startup script"
            $scriptDir=Join-Path $env:TEMP "Scripts"; if (-not (Test-Path $scriptDir)) { New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null }

$startupScript = @"
Write-Host "Installing and configuring LAPS..." -ForegroundColor Yellow
try {
    try {
        Add-WindowsCapability -Online -Name Windows.LAPS~~~~0.0.1.0 -ErrorAction SilentlyContinue | Out-Null
        Write-Host "  _ Windows LAPS capability attempted" -ForegroundColor Cyan
    } catch {}
    `$lapsNew = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS"
    `$lapsOld = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
    New-Item -Path `$lapsNew -Force | Out-Null
    New-Item -Path `$lapsOld -Force | Out-Null
    Set-ItemProperty -Path `$lapsNew -Name "PasswordComplexity" -Value 4 -Force
    Set-ItemProperty -Path `$lapsNew -Name "PasswordLength" -Value 14 -Force
    Set-ItemProperty -Path `$lapsNew -Name "PasswordAgeDays" -Value 30 -Force
    Set-ItemProperty -Path `$lapsNew -Name "BackupDirectory" -Value 1 -Force
    Set-ItemProperty -Path `$lapsNew -Name "IsEnabled" -Value 1 -Force
    Set-ItemProperty -Path `$lapsOld -Name "AdmPwdEnabled" -Value 1 -Force
    Set-ItemProperty -Path `$lapsOld -Name "PasswordComplexity" -Value 4 -Force
    Set-ItemProperty -Path `$lapsOld -Name "PasswordLength" -Value 14 -Force
    Set-ItemProperty -Path `$lapsOld -Name "PasswordAgeDays" -Value 30 -Force
    Write-Host "  _ LAPS policy configured (Windows + legacy)" -ForegroundColor Green
} catch { Write-Host "  _ Failed: `$(`$_.Exception.Message)" -ForegroundColor Red }
"@

            $scriptPath=Join-Path $scriptDir "Configure-LAPS.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoSysvolPath="\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoSysvolPath)) { New-Item -ItemType Directory -Path $gpoSysvolPath -Force | Out-Null }
            Copy-Item -Path $scriptPath -Destination $gpoSysvolPath -Force

            $scriptGpoPath="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Configure-LAPS.ps1" -Type String -ErrorAction Stop

            Write-Host "[Remediation] GPO '$gpoName' created and startup script configured" -ForegroundColor Green
            Write-Host "  _ SYSVOL Path: $gpoSysvolPath" -ForegroundColor Cyan
            Write-Host "  _ Schema/ACL AD requis séparément si non faits" -ForegroundColor Yellow
            return $gpoName
        }
    } catch { Write-Host "ERROR during LAPS remediation: $($_.Exception.Message)" -ForegroundColor Red }
}
