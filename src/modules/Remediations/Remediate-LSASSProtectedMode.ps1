function Remediate-LSASSProtectedMode {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param([string]$SettingsPath="$PSScriptRoot\..\..\..\config\settings.json")

    if (Test-Path $SettingsPath) { $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json } else { $settings = @{ EnableWhatIfByDefault = $true } }
    Write-Host "[INFO] Starting LSASS Protected Mode remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("LSASS Protected Mode GPO", "Create GPO to enable LSASS Protection")) {
            $gpoName = "Harden_AD_LSASSProtectedMode_Enable"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) { Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow; return }

            $gpo = New-GPO -Name $gpoName -Comment "Enable LSASS Protection (RunAsPPL)"
            $scriptDir = Join-Path $env:TEMP "Scripts"; if (-not (Test-Path $scriptDir)) { New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null }

$startupScript = @"
Write-Host "Enabling LSASS Protected Mode (RunAsPPL)..." -ForegroundColor Yellow
`$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
try {
    New-Item -Path `$lsaPath -Force | Out-Null
    Set-ItemProperty -Path `$lsaPath -Name "RunAsPPL" -Value 1 -Force
    Set-ItemProperty -Path `$lsaPath -Name "RunAsPPLBoot" -Value 1 -Force
    Write-Host "  _ LSASS Protection enabled, reboot required" -ForegroundColor Green
} catch { Write-Host "  _ Failed: `$(`$_.Exception.Message)" -ForegroundColor Red }
"@

            $scriptPath = Join-Path $scriptDir "Enable-LSASSProtection.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoSysvolPath="\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoSysvolPath)) { New-Item -ItemType Directory -Path $gpoSysvolPath -Force | Out-Null }
            Copy-Item -Path $scriptPath -Destination $gpoSysvolPath -Force

            $scriptGpoPath="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Enable-LSASSProtection.ps1" -Type String -ErrorAction Stop

            Write-Host "[Remediation] GPO '$gpoName' created and LSASS protection script deployed" -ForegroundColor Green
            Write-Host "  _ SYSVOL Path: $gpoSysvolPath" -ForegroundColor Cyan
            Write-Host "  _ Reboot required for PPL to take effect" -ForegroundColor Yellow
            return $gpoName
        }
    } catch { Write-Host "ERROR during LSASS Protected Mode remediation: $($_.Exception.Message)" -ForegroundColor Red; throw }
}
