function Remediate-CoercionPatches {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param([string]$SettingsPath="$PSScriptRoot\..\..\..\config\settings.json")

    if (Test-Path $SettingsPath) { $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json } else { $settings = @{ EnableWhatIfByDefault = $true } }
    Write-Host "[INFO] Starting Coercion Patches remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("Coercion Patches GPO", "Create GPO with startup script to install coercion patches")) {
            $gpoName="Harden_AD_CoercionPatches_Install"
            $existingGPO=Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) { Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow; return }

            $gpo=New-GPO -Name $gpoName -Comment "Install coercion attack patches via startup script with prerequisite checks"
            $scriptDir=Join-Path $env:TEMP "Scripts"; if (-not (Test-Path $scriptDir)) { New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null }

$startupScript = @"
Write-Host "Installing coercion attack patches..." -ForegroundColor Yellow
try {
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Install-PackageProvider -Name NuGet -Force -Scope AllUsers -ErrorAction SilentlyContinue
        Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers -ErrorAction SilentlyContinue
    }
    `$requiredPatches = @("KB5005413","KB5006744","KB5007205","KB5007262")
    if (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue) {
        Install-WindowsUpdate -KBArticleID `$requiredPatches -AcceptAll -AutoReboot -ErrorAction SilentlyContinue
        Write-Host "  _ Update task queued" -ForegroundColor Cyan
    } else {
        Write-Host "  _ PSWindowsUpdate not available" -ForegroundColor Yellow
    }
} catch { Write-Host "  _ Failed: `$(`$_.Exception.Message)" -ForegroundColor Red }
"@

            $scriptPath=Join-Path $scriptDir "Install-CoercionPatches.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoSysvolPath="\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoSysvolPath)) { New-Item -ItemType Directory -Path $gpoSysvolPath -Force | Out-Null }
            Copy-Item -Path $scriptPath -Destination $gpoSysvolPath -Force

            $scriptGpoPath="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Install-CoercionPatches.ps1" -Type String -ErrorAction Stop

            Write-Host "[Remediation] GPO '$gpoName' created and startup script configured" -ForegroundColor Green
            Write-Host "  _ SYSVOL Path: $gpoSysvolPath" -ForegroundColor Cyan
            return $gpoName
        }
    } catch { Write-Host "ERROR during Coercion Patches remediation: $($_.Exception.Message)" -ForegroundColor Red; throw }
}
