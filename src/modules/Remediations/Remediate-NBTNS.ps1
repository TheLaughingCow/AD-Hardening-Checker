function Remediate-NBTNS {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param([string]$SettingsPath="$PSScriptRoot\..\..\..\config\settings.json")

    if (Test-Path $SettingsPath) { $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json } else { $settings = @{ EnableWhatIfByDefault = $true } }
    Write-Host "[INFO] Starting NBT-NS remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("NBT-NS GPO", "Create GPO with startup script to disable NetBIOS")) {
            $gpoName="Harden_AD_NBTNS_Disable"
            $existingGPO=Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) { Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow; return }

            $gpo=New-GPO -Name $gpoName -Comment "Disable NetBIOS over TCP/IP (NBT-NS)"
            $scriptDir=Join-Path $env:TEMP "Scripts"; if (-not (Test-Path $scriptDir)) { New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null }

$startupScript = @"
Write-Host "Disabling NetBIOS over TCP/IP..." -ForegroundColor Yellow
try {
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue | ForEach-Object {
        Set-ItemProperty -Path `$_.PsPath -Name "NetbiosOptions" -Value 2 -Force
        Write-Host "  _ Set NetbiosOptions=2 on `$($_.PSChildName)" -ForegroundColor Cyan
    }
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | ForEach-Object { `$_.SetTcpipNetbios(2) | Out-Null }
    Write-Host "  _ NetBIOS disabled on all interfaces" -ForegroundColor Green
} catch { Write-Host "  _ Failed: `$(`$_.Exception.Message)" -ForegroundColor Red }
"@

            $scriptPath=Join-Path $scriptDir "Disable-NBTNS.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoSysvolPath="\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoSysvolPath)) { New-Item -ItemType Directory -Path $gpoSysvolPath -Force | Out-Null }
            Copy-Item -Path $scriptPath -Destination $gpoSysvolPath -Force

            $scriptGpoPath="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Disable-NBTNS.ps1" -Type String -ErrorAction Stop

            Write-Host "[Remediation] GPO '$gpoName' created and startup script deployed" -ForegroundColor Green
            Write-Host "  _ SYSVOL Path: $gpoSysvolPath" -ForegroundColor Cyan
            Write-Host "  _ Reboot recommended" -ForegroundColor Yellow
            return $gpoName
        }
    } catch { Write-Host "ERROR during NBT-NS remediation: $($_.Exception.Message)" -ForegroundColor Red }
}
