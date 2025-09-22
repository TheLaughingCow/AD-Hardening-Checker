function Remediate-mDNSBonjour {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ EnableWhatIfByDefault = $true }
    }

    Write-Host "[INFO] Starting mDNS/Bonjour remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("mDNS/Bonjour GPO", "Create GPO with startup script to disable mDNS/Bonjour, LLMNR, and NetBIOS")) {
            $gpoName = "Harden_AD_mDNSBonjour_Disable"
            $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Disable mDNS/Bonjour, LLMNR and NetBIOS over TCP/IP"

            $scriptDir = Join-Path $env:TEMP "Scripts"
            if (-not (Test-Path $scriptDir)) {
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
            }

            $startupScript = @"
Write-Host "Disabling mDNS (Bonjour), LLMNR, and NetBIOS..." -ForegroundColor Green
`$service = Get-Service -Name "mDNSResponder" -ErrorAction SilentlyContinue
if (`$service) {
    if (`$service.Status -eq "Running") {
        Stop-Service -Name "mDNSResponder" -Force -ErrorAction SilentlyContinue
        Write-Host "  _ mDNSResponder stopped" -ForegroundColor Green
    }
    Set-Service -Name "mDNSResponder" -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "  _ mDNSResponder disabled" -ForegroundColor Green
} else {
    Write-Host "  _ mDNSResponder not found (already removed or not installed)" -ForegroundColor Yellow
}
`$dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path `$dnsClientPath)) {
    New-Item -Path `$dnsClientPath -Force | Out-Null
}
Set-ItemProperty -Path `$dnsClientPath -Name "EnableMulticast" -Value 0 -Force
Write-Host "  _ LLMNR disabled via registry" -ForegroundColor Green
Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | ForEach-Object {
    `$result = `$_ .SetTcpipNetbios(2)
    if (`$result.ReturnValue -eq 0) {
        Write-Host "  _ NetBIOS disabled on interface: `$($_.Description)" -ForegroundColor Green
    }
}
Write-Host "  _ mDNS/Bonjour + LLMNR + NetBIOS remediation completed, reboot recommended" -ForegroundColor Cyan
"@

            $scriptPath = Join-Path $scriptDir "Disable-mDNSBonjour.ps1"
            Set-Content -Path $scriptPath -Value $startupScript -Encoding UTF8

            $gpoSysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
            if (-not (Test-Path $gpoSysvolPath)) {
                New-Item -ItemType Directory -Path $gpoSysvolPath -Force | Out-Null
            }
            Copy-Item -Path $scriptPath -Destination $gpoSysvolPath -Force

            $scriptGpoPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"
            Set-GPRegistryValue -Name $gpoName -Key $scriptGpoPath -ValueName "0" -Value "Disable-mDNSBonjour.ps1" -Type String

            Write-Host "[Remediation] GPO '$gpoName' created and startup script deployed" -ForegroundColor Green
            Write-Host "  _ SYSVOL Path: $gpoSysvolPath" -ForegroundColor Cyan
            Write-Host "  _ Reboot required for complete effect" -ForegroundColor Yellow

            return $gpoName
        }
    }
    catch {
        Write-Host "ERROR during mDNS/Bonjour remediation: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
