function Remediate-LDAPSigning {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param([string]$SettingsPath="$PSScriptRoot\..\..\..\config\settings.json")

    if (Test-Path $SettingsPath) { $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json } else { $settings = @{ EnableWhatIfByDefault = $true } }
    Write-Host "[INFO] Starting LDAP Signing remediation (WhatIf: $($settings.EnableWhatIfByDefault))" -ForegroundColor Cyan

    try {
        if ($PSCmdlet.ShouldProcess("LDAP Signing GPO", "Require LDAP signing (Security CSE)")) {
            $gpoName = "Harden_AD_LDAPSigning_Require"
            $existing = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Host "[Remediation] GPO '$gpoName' already exists" -ForegroundColor Yellow
                return
            }

            $gpo = New-GPO -Name $gpoName -Comment "Require LDAP signing via Security Settings (GptTmpl.inf) and enable client integrity"

            $dom = $env:USERDNSDOMAIN
            $polRoot = "\\$dom\SYSVOL\$dom\Policies\{$($gpo.Id)}"
            $secDir  = Join-Path $polRoot "Machine\Microsoft\Windows NT\SecEdit"
            $infPath = Join-Path $secDir  "GptTmpl.inf"
            $gptPath = Join-Path $polRoot "gpt.ini"

            if (-not (Test-Path $secDir)) { New-Item -ItemType Directory -Path $secDir -Force | Out-Null }

            $content = @()
            if (Test-Path $infPath) {
                $content = Get-Content -Path $infPath -Encoding ASCII
            } else {
                $content = @("[Unicode]","Unicode=yes","[Version]","signature=`"`$CHICAGO`$`"","Revision=1","[Registry Values]")
            }

            if (-not ($content -match '^\[Registry Values\]')) { $content += "[Registry Values]" }

            $content = $content | Where-Object {
                $_ -notmatch '^MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=' -and
                $_ -notmatch '^MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\RequireSecureSimpleBind=' -and
                $_ -notmatch '^MACHINE\\System\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity='
            }

            $lines = @(
                'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,2',
                'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\RequireSecureSimpleBind=4,1',
                'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=4,1'
            )

            $idx = ($content | Select-String '^\[Registry Values\]').LineNumber
            if ($idx) {
                $before = $content[0..($idx-1)]
                $after  = $content[$idx..($content.Count-1)]
                $content = @($before + $after[0] + $lines + $after[1..($after.Count-1)])
            } else {
                $content += $lines
            }

            Set-Content -Path $infPath -Value $content -Encoding ASCII

            if (Test-Path $gptPath) {
                $gpt = Get-Content -Path $gptPath -Encoding ASCII
                $verLine = $gpt | Where-Object { $_ -match '^Version=' }
                if ($verLine) {
                    $cur = [int]($verLine -split '=')[1]
                    $new = $cur + 65536
                    $gpt = $gpt -replace '^Version=\d+', ("Version={0}" -f $new)
                } else {
                    $gpt += 'Version=65536'
                }
                Set-Content -Path $gptPath -Value $gpt -Encoding ASCII
            } else {
                @('[General]','Version=65536') | Set-Content -Path $gptPath -Encoding ASCII
            }

            Write-Host "[Remediation] GPO '$gpoName' created and Security Settings authored" -ForegroundColor Green
            Write-Host "  _ MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity = 4,2" -ForegroundColor Cyan
            Write-Host "  _ MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\RequireSecureSimpleBind = 4,1" -ForegroundColor Cyan
            Write-Host "  _ MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity = 4,1" -ForegroundColor Cyan
            Write-Host "  _ Version incremented in gpt.ini to force CSE Security reapplied" -ForegroundColor Yellow
            Write-Host "  _ Link this GPO to Domain Controllers OU with highest precedence, then gpupdate /force and reboot DC" -ForegroundColor Yellow

            return $gpoName
        }
    }
    catch {
        Write-Host "ERROR during LDAP Signing remediation: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
