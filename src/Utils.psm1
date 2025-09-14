function Get-ADHCSettings {
    param(
        [string]$SettingsPath = "$PSScriptRoot/../../config\settings.json"
    )
    if (Test-Path $SettingsPath) {
        try {
            return Get-Content $SettingsPath -Raw | ConvertFrom-Json
        }
        catch {
            Write-Warning "Unable to parse $SettingsPath : $($_.Exception.Message)"
            return @{}
        }
    } else {
        Write-Verbose "settings.json file not found, using default values."
        return @{}
    }
}

function Export-ADHCResult {
    param(
        [Parameter(Mandatory=$true)] [PSCustomObject]$Result,
        [string]$CsvPath = "$PSScriptRoot/../results\AD_Hardening_Report.csv"
    )

    $dir = Split-Path $CsvPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    if (-not (Test-Path $CsvPath)) {
        "ID,Action,Status,DetectedValue,Recommendation" | Out-File $CsvPath -Encoding UTF8
    }

    if ($null -ne $Result) {
        $Result | Export-Csv -Path $CsvPath -Append -NoTypeInformation
    }
}

function Write-ADHCStatus {
    param(
        [Parameter(Mandatory=$true)] [PSCustomObject]$Result,
        [object]$Settings
    )

    $color = switch ($Result.Status) {
        "OK"   { $Settings.Color_OK   }
        "FAIL" { $Settings.Color_FAIL }
        "WARN" { $Settings.Color_WARN }
        default { "White" }
    }

    Write-Host ("[ID {0}] {1} -> {2} (Detected: {3})" -f `
        $Result.ID, $Result.Action, $Result.Status, $Result.DetectedValue) -ForegroundColor $color
}

function Write-ADHCLog {
    param(
        [string]$Message,
        [string]$LogPath = "$PSScriptRoot/../results\logs"
    )

    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = Join-Path $LogPath ("Remediation-{0}.log" -f (Get-Date -Format "yyyyMMdd"))
    "$timestamp `t $Message" | Out-File $logFile -Append -Encoding UTF8
}

function Invoke-ADHCRemediation {
    param(
        [Parameter(Mandatory=$true)] [string]$ActionName,
        [scriptblock]$Action,
        [switch]$WhatIf,
        [switch]$Confirm
    )

    if ($PSCmdlet.ShouldProcess($ActionName, "Remediation")) {
        & $Action
        Write-ADHCLog "Remediation applied: $ActionName"
    } else {
        Write-ADHCLog "Remediation skipped: $ActionName"
    }
}