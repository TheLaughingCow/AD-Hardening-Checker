# ==============================
# Utils.psm1
# Fonctions utilitaires globales
# ==============================

# --- Charger la configuration globale ---
function Get-ADHCSettings {
    param(
        [string]$SettingsPath = "$PSScriptRoot/../../config/settings.json"
    )
    if (Test-Path $SettingsPath) {
        try {
            return Get-Content $SettingsPath -Raw | ConvertFrom-Json
        }
        catch {
            Write-Warning "Impossible de parser $SettingsPath : $($_.Exception.Message)"
            return @{}
        }
    } else {
        Write-Verbose "Fichier settings.json introuvable, valeurs par défaut utilisées."
        return @{}
    }
}

# --- Exporter un résultat au CSV ---
function Export-ADHCResult {
    param(
        [Parameter(Mandatory=$true)] [PSCustomObject]$Result,
        [string]$CsvPath = "$PSScriptRoot/../results/AD_Hardening_Report.csv"
    )

    # Créer le répertoire si nécessaire
    $dir = Split-Path $CsvPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    # Créer l'en-tête si le fichier n'existe pas encore
    if (-not (Test-Path $CsvPath)) {
        "ID,Action,Status,DetectedValue,Recommendation" | Out-File $CsvPath -Encoding UTF8
    }

    # Exporter l'objet en CSV (append)
    $Result | Export-Csv -Path $CsvPath -Append -NoTypeInformation
}

# --- Affichage colorisé uniforme ---
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

    Write-Host ("[ID {0}] {1} → {2} (Detected: {3})" -f `
        $Result.ID, $Result.Action, $Result.Status, $Result.DetectedValue) -ForegroundColor $color
}

# --- Logger les actions de remédiation ---
function Write-ADHCLog {
    param(
        [string]$Message,
        [string]$LogPath = "$PSScriptRoot/../results/logs"
    )

    # Créer le répertoire si nécessaire
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = Join-Path $LogPath ("Remediation-{0}.log" -f (Get-Date -Format "yyyyMMdd"))
    "$timestamp `t $Message" | Out-File $logFile -Append -Encoding UTF8
}

# --- Fonction pour exécuter un bloc de remédiation avec ShouldProcess ---
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
