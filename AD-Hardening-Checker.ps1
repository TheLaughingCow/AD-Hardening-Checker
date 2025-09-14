#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("Audit", "Analysis", "Remediation")]
    [string]$Mode,
    
    [Parameter(Mandatory = $false)]
    [string]$CsvPath,
    
    [Parameter(Mandatory = $false, Position = 1)]
    [string[]]$RemediationList
)

$ScriptRoot = Split-Path -Parent $PSCommandPath

function Get-GPOInstructions {
    param([string]$CheckName)
    # Return GPO instructions in French without accents
    $gpoInstructions = @{
        "Password Policy Partially Compliant" = "Configuration ordinateur > Parametres Windows > Parametres de securite > Strategies de comptes > Strategie de mot de passe"
        "LAPS Not Detected" = "Configuration ordinateur > Modeles d'administration > Systeme > LAPS > 'Activer la solution de mot de passe administrateur local' = Active"
        "LSASS Unprotected" = "Configuration ordinateur > Modeles d'administration > Systeme > Credential Guard > 'Activer Credential Guard' = Active avec verrouillage UEFI"
        "Print Spooler Disabled" = "Configuration ordinateur > Modeles d'administration > Imprimantes > 'Autoriser le spouleur d'impression a accepter les connexions client' = Desactive"
        "MachineAccountQuota Secured" = "Configuration ordinateur > Modeles d'administration > Systeme > Net Logon > 'Quota de compte d'ordinateur' = 0"
        "Default Credentials Secured" = "Configuration ordinateur > Parametres Windows > Parametres de securite > Strategies locales > Attribution des droits utilisateur > 'Refuser l'ouverture de session locale' = Ajouter les comptes de service"
        "Service Accounts Not Secured" = "Configuration ordinateur > Parametres Windows > Parametres de securite > Strategies locales > Attribution des droits utilisateur > 'Refuser l'ouverture de session locale' = Ajouter les comptes de service"
        "Unconstrained Delegation Detected" = "Configuration ordinateur > Parametres Windows > Parametres de securite > Strategies locales > Attribution des droits utilisateur > 'Activer les comptes d'ordinateur et d'utilisateur pour qu'ils soient approuves pour la delegation' = Supprimer tout"
        "PASSWD_NOTREQD Accounts Found" = "Configuration ordinateur > Parametres Windows > Parametres de securite > Strategies de comptes > Strategie de mot de passe > 'Le mot de passe n'est pas requis' = Desactive"
        "Kerberos Pre-Auth Fully Enforced" = "Configuration ordinateur > Parametres Windows > Parametres de securite > Strategies de comptes > Strategie Kerberos > 'Appliquer les restrictions de connexion utilisateur' = Active"
        "Coercion Patches Missing" = "Windows Update > Installer KB5005413, KB5006744, KB5007205, KB5007262 (correctifs PetitPotam/Relay)"
        "RID Brute Force Protection Partial" = "Configuration ordinateur > Modeles d'administration > Systeme > Net Logon > 'Desactiver Net Logon' = Active"
        "Security Baseline Check Error" = "Configuration ordinateur > Parametres Windows > Parametres de securite > Strategies locales > Options de securite > Examiner tous les parametres"
        "Pre-Windows 2000 Check Error" = "Configuration ordinateur > Parametres Windows > Parametres de securite > Strategies locales > Attribution des droits utilisateur > 'Acceder a cet ordinateur a partir du reseau' = Supprimer Tout le monde"
        "Protected Users Group" = "Configuration ordinateur > Parametres Windows > Parametres de securite > Groupes restreints > Ajouter le groupe 'Protected Users'"
        "Tiered Admin Model Missing" = "Creer des UO separees pour les comptes administrateur Tier 0, 1, 2 avec differents GPO"
        "Share ACL Restriction" = "Configuration ordinateur > Parametres Windows > Parametres de securite > Strategies locales > Attribution des droits utilisateur > 'Acceder a cet ordinateur a partir du reseau' = Supprimer Tout le monde"
    }
    
    if ($gpoInstructions.ContainsKey($CheckName)) {
        return $gpoInstructions[$CheckName]
    }
    return "GPO configuration required"
}

Write-Host "Loading Check-* functions..." -ForegroundColor Yellow
$checksPath = Join-Path $ScriptRoot "src\modules\Checks"
$checkFiles = Get-ChildItem -Path $checksPath -Filter "Check-*.ps1" -File -ErrorAction SilentlyContinue

$loadedFunctions = @()
foreach ($file in $checkFiles) {
    try {
        . $file.FullName
        $functionName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $loadedFunctions += $functionName
        Write-Verbose "Function loaded: $functionName"
    }
    catch {
        Write-Warning "Unable to load $($file.Name): $($_.Exception.Message)"
    }
}

Write-Host "Functions loaded: $($loadedFunctions.Count)" -ForegroundColor Green

if (Get-Module -Name ActiveDirectory -ListAvailable) {
    try {
        Import-Module ActiveDirectory -Force -ErrorAction Stop
        Write-Verbose "Active Directory module imported successfully"
    }
    catch {
        Write-Warning "Unable to import Active Directory module: $($_.Exception.Message)"
    }
} else {
    Write-Warning "Active Directory module not available on this system"
}

    $utilsPath = Join-Path $ScriptRoot "src\Utils.psm1"
    if (Test-Path $utilsPath) {
        try {
            Import-Module $utilsPath -Force -ErrorAction Stop
            Write-Verbose "Utils module imported successfully"
        }
        catch {
            Write-Warning "Unable to import Utils module: $($_.Exception.Message)"
        }
    } else {
        Write-Warning "Utils module not found at: $utilsPath"
    }
    
    $languageUtilsPath = Join-Path $ScriptRoot "src\Utils-Language.psm1"
    if (Test-Path $languageUtilsPath) {
        try {
            Import-Module $languageUtilsPath -Force -ErrorAction Stop
            Write-Verbose "Language Utils module imported successfully"
        }
        catch {
            Write-Warning "Unable to import Language Utils module: $($_.Exception.Message)"
        }
    } else {
        Write-Warning "Language Utils module not found at: $languageUtilsPath"
    }
    
    $systemLanguage = Get-SystemLanguage
    Write-Host "System Language Detected: $systemLanguage" -ForegroundColor Cyan

$remediationPath = Join-Path $ScriptRoot "src\modules\Remediations"
$remediationFiles = Get-ChildItem -Path $remediationPath -Filter "Remediate-*.ps1" -File -ErrorAction SilentlyContinue

foreach ($file in $remediationFiles) {
    try {
        . $file.FullName
        Write-Verbose "Remediation module loaded: $($file.Name)"
    }
    catch {
        Write-Warning "Unable to load $($file.Name): $($_.Exception.Message)"
    }
}

$Settings = @{
    CsvPath = Join-Path $ScriptRoot "results\AD_Hardening_Report.csv"
    LogPath = Join-Path $ScriptRoot "results\logs\AD_Hardening.log"
    FailThreshold = 0
    WarnThreshold = 5
    AllowedRemediations = @(1..27)
    QuickWinPriority = @(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
    Color_PASS = "Green"
    Color_FAIL = "Red"
    Color_WARN = "DarkYellow"
    Color_INFO = "Cyan"
}

$resultsDir = Join-Path $ScriptRoot "results"
$logsDir = Join-Path $resultsDir "logs"

if (-not (Test-Path $resultsDir)) {
    New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null
    Write-Verbose "Created results directory: $resultsDir"
}

if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    Write-Verbose "Created logs directory: $logsDir"
}

if ($CsvPath) {
    $Settings.CsvPath = $CsvPath
}

Write-Host ""
Write-Host "=== AD HARDENING CHECKER ===" -ForegroundColor Cyan
Write-Host "Mode: $Mode" -ForegroundColor White
Write-Host "CSV Path: $($Settings.CsvPath)" -ForegroundColor White
Write-Host "Log Path: $($Settings.LogPath)" -ForegroundColor White
Write-Host ""

if ($Mode -eq "Audit") {
    Write-Host "=== AUDIT MODE ===" -ForegroundColor Yellow
    Write-Host "Executing security controls..." -ForegroundColor White
    
    $totalChecks = 0
    $passedChecks = 0
    $failedChecks = 0
    $warnedChecks = 0
    
    # Initialiser le fichier CSV
    if (-not (Test-Path $Settings.CsvPath)) {
        $header = "ID,Action,Status,DetectedValue,Recommendation"
        $header | Out-File -FilePath $Settings.CsvPath -Encoding UTF8 -Force
    }
    
    foreach ($functionName in $loadedFunctions) {
        if (Get-Command -Name $functionName -ErrorAction SilentlyContinue) {
            try {
                Write-Host "Executing: $functionName" -ForegroundColor Cyan
                $result = & $functionName
                $totalChecks++
                
                if ($null -ne $result -and $result.PSObject.Properties.Name -contains "Status") {
                    # Exporter directement le résultat
                    $result | Export-Csv -Path $Settings.CsvPath -Append -NoTypeInformation -Encoding UTF8
                    
                    # Affichage formaté avec détails
                    $statusIcon = switch ($result.Status) {
                        "PASS" { "[OK]"; $passedChecks++; "Green" }
                        "OK" { "[OK]"; $passedChecks++; "Green" }
                        "FAIL" { "[FAIL]"; $failedChecks++; "Red" }
                        "WARN" { "[WARN]"; $warnedChecks++; "Yellow" }
                        default { "[?]"; "Yellow" }
                    }
                    
                    $color = $statusIcon[1]
                    $icon = $statusIcon[0]
                    
                    Write-Host "  $icon $($result.Action)" -ForegroundColor $color
                } else {
                    Write-Host "  [?] No valid result returned" -ForegroundColor Yellow
                    $warnedChecks++
                }
            }
            catch {
                Write-Warning "Error executing $functionName : $($_.Exception.Message)"
                $totalChecks++
            }
        }
    }
    
    Write-Host ""
    Write-Host "Results exported to: $($Settings.CsvPath)" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "=== AUDIT SUMMARY ===" -ForegroundColor Cyan
    Write-Host "+=========================================+" -ForegroundColor Cyan
    Write-Host "| Total Controls: $($totalChecks.ToString().PadLeft(2))                      |" -ForegroundColor Cyan
    Write-Host "| [OK] Passed: $($passedChecks.ToString().PadLeft(2))                         |" -ForegroundColor Cyan
    Write-Host "| [FAIL] Failed: $($failedChecks.ToString().PadLeft(2))                       |" -ForegroundColor Cyan
    Write-Host "| [WARN] Warnings: $($warnedChecks.ToString().PadLeft(2))                     |" -ForegroundColor Cyan
    Write-Host "+=========================================+" -ForegroundColor Cyan
    
    if ($failedChecks -gt 0) {
        Write-Host ""
        Write-Host "*** SECURITY ALERT: $failedChecks control(s) have failed! ***" -ForegroundColor Red
        Write-Host "   These issues must be fixed immediately!" -ForegroundColor Red
        Write-Host "   Check the CSV report for detailed information." -ForegroundColor Yellow
    }
    
    if ($warnedChecks -gt 0) {
        Write-Host ""
        Write-Host "*** WARNING: $warnedChecks control(s) need attention. ***" -ForegroundColor Yellow
        Write-Host "   Review these items and fix if necessary." -ForegroundColor Yellow
    }
}

elseif ($Mode -eq "Analysis") {
    Write-Host "=== ANALYSIS MODE ===" -ForegroundColor Yellow
    
    if (-not (Test-Path $Settings.CsvPath)) {
        Write-Error "CSV file not found: $($Settings.CsvPath)"
        Write-Host "Run Audit mode first to generate the report." -ForegroundColor Yellow
        exit 1
    }
    
    try {
        $results = Import-Csv -Path $Settings.CsvPath -Encoding UTF8
        Write-Host "Report loaded: $($results.Count) results" -ForegroundColor Green
    }
    catch {
        Write-Error "Unable to load CSV report: $($_.Exception.Message)"
        exit 1
    }
    
    $groupedResults = $results | Group-Object Status
    $passCount = (($groupedResults | Where-Object { $_.Name -eq "PASS" }).Count) + (($groupedResults | Where-Object { $_.Name -eq "OK" }).Count)
    $failCount = ($groupedResults | Where-Object { $_.Name -eq "FAIL" }).Count
    $warnCount = ($groupedResults | Where-Object { $_.Name -eq "WARN" }).Count
    $errorCount = ($groupedResults | Where-Object { $_.Name -eq "ERROR" }).Count
    
    if ($failCount -gt 0) {
        Write-Host ""
        Write-Host "SECURITY ALERT: $failCount control(s) have failed!" -ForegroundColor Red
        Write-Host "These security issues must be fixed immediately." -ForegroundColor Red
    }
    
    if ($warnCount -gt 0) {
        Write-Host ""
        Write-Host "WARNING: $warnCount control(s) need attention." -ForegroundColor Yellow
        Write-Host "These items should be reviewed and fixed if necessary." -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "=== ANALYSIS SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Total controls: $($results.Count)" -ForegroundColor White
    Write-Host "Passed (PASS): $passCount" -ForegroundColor Green
    Write-Host "Failed (FAIL): $failCount" -ForegroundColor Red
    Write-Host "Warnings (WARN): $warnCount" -ForegroundColor Yellow
    Write-Host "Errors (ERROR): $errorCount" -ForegroundColor Yellow
    
    if ($failCount -gt 0) {
        Write-Host ""
        Write-Host "=== FAILURES BY PRIORITY ===" -ForegroundColor Red
        $failures = $results | Where-Object { $_.Status -eq "FAIL" } | Sort-Object Action
        foreach ($failure in $failures) {
            $priority = if ($failure.Priority) { $failure.Priority } else { "High" }
            $name = if ($failure.Name) { $failure.Name } else { $failure.Action }
            $priorityColor = switch ($priority) {
                "Critical" { "Red" }
                "High" { "Red" }
                "Medium" { "Yellow" }
                "Low" { "Gray" }
                default { "White" }
            }
            Write-Host "  [$priority] $name" -ForegroundColor $priorityColor
            if ($failure.Recommendation) {
                Write-Host "      -> $($failure.Recommendation)" -ForegroundColor Gray
            }
            if ($failure.DetectedValue) {
                Write-Host "      -> Detected: $($failure.DetectedValue)" -ForegroundColor DarkGray
            }
            $gpoInstructions = Get-GPOInstructions -CheckName $failure.Action
            if ($gpoInstructions) {
                Write-Host "      -> GPO: $gpoInstructions" -ForegroundColor Cyan
            }
        }
    }
    
    if ($warnCount -gt 0) {
        Write-Host ""
        Write-Host "=== WARNINGS ===" -ForegroundColor Yellow
        $warnings = $results | Where-Object { $_.Status -eq "WARN" } | Sort-Object Action
        foreach ($warning in $warnings) {
            $priority = if ($warning.Priority) { $warning.Priority } else { "Medium" }
            $name = if ($warning.Name) { $warning.Name } else { $warning.Action }
            $priorityColor = switch ($priority) {
                "Critical" { "Red" }
                "High" { "Red" }
                "Medium" { "Yellow" }
                "Low" { "Gray" }
                default { "White" }
            }
            Write-Host "  [$priority] $name" -ForegroundColor $priorityColor
            if ($warning.Recommendation) {
                Write-Host "      -> $($warning.Recommendation)" -ForegroundColor Gray
            }
            if ($warning.DetectedValue) {
                Write-Host "      -> Detected: $($warning.DetectedValue)" -ForegroundColor DarkGray
            }
            $gpoInstructions = Get-GPOInstructions -CheckName $warning.Action
            if ($gpoInstructions) {
                Write-Host "      -> GPO: $gpoInstructions" -ForegroundColor Cyan
            }
        }
    }
    
    if ($failCount -gt 0) {
        Write-Host ""
        Write-Host "Exit code: 2 (Critical failures detected)" -ForegroundColor Red
        exit 2
    } elseif ($warnCount -gt 0) {
        Write-Host ""
        Write-Host "Exit code: 1 (Warnings detected)" -ForegroundColor Yellow
        exit 1
    } else {
        Write-Host ""
        Write-Host "Exit code: 0 (All controls passed)" -ForegroundColor Green
        exit 0
    }
}

elseif ($Mode -eq "Remediation") {
    Write-Host "=== REMEDIATION MODE ===" -ForegroundColor Yellow
    
    if (-not (Get-Module -Name GroupPolicy -ListAvailable)) {
        Write-Error "GroupPolicy module not available. This module is required for remediation."
        Write-Host "Install the module with: Install-Module -Name GroupPolicy" -ForegroundColor Yellow
        exit 1
    }
    
    try {
        Import-Module GroupPolicy -Force -ErrorAction Stop
        Write-Verbose "GroupPolicy module imported successfully"
    }
    catch {
        Write-Error "Unable to import GroupPolicy module: $($_.Exception.Message)"
        exit 1
    }
    
    # Charger les fonctions de remediation
    Write-Host (Get-LocalizedMessages -MessageKey "LoadingRemediationFunctions") -ForegroundColor Gray
    $remediationPath = Join-Path $ScriptRoot "src\modules\Remediations"
    $remediationFiles = Get-ChildItem -Path $remediationPath -Filter "Remediate-*.ps1" -File -ErrorAction SilentlyContinue
    
    if ($remediationFiles) {
        foreach ($file in $remediationFiles) {
            try {
                . $file.FullName
                Write-Verbose "Loaded: $($file.BaseName)"
            }
            catch {
                Write-Warning "Failed to load $($file.Name): $($_.Exception.Message)"
            }
        }
        Write-Host (Get-LocalizedMessages -MessageKey "RemediationFunctionsLoaded") + ": $($remediationFiles.Count)" -ForegroundColor Green
    } else {
        Write-Warning "No remediation functions found in $remediationPath"
    }
    
    if ($RemediationList -contains "ALL") {
        $RemediationList = $Settings.AllowedRemediations
        Write-Host "ALL option detected: All remediations will be executed" -ForegroundColor Yellow
    }
    elseif ($RemediationList -contains "PRIORITY") {
        $RemediationList = $Settings.QuickWinPriority
        Write-Host "PRIORITY option detected: Priority remediations only" -ForegroundColor Yellow
    }
    elseif ($RemediationList -contains "FAILED") {
        if (Test-Path $Settings.CsvPath) {
            try {
                $auditResults = Import-Csv -Path $Settings.CsvPath -Encoding UTF8
                $failedIds = $auditResults | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object { [int]$_.ID }
                $RemediationList = $failedIds
                Write-Host "FAILED option detected: $($failedIds.Count) remediations for failures" -ForegroundColor Yellow
            }
            catch {
                Write-Error "Unable to load audit report: $($_.Exception.Message)"
                exit 1
            }
        } else {
            Write-Error "Audit file not found: $($Settings.CsvPath)"
            Write-Host "Run Audit mode first." -ForegroundColor Yellow
            exit 1
        }
    }
    else {
        # Convertir les IDs en entiers si ce sont des nombres
        $RemediationList = $RemediationList | ForEach-Object {
            if ($_ -match '^\d+$') {
                [int]$_
            } else {
                $_
            }
        }
    }
    
    if (-not $RemediationList -or $RemediationList.Count -eq 0) {
        Write-Host ""
        Write-Host "=== AVAILABLE OPTIONS ===" -ForegroundColor Cyan
        Write-Host "Usage: .\AD-Hardening-Checker.ps1 -Mode Remediation [OPTIONS]" -ForegroundColor White
        Write-Host ""
        Write-Host "Options:" -ForegroundColor Yellow
        Write-Host "  @(1,2,3)     - Specific remediations by ID" -ForegroundColor White
        Write-Host "  @(PRIORITY)  - Pre-defined priority remediations" -ForegroundColor White
        Write-Host "  @(FAILED)    - Remediations for audit failures" -ForegroundColor White
        Write-Host "  @(ALL)       - All available remediations" -ForegroundColor White
        Write-Host ""
        Write-Host "Examples:" -ForegroundColor Yellow
        Write-Host "  .\AD-Hardening-Checker.ps1 -Mode Remediation @(1,2,3)" -ForegroundColor Gray
        Write-Host "  .\AD-Hardening-Checker.ps1 -Mode Remediation @(PRIORITY)" -ForegroundColor Gray
        Write-Host "  .\AD-Hardening-Checker.ps1 -Mode Remediation @(FAILED)" -ForegroundColor Gray
        Write-Host "  .\AD-Hardening-Checker.ps1 -Mode Remediation @(ALL)" -ForegroundColor Gray
        exit 0
    }
    
    $remediationMap = @{
        1 = "Remediate-LLMNR"
        2 = "Remediate-NBTNS"
        3 = "Remediate-mDNSBonjour"
        4 = "Remediate-MachineAccountQuota"
        5 = "Remediate-SMBSigning"
        6 = "Remediate-LDAPSigning"
        7 = "Remediate-PrintSpooler"
        8 = "Remediate-SMBv1"
        9 = "Remediate-LAPS"
        10 = "Remediate-UnconstrainedDelegation"
        11 = "Remediate-ProtectedUsersGroup"
        12 = "Remediate-LSASSProtectedMode"
        13 = "Remediate-SMBNullSession"
        14 = "Remediate-LDAPAnonymousBind"
        15 = "Remediate-PasswordPolicy"
        16 = "Remediate-RIDBruteForceMitigation"
        17 = "Remediate-PreWin2000CompatibleAccess"
        18 = "Remediate-IPv6Management"
        19 = "Remediate-NTLMRestriction"
        20 = "Remediate-ShareACLRestriction"
        21 = "Remediate-DefaultCredentials"
        22 = "Remediate-KerberosPreAuth"
        23 = "Remediate-CoercionPatches"
        24 = "Remediate-TieringModel"
        25 = "Remediate-PasswdNotReqdFlag"
        26 = "Remediate-SecureServiceAccounts"
        27 = "Remediate-SecurityBaseline"
    }
    
    $createdGpos = @()
    $failedRemediations = @()
    
    Write-Host "Executing $($RemediationList.Count) remediation(s)..." -ForegroundColor White
    
    foreach ($id in $RemediationList) {
        if ($remediationMap.ContainsKey($id)) {
            $functionName = $remediationMap[$id]
            Write-Host ""
            Write-Host "Remediation $id : $functionName" -ForegroundColor Cyan
            
            try {
                if (Get-Command -Name $functionName -ErrorAction SilentlyContinue) {
                    $result = & $functionName -WhatIf:$WhatIfPreference
                    if ($result) {
                        $createdGpos += $result
                    }
                } else {
                    Write-Warning "Remediation function not found: $functionName"
                    $failedRemediations += $id
                }
            } catch {
                Write-Error "Error executing $functionName : $($_.Exception.Message)"
                $failedRemediations += $id
            }
        } else {
            Write-Warning "Invalid remediation ID: $id"
            $failedRemediations += $id
        }
    }
    
    Write-Host ""
    Write-Host "=== REMEDIATION SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Remediations executed: $($RemediationList.Count)" -ForegroundColor White
    Write-Host "GPOs created: $($createdGpos.Count)" -ForegroundColor Green
    Write-Host "Failures: $($failedRemediations.Count)" -ForegroundColor Red
    
    if ($createdGpos.Count -gt 0) {
        Write-Host ""
        Write-Host "=== CREATED GPOS ===" -ForegroundColor Green
        foreach ($gpo in $createdGpos) {
            Write-Host "  - $gpo" -ForegroundColor White
        }
        
        Write-Host ""
        Write-Host "=== NEXT STEPS ===" -ForegroundColor Yellow
        Write-Host "1. Open Group Policy Management Console (gpmc.msc)" -ForegroundColor White
        Write-Host "2. Navigate to 'Group Policy Objects'" -ForegroundColor White
        Write-Host "3. Link the created GPOs to desired domains or OUs" -ForegroundColor White
        Write-Host "4. Run 'gpupdate /force' on target computers" -ForegroundColor White
    }
    
    if ($failedRemediations.Count -gt 0) {
        Write-Host ""
        Write-Host "=== FAILED REMEDIATIONS ===" -ForegroundColor Red
        foreach ($id in $failedRemediations) {
            Write-Host "  - ID $id" -ForegroundColor White
        }
    }
}

Write-Host ""
Write-Host "=== EXECUTION COMPLETED ===" -ForegroundColor Green