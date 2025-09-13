#Requires -Version 5.1
<#
.SYNOPSIS
    Script d'audit et de remédiation pour le durcissement Active Directory

.DESCRIPTION
    Ce script permet d'auditer, analyser et remédier 27 points de durcissement Active Directory.
    Il fonctionne en trois modes : Audit, Analyse et Remediate.

.PARAMETER Mode
    Mode d'exécution : Audit, Analyse ou Remediate

.PARAMETER CsvPath
    Chemin vers le fichier CSV de résultats. Si non fourni, utilise la valeur de settings.json

.PARAMETER RemediationList
    Liste des IDs de contrôles à remédier (ex: 1,2,8). Utilisé avec -Mode Remediate

.PARAMETER WhatIf
    Affiche les actions qui seraient effectuées sans les exécuter

.PARAMETER Confirm
    Demande confirmation avant d'exécuter les actions

.EXAMPLE
    .\AD-Hardening-Checker.ps1 -Mode Audit
    Effectue un audit complet et exporte les résultats en CSV

.EXAMPLE
    .\AD-Hardening-Checker.ps1 -Mode Analyse
    Analyse les résultats d'audit précédents

.EXAMPLE
    .\AD-Hardening-Checker.ps1 -Mode Remediate -RemediationList 1,2,8 -WhatIf
    Affiche les remédiations qui seraient appliquées pour les contrôles 1, 2 et 8

.NOTES
    Auteur: Assistant IA
    Version: 1.0
    Compatible: PowerShell 5.1+ et PowerShell 7
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Audit", "Analyse", "Remediate")]
    [string]$Mode,
    
    [Parameter(Mandatory = $false)]
    [string]$CsvPath,
    
    [Parameter(Mandatory = $false)]
    [int[]]$RemediationList = @()
)

# ==============================
# INITIALISATION
# ==============================

# Déterminer le répertoire du script
$ScriptRoot = Split-Path -Parent $PSCommandPath

# Charger le système de modules
$LoadModulesPath = Join-Path $ScriptRoot "Load-Modules.ps1"
if (Test-Path $LoadModulesPath) {
    . $LoadModulesPath
    $LoadedModules = Import-ADHCModules
    if ($LoadedModules) {
        Write-Verbose "Modules chargés: $($LoadedModules.Checks.Count) tests, $($LoadedModules.Remediations.Count) remédiations"
    } else {
        Write-Error "Échec du chargement des modules"
        exit 1
    }
} else {
    Write-Error "Script Load-Modules.ps1 non trouvé: $LoadModulesPath"
    exit 1
}

# Importer le module Active Directory si disponible
if (Get-Module -Name ActiveDirectory -ListAvailable) {
    try {
        Import-Module ActiveDirectory -Force -ErrorAction Stop
        Write-Verbose "Module Active Directory importé avec succès"
    }
    catch {
        Write-Warning "Impossible d'importer le module Active Directory: $($_.Exception.Message)"
        Write-Warning "Certaines vérifications AD ne fonctionneront pas correctement"
    }
} else {
    Write-Warning "Module Active Directory non disponible sur ce système"
    Write-Warning "Les vérifications et remédiations AD ne fonctionneront pas"
    Write-Warning "Installez le module avec: Install-WindowsFeature -Name RSAT-AD-PowerShell"
}

# Charger la configuration avec valeurs par défaut sûres
$SettingsPath = Join-Path $ScriptRoot "config\settings.json"
$DefaultSettings = @{
    CsvPath = "results\AD_Hardening_Report.csv"
    LogPath = "results\logs"
    ShowRecommendationsInConsole = $true
    Color_OK = "Green"
    Color_FAIL = "Red"
    Color_WARN = "Yellow"
    QuickWinPriority = @(1, 2, 8, 5, 6, 7, 9, 10)
}

if (Test-Path $SettingsPath) {
    try {
        $SettingsContent = Get-Content $SettingsPath -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($SettingsContent)) {
            Write-Warning "Fichier de configuration vide, utilisation des valeurs par défaut"
            $Settings = $DefaultSettings
        } else {
            $Settings = $SettingsContent | ConvertFrom-Json
            Write-Verbose "Configuration chargée depuis: $SettingsPath"
            
            # S'assurer que les propriétés essentielles existent
            foreach ($key in $DefaultSettings.Keys) {
                if (-not $Settings.PSObject.Properties.Name -contains $key) {
                    $Settings | Add-Member -NotePropertyName $key -NotePropertyValue $DefaultSettings[$key] -Force
                    Write-Verbose "Propriété manquante ajoutée: $key = $($DefaultSettings[$key])"
                }
            }
        }
    }
    catch {
        Write-Warning "Impossible de charger la configuration: $($_.Exception.Message)"
        Write-Warning "Utilisation des valeurs par défaut sûres"
        $Settings = $DefaultSettings
    }
} else {
    Write-Warning "Fichier de configuration non trouvé: $SettingsPath"
    Write-Warning "Utilisation des valeurs par défaut sûres"
    $Settings = $DefaultSettings
}

# Déterminer le chemin CSV (résolu depuis la racine du script)
if (-not $CsvPath) {
    if ($Settings.CsvPath) {
        # Résoudre le chemin depuis la racine du script
        if ([System.IO.Path]::IsPathRooted($Settings.CsvPath)) {
            $CsvPath = $Settings.CsvPath
        } else {
            $CsvPath = Join-Path $ScriptRoot $Settings.CsvPath
        }
        Write-Verbose "Chemin CSV depuis la configuration: $CsvPath"
    } else {
        $CsvPath = Join-Path $ScriptRoot "results\AD_Hardening_Report.csv"
        Write-Verbose "Chemin CSV par défaut: $CsvPath"
    }
}

# Déterminer le chemin des logs (résolu depuis la racine du script)
$LogPath = $Settings.LogPath
if (-not [System.IO.Path]::IsPathRooted($LogPath)) {
    $LogPath = Join-Path $ScriptRoot $LogPath
}
Write-Verbose "Chemin des logs: $LogPath"

# Créer les répertoires de sortie si nécessaire
$CsvDir = Split-Path $CsvPath -Parent
if ($CsvDir -and -not (Test-Path $CsvDir)) {
    try {
        New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
        Write-Verbose "Répertoire CSV créé: $CsvDir"
    }
    catch {
        Write-Warning "Impossible de créer le répertoire CSV: $($_.Exception.Message)"
    }
}

if ($LogPath -and -not (Test-Path $LogPath)) {
    try {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        Write-Verbose "Répertoire des logs créé: $LogPath"
    }
    catch {
        Write-Warning "Impossible de créer le répertoire des logs: $($_.Exception.Message)"
    }
}

# ==============================
# FONCTIONS PRINCIPALES
# ==============================

function Start-AuditMode {
    [CmdletBinding()]
    param(
        [string]$CsvPath,
        [object]$Settings,
        [object]$LoadedModules
    )
    
    Write-Host "=== MODE AUDIT ===" -ForegroundColor Cyan
    Write-Host "Chemin CSV: $CsvPath" -ForegroundColor Yellow
    Write-Host "Fonctions de test disponibles: $($LoadedModules.Checks.Count)" -ForegroundColor Yellow
    Write-Host ""
    
    # Découvrir toutes les fonctions Test-*
    $testFunctions = Get-Command -CommandType Function | Where-Object { $_.Name -like "Test-*" }
    Write-Host "Fonctions Test-* découvertes: $($testFunctions.Count)" -ForegroundColor Green
    
    if ($testFunctions.Count -eq 0) {
        Write-Warning "Aucune fonction Test-* trouvée. Vérifiez que les modules sont correctement chargés."
        return
    }
    
    # Initialiser le fichier CSV avec l'en-tête si absent
    if (-not (Test-Path $CsvPath)) {
        $Headers = @("ID", "Action", "Status", "DetectedValue", "Recommendation")
        $Headers | Out-File -FilePath $CsvPath -Encoding UTF8 -Force
        Write-Verbose "Fichier CSV créé avec en-tête: $CsvPath"
    }
    
    # Compteurs pour le résumé
    $totalChecks = 0
    $okCount = 0
    $failCount = 0
    $warnCount = 0
    
    # Exécuter chaque fonction de test
    foreach ($function in $testFunctions) {
        $functionName = $function.Name
        Write-Host "Exécution de $functionName..." -ForegroundColor Yellow
        
        try {
            # Exécuter la fonction de test
            $result = & $functionName
            
            # Valider que le résultat contient les propriétés requises
            if (-not $result) {
                throw "La fonction $functionName n'a retourné aucun résultat"
            }
            
            # Vérifier les propriétés requises
            $requiredProperties = @("ID", "Action", "Status", "DetectedValue", "Recommendation")
            $missingProperties = @()
            
            foreach ($prop in $requiredProperties) {
                if (-not $result.PSObject.Properties.Name -contains $prop) {
                    $missingProperties += $prop
                }
            }
            
            if ($missingProperties.Count -gt 0) {
                throw "Propriétés manquantes: $($missingProperties -join ', ')"
            }
            
            # Valider les valeurs
            if ([string]::IsNullOrEmpty($result.ID)) {
                $result.ID = "?"
            }
            if ([string]::IsNullOrEmpty($result.Action)) {
                $result.Action = $functionName
            }
            if ([string]::IsNullOrEmpty($result.Status)) {
                $result.Status = "WARN"
                $result.DetectedValue = "Status non défini"
                $result.Recommendation = "Review"
            }
            if ([string]::IsNullOrEmpty($result.DetectedValue)) {
                $result.DetectedValue = "Non détecté"
            }
            if ([string]::IsNullOrEmpty($result.Recommendation)) {
                $result.Recommendation = "Review"
            }
            
            # Exporter le résultat vers CSV
            Export-ADHCResult -Result $result -CsvPath $CsvPath
            
            # Afficher le statut si configuré
            if ($Settings.ShowRecommendationsInConsole -eq $true) {
                Write-ADHCStatus -Result $result -Settings $Settings
            }
            
            # Compter les résultats
            $totalChecks++
            switch ($result.Status.ToUpper()) {
                "OK" { $okCount++ }
                "FAIL" { $failCount++ }
                "WARN" { $warnCount++ }
                default { $warnCount++ }
            }
            
            Write-Host "  ✓ $($result.Status) - $($result.Action)" -ForegroundColor $(if($result.Status -eq "OK") {"Green"} elseif($result.Status -eq "FAIL") {"Red"} else {"Yellow"})
        }
        catch {
            # En cas d'erreur, créer un objet de résultat par défaut
            $errorResult = [PSCustomObject]@{
                ID = "?"
                Action = $functionName
                Status = "WARN"
                DetectedValue = "Erreur: $($_.Exception.Message)"
                Recommendation = "Review"
            }
            
            # Exporter le résultat d'erreur vers CSV
            Export-ADHCResult -Result $errorResult -CsvPath $CsvPath
            
            # Afficher le statut si configuré
            if ($Settings.ShowRecommendationsInConsole -eq $true) {
                Write-ADHCStatus -Result $errorResult -Settings $Settings
            }
            
            # Compter comme WARN
            $totalChecks++
            $warnCount++
            
            Write-Host "  ⚠ WARN - $functionName (Erreur: $($_.Exception.Message))" -ForegroundColor Yellow
        }
    }
    
    # Afficher le résumé
    Write-Host ""
    Write-Host "=== RÉSUMÉ DE L'AUDIT ===" -ForegroundColor Cyan
    Write-Host "Checks exécutés: $totalChecks" -ForegroundColor White
    Write-Host "OK: $okCount" -ForegroundColor Green
    Write-Host "FAIL: $failCount" -ForegroundColor Red
    Write-Host "WARN: $warnCount" -ForegroundColor Yellow
    
    # Calculer le taux de conformité
    if ($totalChecks -gt 0) {
        $complianceRate = [math]::Round(($okCount / $totalChecks) * 100, 2)
        $complianceColor = if($complianceRate -ge 80) {"Green"} elseif($complianceRate -ge 60) {"Yellow"} else {"Red"}
        Write-Host "Taux de conformité: $complianceRate%" -ForegroundColor $complianceColor
    }
    
    Write-Host ""
    Write-Host "Résultats exportés vers: $CsvPath" -ForegroundColor Green
}

function Start-AnalyseMode {
    [CmdletBinding()]
    param(
        [string]$CsvPath,
        [object]$Settings
    )
    
    Write-Host "=== MODE ANALYSE ===" -ForegroundColor Cyan
    Write-Host "Fichier CSV: $CsvPath" -ForegroundColor Yellow
    Write-Host ""
    
    # Vérifier que le fichier CSV existe
    if (-not (Test-Path $CsvPath)) {
        Write-Error "Fichier CSV non trouvé: $CsvPath"
        return
    }
    
    # Vérifier que le fichier CSV n'est pas vide
    $csvContent = Get-Content $CsvPath -Raw
    if ([string]::IsNullOrWhiteSpace($csvContent)) {
        Write-Error "Le fichier CSV est vide: $CsvPath"
        return
    }
    
    try {
        # Importer le CSV
        Write-Host "Import des résultats d'audit..." -ForegroundColor Yellow
        $results = Import-Csv -Path $CsvPath -Encoding UTF8 -ErrorAction Stop
        
        if ($results.Count -eq 0) {
            Write-Warning "Aucun résultat trouvé dans le fichier CSV"
            return
        }
        
        # Vérifier les colonnes requises
        $requiredColumns = @("ID", "Action", "Status", "DetectedValue", "Recommendation")
        $csvColumns = $results[0].PSObject.Properties.Name
        
        $missingColumns = @()
        foreach ($col in $requiredColumns) {
            if ($col -notin $csvColumns) {
                $missingColumns += $col
            }
        }
        
        if ($missingColumns.Count -gt 0) {
            Write-Error "Colonnes manquantes dans le CSV: $($missingColumns -join ', ')"
            return
        }
        
        # Regrouper par Status
        $groupedResults = $results | Group-Object -Property Status
        
        # Calculer les totaux
        $totalResults = $results.Count
        $okCount = ($groupedResults | Where-Object { $_.Name -eq "OK" }).Count
        $failCount = ($groupedResults | Where-Object { $_.Name -eq "FAIL" }).Count
        $warnCount = ($groupedResults | Where-Object { $_.Name -eq "WARN" }).Count
        
        # Afficher les totaux
        Write-Host "=== RÉSUMÉ DE L'ANALYSE ===" -ForegroundColor Cyan
        Write-Host "Total des contrôles: $totalResults" -ForegroundColor White
        Write-Host "OK: $okCount" -ForegroundColor Green
        Write-Host "FAIL: $failCount" -ForegroundColor Red
        Write-Host "WARN: $warnCount" -ForegroundColor Yellow
        
        # Calculer le taux de conformité
        if ($totalResults -gt 0) {
            $complianceRate = [math]::Round(($okCount / $totalResults) * 100, 2)
            $complianceColor = if($complianceRate -ge 80) {"Green"} elseif($complianceRate -ge 60) {"Yellow"} else {"Red"}
            Write-Host "Taux de conformité: $complianceRate%" -ForegroundColor $complianceColor
        }
        
        # Traiter les résultats FAIL
        $failResults = $results | Where-Object { $_.Status -eq "FAIL" }
        
        if ($failResults.Count -gt 0) {
            Write-Host ""
            Write-Host "=== CONTRÔLES EN ÉCHEC (FAIL) ===" -ForegroundColor Red
            
            # Trier par priorité si QuickWinPriority est défini
            if ($Settings.QuickWinPriority -and $Settings.QuickWinPriority.Count -gt 0) {
                Write-Host "Tri par priorité QuickWin..." -ForegroundColor Yellow
                
                # Séparer les résultats selon la priorité
                $priorityResults = @()
                $otherResults = @()
                
                foreach ($result in $failResults) {
                    $id = [int]$result.ID
                    if ($id -in $Settings.QuickWinPriority) {
                        $priorityResults += $result
                    } else {
                        $otherResults += $result
                    }
                }
                
                # Trier les résultats prioritaires selon l'ordre de QuickWinPriority
                $sortedPriorityResults = @()
                foreach ($priorityId in $Settings.QuickWinPriority) {
                    $priorityResult = $priorityResults | Where-Object { [int]$_.ID -eq $priorityId }
                    if ($priorityResult) {
                        $sortedPriorityResults += $priorityResult
                    }
                }
                
                # Trier les autres résultats par ID
                $sortedOtherResults = $otherResults | Sort-Object { [int]$_.ID }
                
                # Combiner les résultats triés
                $sortedFailResults = $sortedPriorityResults + $sortedOtherResults
            } else {
                # Trier par ID si pas de priorité définie
                $sortedFailResults = $failResults | Sort-Object { [int]$_.ID }
            }
            
            # Afficher chaque résultat FAIL
            foreach ($result in $sortedFailResults) {
                $id = $result.ID
                $action = $result.Action
                $recommendation = $result.Recommendation
                
                Write-Host "[ID $id] $action → $recommendation" -ForegroundColor White
            }
        } else {
            Write-Host ""
            Write-Host "✓ Aucun contrôle en échec (FAIL)" -ForegroundColor Green
        }
        
        # Traiter les résultats WARN
        $warnResults = $results | Where-Object { $_.Status -eq "WARN" }
        
        if ($warnResults.Count -gt 0) {
            Write-Host ""
            Write-Host "=== CONTRÔLES D'AVERTISSEMENT (WARN) ===" -ForegroundColor Yellow
            
            $sortedWarnResults = $warnResults | Sort-Object { [int]$_.ID }
            
            foreach ($result in $sortedWarnResults) {
                $id = $result.ID
                $action = $result.Action
                $detectedValue = $result.DetectedValue
                
                Write-Host "[ID $id] $action → $detectedValue" -ForegroundColor White
            }
        }
        
        Write-Host ""
        Write-Host "=== ANALYSE TERMINÉE ===" -ForegroundColor Green
        
        # Gestion des codes de sortie basés sur les seuils
        $failCount = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
        $warnCount = ($results | Where-Object { $_.Status -eq "WARN" }).Count
        
        # Vérifier les seuils et définir le code de sortie
        if ($failCount -ge $Settings.FailThreshold) {
            Write-Host "❌ Échecs critiques détectés ($failCount >= $($Settings.FailThreshold))" -ForegroundColor Red
            exit 2
        }
        elseif ($warnCount -ge $Settings.WarnThreshold) {
            Write-Host "⚠️  Avertissements détectés ($warnCount >= $($Settings.WarnThreshold))" -ForegroundColor Yellow
            exit 1
        }
        else {
            Write-Host "✅ Analyse réussie (FAIL: $failCount, WARN: $warnCount)" -ForegroundColor Green
            exit 0
        }
    }
    catch {
        Write-Error "Erreur lors de l'analyse du fichier CSV: $($_.Exception.Message)"
        exit 3
    }
}

function Start-RemediateMode {
    [CmdletBinding()]
    param(
        [int[]]$RemediationList,
        [string]$CsvPath,
        [object]$Settings,
        [object]$LoadedModules
    )
    
    Write-Host "=== MODE REMÉDIATION ===" -ForegroundColor Cyan
    Write-Host "IDs à remédier: $($RemediationList -join ', ')" -ForegroundColor Yellow
    Write-Host "Fonctions de remédiation disponibles: $($LoadedModules.Remediations.Count)" -ForegroundColor Yellow
    Write-Host "WhatIf: $WhatIfPreference" -ForegroundColor Yellow
    Write-Host "Confirm: $ConfirmPreference" -ForegroundColor Yellow
    Write-Host ""
    
    # Vérifier que des IDs sont fournis
    if ($RemediationList.Count -eq 0) {
        Write-Error "Aucun ID de remédiation spécifié. Utilisez -RemediationList pour spécifier les contrôles à traiter."
        Write-Host ""
        Write-Host "Exemples d'utilisation:" -ForegroundColor Yellow
        Write-Host "  .\AD-Hardening-Checker.ps1 -Mode Remediate -RemediationList 1,2,8" -ForegroundColor Cyan
        Write-Host "  .\AD-Hardening-Checker.ps1 -Mode Remediate -RemediationList 1,2,8 -WhatIf" -ForegroundColor Cyan
        Write-Host "  .\AD-Hardening-Checker.ps1 -Mode Remediate -RemediationList 1,2,8 -Confirm" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "IDs disponibles (1-27):" -ForegroundColor Yellow
        Write-Host "  1=LLMNR, 2=NBT-NS, 3=mDNS/Bonjour, 4=MachineAccountQuota, 5=SMB Signing" -ForegroundColor Cyan
        Write-Host "  6=LDAP Signing, 7=Print Spooler, 8=SMBv1, 9=LAPS, 10=Unconstrained Delegation" -ForegroundColor Cyan
        Write-Host "  11=Protected Users, 12=LSASS Protected, 13=SMB Null Session, 14=LDAP Anonymous" -ForegroundColor Cyan
        Write-Host "  15=Password Policy, 16=RID Brute Force, 17=Pre-Win2k Access, 18=IPv6 Management" -ForegroundColor Cyan
        Write-Host "  19=NTLM Restriction, 20=Share ACLs, 21=Default Credentials, 22=Kerberos PreAuth" -ForegroundColor Cyan
        Write-Host "  23=Coercion Patches, 24=Tiered Admin, 25=PasswdNotReqd, 26=Secure Service Accounts" -ForegroundColor Cyan
        Write-Host "  27=Security Baseline" -ForegroundColor Cyan
        return
    }
    
    # Construire la table de mapping ID → Nom de fonction
    $remediationMapping = @{
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
        24 = "Remediate-TieredAdminModel"
        25 = "Remediate-PasswdNotReqdFlag"
        26 = "Remediate-SecureServiceAccounts"
        27 = "Remediate-SecurityBaseline"
    }
    
    # Compteurs pour le résumé
    $totalProcessed = 0
    $successCount = 0
    $errorCount = 0
    $skippedCount = 0
    
    # Traiter chaque ID
    foreach ($id in $RemediationList) {
        $totalProcessed++
        
        # Vérifier que l'ID est valide
        if ($id -lt 1 -or $id -gt 27) {
            Write-Warning "ID invalide ignoré: $id (doit être entre 1 et 27)"
            $errorCount++
            continue
        }
        
        # Vérifier que l'ID est autorisé pour la remédiation
        if ($Settings.AllowedRemediations -and $id -notin $Settings.AllowedRemediations) {
            Write-Warning "ID $id non autorisé pour la remédiation (voir AllowedRemediations dans settings.json)"
            $skippedCount++
            continue
        }
        
        # Obtenir le nom de la fonction
        $functionName = $remediationMapping[$id]
        
        if (-not $functionName) {
            Write-Warning "Aucune fonction de remédiation trouvée pour l'ID: $id"
            $errorCount++
            continue
        }
        
        # Vérifier que la fonction existe
        $function = Get-Command -Name $functionName -CommandType Function -ErrorAction SilentlyContinue
        if (-not $function) {
            Write-Warning "Fonction de remédiation non trouvée: $functionName"
            $errorCount++
            continue
        }
        
        Write-Host "Traitement de l'ID $id ($functionName)..." -ForegroundColor Yellow
        
        try {
            # Exécuter la fonction de remédiation
            # Vérifier si la fonction supporte WhatIf et Confirm
            $functionParams = $function.Parameters
            
            $paramHash = @{}
            
            # Ajouter WhatIf si la fonction le supporte
            if ($functionParams.ContainsKey("WhatIf")) {
                $paramHash["WhatIf"] = $WhatIfPreference
            }
            
            # Ajouter Confirm si la fonction le supporte
            if ($functionParams.ContainsKey("Confirm")) {
                $paramHash["Confirm"] = $ConfirmPreference
            }
            
            # Exécuter la fonction
            if ($paramHash.Count -gt 0) {
                & $functionName @paramHash
            } else {
                & $functionName
            }
            
            # Déterminer le statut
            if ($WhatIfPreference) {
                $status = "Skipped (WhatIf)"
                $skippedCount++
                Write-Host "  ✓ Simulation effectuée (WhatIf)" -ForegroundColor Cyan
            } else {
                $status = "Applied"
                $successCount++
                Write-Host "  ✓ Remédiation appliquée" -ForegroundColor Green
            }
            
            # Journaliser l'action
            Write-ADHCLog "Remediation $status`: $functionName pour ID $id" -LogPath $LogPath
            
        }
        catch {
            $status = "Error"
            $errorCount++
            Write-Host "  ✗ Erreur: $($_.Exception.Message)" -ForegroundColor Red
            
            # Journaliser l'erreur
            Write-ADHCLog "Remediation Error: $functionName pour ID $id - $($_.Exception.Message)" -LogPath $LogPath
        }
    }
    
    # Afficher le résumé
    Write-Host ""
    Write-Host "=== RÉSUMÉ DE LA REMÉDIATION ===" -ForegroundColor Cyan
    Write-Host "IDs traités: $totalProcessed" -ForegroundColor White
    Write-Host "Succès: $successCount" -ForegroundColor Green
    Write-Host "Erreurs: $errorCount" -ForegroundColor Red
    Write-Host "Simulés (WhatIf): $skippedCount" -ForegroundColor Cyan
    
    if ($errorCount -gt 0) {
        Write-Host ""
        Write-Host "⚠ Des erreurs ont été rencontrées. Consultez les logs pour plus de détails." -ForegroundColor Yellow
    }
    
    if ($WhatIfPreference) {
        Write-Host ""
        Write-Host "ℹ Mode simulation activé. Aucune modification n'a été appliquée." -ForegroundColor Blue
        Write-Host "Pour appliquer les remédiations, relancez sans -WhatIf" -ForegroundColor Blue
    }
    
    Write-Host ""
    Write-Host "=== REMÉDIATION TERMINÉE ===" -ForegroundColor Green
}

# ==============================
# EXÉCUTION PRINCIPALE
# ==============================

try {
    Write-Host "=== AD HARDENING CHECKER ===" -ForegroundColor Green
    Write-Host "Mode: $Mode" -ForegroundColor White
    Write-Host "Version: 1.0" -ForegroundColor White
    Write-Host "PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor White
    Write-Host ""
    
    # Exécuter le mode sélectionné
    switch ($Mode) {
        "Audit" {
            Start-AuditMode -CsvPath $CsvPath -Settings $Settings -LoadedModules $LoadedModules
        }
        "Analyse" {
            Start-AnalyseMode -CsvPath $CsvPath -Settings $Settings
        }
        "Remediate" {
            Start-RemediateMode -RemediationList $RemediationList -CsvPath $CsvPath -Settings $Settings -LoadedModules $LoadedModules
        }
        default {
            Write-Error "Mode non reconnu: $Mode"
            exit 1
        }
    }
    
    Write-Host ""
    Write-Host "=== EXÉCUTION TERMINÉE ===" -ForegroundColor Green
}
catch {
    Write-Error "Erreur lors de l'exécution: $($_.Exception.Message)"
    Write-Error "Détails: $($_.Exception.StackTrace)"
    exit 1
}