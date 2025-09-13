# ==============================
# Test-Audit.ps1
# Test du mode Audit du script AD-Hardening-Checker
# ==============================

# Déterminer les chemins
$TestRoot = Split-Path -Parent $PSCommandPath
$LoadModulesPath = Join-Path $TestRoot "..\src\Load-Modules.ps1"
$ScriptPath = Join-Path $TestRoot "..\src\AD-Hardening-Checker.ps1"

Write-Host "=== TEST DU MODE AUDIT ===" -ForegroundColor Cyan
Write-Host "Répertoire de test: $TestRoot" -ForegroundColor Yellow
Write-Host "Script à tester: $ScriptPath" -ForegroundColor Yellow
Write-Host ""

# Vérifier que les fichiers existent
if (-not (Test-Path $LoadModulesPath)) {
    Write-Error "Fichier Load-Modules.ps1 non trouvé: $LoadModulesPath"
    exit 1
}

if (-not (Test-Path $ScriptPath)) {
    Write-Error "Script AD-Hardening-Checker.ps1 non trouvé: $ScriptPath"
    exit 1
}

# Créer un chemin CSV temporaire
$TempCsvPath = Join-Path $TestRoot "..\results\_tmp-test-audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
Write-Host "Chemin CSV temporaire: $TempCsvPath" -ForegroundColor Yellow

# S'assurer que le répertoire results existe
$ResultsDir = Split-Path $TempCsvPath -Parent
if (-not (Test-Path $ResultsDir)) {
    try {
        New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
        Write-Host "Répertoire results créé: $ResultsDir" -ForegroundColor Green
    }
    catch {
        Write-Error "Impossible de créer le répertoire results: $($_.Exception.Message)"
        exit 1
    }
}

try {
    Write-Host "Exécution du mode Audit..." -ForegroundColor Yellow
    
    # Exécuter le script en mode Audit
    $result = & $ScriptPath -Mode Audit -CsvPath $TempCsvPath
    
    # Vérifier le code de sortie
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Le script a échoué avec le code de sortie: $LASTEXITCODE"
        Write-Host "Sortie du script: $result" -ForegroundColor Red
        exit 1
    }
    
    # Afficher la sortie du script pour validation
    Write-Host "Sortie du script:" -ForegroundColor Gray
    Write-Host $result -ForegroundColor Gray
    
    Write-Host "Script exécuté avec succès" -ForegroundColor Green
    
    # Vérifier que le fichier CSV existe
    if (-not (Test-Path $TempCsvPath)) {
        Write-Error "Le fichier CSV n'a pas été créé: $TempCsvPath"
        exit 1
    }
    
    Write-Host "Fichier CSV créé: $TempCsvPath" -ForegroundColor Green
    
    # Vérifier que le fichier CSV n'est pas vide
    $csvContent = Get-Content $TempCsvPath -Raw
    if ([string]::IsNullOrWhiteSpace($csvContent)) {
        Write-Error "Le fichier CSV est vide"
        exit 1
    }
    
    Write-Host "Fichier CSV contient des données" -ForegroundColor Green
    
    # Importer le CSV et vérifier les colonnes
    try {
        $csvData = Import-Csv -Path $TempCsvPath -Encoding UTF8
        Write-Host "CSV importé avec succès: $($csvData.Count) lignes" -ForegroundColor Green
    }
    catch {
        Write-Error "Impossible d'importer le CSV: $($_.Exception.Message)"
        exit 1
    }
    
    # Vérifier les colonnes requises
    $requiredColumns = @("ID", "Action", "Status", "DetectedValue", "Recommendation")
    $csvColumns = $csvData[0].PSObject.Properties.Name
    
    $missingColumns = @()
    foreach ($col in $requiredColumns) {
        if ($col -notin $csvColumns) {
            $missingColumns += $col
        }
    }
    
    if ($missingColumns.Count -gt 0) {
        Write-Error "Colonnes manquantes dans le CSV: $($missingColumns -join ', ')"
        Write-Host "Colonnes présentes: $($csvColumns -join ', ')" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "Toutes les colonnes requises sont présentes" -ForegroundColor Green
    
    # Vérifier qu'il y a des données
    if ($csvData.Count -eq 0) {
        Write-Error "Aucune donnée trouvée dans le CSV"
        exit 1
    }
    
    Write-Host "Données trouvées: $($csvData.Count) contrôles" -ForegroundColor Green
    
    # Vérifier la structure des données
    $validRows = 0
    $invalidRows = 0
    
    foreach ($row in $csvData) {
        $isValid = $true
        
        # Vérifier que les propriétés requises ne sont pas vides
        foreach ($col in $requiredColumns) {
            if ([string]::IsNullOrWhiteSpace($row.$col)) {
                $isValid = $false
                break
            }
        }
        
        if ($isValid) {
            $validRows++
        } else {
            $invalidRows++
        }
    }
    
    Write-Host "Lignes valides: $validRows" -ForegroundColor Green
    if ($invalidRows -gt 0) {
        Write-Host "Lignes invalides: $invalidRows" -ForegroundColor Yellow
    }
    
    # Vérifier les statuts
    $statusCounts = $csvData | Group-Object -Property Status
    Write-Host "Répartition des statuts:" -ForegroundColor Cyan
    foreach ($status in $statusCounts) {
        $color = switch ($status.Name) {
            "OK" { "Green" }
            "FAIL" { "Red" }
            "WARN" { "Yellow" }
            default { "White" }
        }
        Write-Host "  $($status.Name): $($status.Count)" -ForegroundColor $color
    }
    
    # Afficher un échantillon des données
    Write-Host "`nÉchantillon des données:" -ForegroundColor Cyan
    $sampleData = $csvData | Select-Object -First 3
    foreach ($row in $sampleData) {
        Write-Host "  [ID $($row.ID)] $($row.Action) → $($row.Status)" -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host "=== TEST RÉUSSI ===" -ForegroundColor Green
    Write-Host "✓ Script exécuté sans erreur" -ForegroundColor Green
    Write-Host "✓ Fichier CSV créé et accessible" -ForegroundColor Green
    Write-Host "✓ Toutes les colonnes requises présentes" -ForegroundColor Green
    Write-Host "✓ Données valides trouvées" -ForegroundColor Green
    Write-Host "✓ Structure des données correcte" -ForegroundColor Green
    
    # Nettoyer le fichier temporaire
    try {
        Remove-Item $TempCsvPath -Force
        Write-Host "Fichier temporaire supprimé: $TempCsvPath" -ForegroundColor Gray
    }
    catch {
        Write-Warning "Impossible de supprimer le fichier temporaire: $($_.Exception.Message)"
    }
    
}
catch {
    Write-Error "Erreur lors du test: $($_.Exception.Message)"
    Write-Error "Détails: $($_.Exception.StackTrace)"
    
    # Nettoyer le fichier temporaire en cas d'erreur
    if (Test-Path $TempCsvPath) {
        try {
            Remove-Item $TempCsvPath -Force
            Write-Host "Fichier temporaire supprimé après erreur" -ForegroundColor Gray
        }
        catch {
            Write-Warning "Impossible de supprimer le fichier temporaire après erreur"
        }
    }
    
    exit 1
}
