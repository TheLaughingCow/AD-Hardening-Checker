# ==============================
# Test-LoadModules.ps1
# Test du système de chargement des modules
# ==============================

# Charger le script de chargement
$LoadModulesPath = Join-Path $PSScriptRoot "..\src\Load-Modules.ps1"
if (Test-Path $LoadModulesPath) {
    . $LoadModulesPath
} else {
    Write-Error "Fichier Load-Modules.ps1 non trouvé: $LoadModulesPath"
    exit 1
}

Write-Host "=== Test du système de chargement des modules ===" -ForegroundColor Cyan

# Test 1: Chargement initial
Write-Host "`n1. Chargement initial des modules..." -ForegroundColor Yellow
$result1 = Import-ADHCModules
if ($result1) {
    Write-Host "✓ Chargement réussi" -ForegroundColor Green
    Write-Host "  - Fonctions de test: $($result1.Checks.Count)" -ForegroundColor White
    Write-Host "  - Fonctions de remédiation: $($result1.Remediations.Count)" -ForegroundColor White
} else {
    Write-Host "✗ Échec du chargement" -ForegroundColor Red
}

# Test 2: Chargement idempotent (ne doit pas recharger)
Write-Host "`n2. Test d'idempotence..." -ForegroundColor Yellow
$result2 = Import-ADHCModules
if ($result2) {
    Write-Host "✓ Chargement idempotent réussi" -ForegroundColor Green
    Write-Host "  - Fonctions de test: $($result2.Checks.Count)" -ForegroundColor White
    Write-Host "  - Fonctions de remédiation: $($result2.Remediations.Count)" -ForegroundColor White
} else {
    Write-Host "✗ Échec du chargement idempotent" -ForegroundColor Red
}

# Test 3: Vérification des fonctions chargées
Write-Host "`n3. Vérification des fonctions chargées..." -ForegroundColor Yellow
$loadedFunctions = Get-ADHCLoadedFunctions
if ($loadedFunctions) {
    Write-Host "✓ Fonctions disponibles:" -ForegroundColor Green
    
    Write-Host "`n  Fonctions de test chargées:" -ForegroundColor Cyan
    foreach ($func in $loadedFunctions.Checks) {
        Write-Host "    - $func" -ForegroundColor White
    }
    
    Write-Host "`n  Fonctions de remédiation chargées:" -ForegroundColor Cyan
    foreach ($func in $loadedFunctions.Remediations) {
        Write-Host "    - $func" -ForegroundColor White
    }
} else {
    Write-Host "✗ Aucune fonction chargée" -ForegroundColor Red
}

# Test 4: Test d'une fonction de test
Write-Host "`n4. Test d'exécution d'une fonction de test..." -ForegroundColor Yellow
if ($loadedFunctions.Checks.Count -gt 0) {
    $testFunction = $loadedFunctions.Checks[0]
    Write-Host "  Test de la fonction: $testFunction" -ForegroundColor Cyan
    
    try {
        $testResult = & $testFunction
        if ($testResult) {
            Write-Host "✓ Fonction $testFunction exécutée avec succès" -ForegroundColor Green
            Write-Host "  - ID: $($testResult.ID)" -ForegroundColor White
            Write-Host "  - Action: $($testResult.Action)" -ForegroundColor White
            Write-Host "  - Status: $($testResult.Status)" -ForegroundColor White
        } else {
            Write-Host "⚠ Fonction $testFunction exécutée mais sans résultat" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "✗ Erreur lors de l'exécution de $testFunction : $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "⚠ Aucune fonction de test disponible pour le test" -ForegroundColor Yellow
}

# Test 5: Réinitialisation
Write-Host "`n5. Test de réinitialisation..." -ForegroundColor Yellow
Reset-ADHCModules
$resetResult = Get-ADHCLoadedFunctions
if ($resetResult.Checks.Count -eq 0 -and $resetResult.Remediations.Count -eq 0) {
    Write-Host "✓ Réinitialisation réussie" -ForegroundColor Green
} else {
    Write-Host "✗ Échec de la réinitialisation" -ForegroundColor Red
}

Write-Host "`n=== Test terminé ===" -ForegroundColor Cyan

