# ==============================
# Load-Modules.ps1
# Chargement dynamique des modules de test et remédiation
# Compatible PowerShell 5.1+ et 7
# ==============================

# Déterminer le répertoire racine
$Root = $PSScriptRoot

# Variables globales pour éviter le double chargement
$script:ModulesLoaded = $false
$script:LoadedFunctions = @{
    Checks = @()
    Remediations = @()
}

function Import-ADHCModules {
    [CmdletBinding()]
    param()
    
    # Vérifier si les modules sont déjà chargés (idempotent)
    if ($script:ModulesLoaded) {
        Write-Verbose "Modules déjà chargés. Retour des fonctions disponibles."
        return $script:LoadedFunctions
    }
    
    Write-Verbose "Chargement des modules AD Hardening Checker..."
    
    try {
        # 1. Charger Utils.psm1
        $utilsPath = Join-Path $Root "Utils.psm1"
        if (Test-Path $utilsPath) {
            try {
                Import-Module $utilsPath -Force -ErrorAction Stop
                Write-Verbose "Module Utils.psm1 chargé"
            }
            catch {
                Write-Warning "Impossible de charger Utils.psm1: $($_.Exception.Message)"
            }
        } else {
            Write-Warning "Fichier Utils.psm1 non trouvé: $utilsPath"
        }
        
        # 2. Charger tous les modules de test (Test-*.ps1)
        $checksPath = Join-Path $Root "modules\Checks"
        if (Test-Path $checksPath) {
            $checkFiles = Get-ChildItem -Path $checksPath -Filter "Test-*.ps1" -File -ErrorAction SilentlyContinue
            foreach ($file in $checkFiles) {
                try {
                    . $file.FullName
                    $functionName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                    $script:LoadedFunctions.Checks += $functionName
                    Write-Verbose "Module de test chargé: $($file.Name)"
                }
                catch {
                    Write-Warning "Impossible de charger $($file.Name): $($_.Exception.Message)"
                }
            }
        } else {
            Write-Verbose "Dossier Checks non trouvé: $checksPath"
        }
        
        # 3. Charger tous les modules de remédiation (Remediate-*.ps1)
        $remediationsPath = Join-Path $Root "modules\Remediations"
        if (Test-Path $remediationsPath) {
            $remediationFiles = Get-ChildItem -Path $remediationsPath -Filter "Remediate-*.ps1" -File -ErrorAction SilentlyContinue
            foreach ($file in $remediationFiles) {
                try {
                    . $file.FullName
                    $functionName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                    $script:LoadedFunctions.Remediations += $functionName
                    Write-Verbose "Module de remédiation chargé: $($file.Name)"
                }
                catch {
                    Write-Warning "Impossible de charger $($file.Name): $($_.Exception.Message)"
                }
            }
        } else {
            Write-Verbose "Dossier Remediations non trouvé: $remediationsPath"
        }
        
        # Marquer comme chargé
        $script:ModulesLoaded = $true
        
        Write-Verbose "Chargement des modules terminé."
        Write-Verbose "Fonctions de test chargées: $($script:LoadedFunctions.Checks.Count)"
        Write-Verbose "Fonctions de remédiation chargées: $($script:LoadedFunctions.Remediations.Count)"
        
        return $script:LoadedFunctions
    }
    catch {
        Write-Error "Erreur lors du chargement des modules: $($_.Exception.Message)"
        return $null
    }
}

function Get-ADHCLoadedFunctions {
    [CmdletBinding()]
    param()
    
    return $script:LoadedFunctions
}

function Reset-ADHCModules {
    [CmdletBinding()]
    param()
    
    $script:ModulesLoaded = $false
    $script:LoadedFunctions = @{
        Checks = @()
        Remediations = @()
    }
    Write-Verbose "État des modules réinitialisé"
}

# Exporter les fonctions
Export-ModuleMember -Function Import-ADHCModules, Get-ADHCLoadedFunctions, Reset-ADHCModules