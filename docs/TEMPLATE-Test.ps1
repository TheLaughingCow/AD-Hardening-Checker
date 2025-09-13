# ==============================
# TEMPLATE-Test.ps1
# Template pour créer une nouvelle fonction de test
# ==============================

function Test-<Name> {
    [CmdletBinding()]
    param(
        [string]$SettingsPath = "$PSScriptRoot/../../../config/settings.json"
    )

    # Charger la configuration
    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        Write-Verbose "Fichier settings.json introuvable, utilisation des valeurs par défaut."
        $settings = @{ }
    }

    # Objet de résultat par défaut
    $result = [PSCustomObject]@{
        ID             = <ID_NUMBER>                    # Remplacer par le numéro d'ID (1-27)
        Action         = "<Action Name>"                # Remplacer par le nom de l'action
        Status         = "UNKNOWN"                      # Sera mis à jour selon le résultat
        DetectedValue  = $null                          # Valeur détectée par le test
        Recommendation = "<Recommendation Text>"        # Remplacer par la recommandation
    }

    try {
        # ==============================
        # LOGIQUE DE TEST ICI
        # ==============================
        
        # Exemple de vérification de registre :
        # $regPath = "HKLM:\Path\To\Registry\Key"
        # $regValue = Get-ItemProperty -Path $regPath -Name "ValueName" -ErrorAction SilentlyContinue
        # if ($regValue -and $regValue.ValueName -eq 0) {
        #     $result.Status = "OK"
        #     $result.DetectedValue = "Correctly configured"
        # } else {
        #     $result.Status = "FAIL"
        #     $result.DetectedValue = "Not configured or incorrect value"
        # }
        
        # Exemple de vérification de service :
        # $service = Get-Service -Name "ServiceName" -ErrorAction SilentlyContinue
        # if ($service -and $service.Status -eq "Stopped") {
        #     $result.Status = "OK"
        #     $result.DetectedValue = "Service stopped"
        # } else {
        #     $result.Status = "FAIL"
        #     $result.DetectedValue = "Service running or not found"
        # }
        
        # Exemple de vérification Active Directory :
        # if (Get-Module -Name ActiveDirectory -ListAvailable) {
        #     $adObject = Get-ADObject -Filter "Name -eq 'TestObject'" -ErrorAction SilentlyContinue
        #     if ($adObject) {
        #         $result.Status = "OK"
        #         $result.DetectedValue = "AD object found"
        #     } else {
        #         $result.Status = "FAIL"
        #         $result.DetectedValue = "AD object not found"
        #     }
        # } else {
        #     $result.Status = "WARN"
        #     $result.DetectedValue = "Active Directory module not available"
        # }
        
        # ==============================
        # FIN DE LA LOGIQUE DE TEST
        # ==============================
        
        # Si aucun statut n'a été défini, définir par défaut
        if ($result.Status -eq "UNKNOWN") {
            $result.Status = "WARN"
            $result.DetectedValue = "Test not implemented"
            $result.Recommendation = "Implement test logic"
        }
    }
    catch {
        # En cas d'erreur, définir comme WARN avec le message d'erreur
        $result.Status = "WARN"
        $result.DetectedValue = "Error: $($_.Exception.Message)"
        $result.Recommendation = "Review configuration and permissions"
    }

    # Afficher le statut si configuré
    if ($settings.ShowRecommendationsInConsole -eq $true) {
        $color = switch ($result.Status) {
            "OK"   { $settings.Color_OK   }
            "FAIL" { $settings.Color_FAIL }
            "WARN" { $settings.Color_WARN }
            default { "White" }
        }
        Write-Host ("[ID {0}] {1} → {2} (Detected: {3})" -f `
            $result.ID, $result.Action, $result.Status, $result.DetectedValue) -ForegroundColor $color
    }

    return $result
}

# ==============================
# INSTRUCTIONS D'UTILISATION
# ==============================
# 1. Copier ce fichier vers src/modules/Checks/Test-<Name>.ps1
# 2. Remplacer <Name> par le nom de votre test (ex: Test-SMBv2)
# 3. Remplacer <ID_NUMBER> par le numéro d'ID (1-27)
# 4. Remplacer <Action Name> par le nom de l'action
# 5. Remplacer <Recommendation Text> par la recommandation
# 6. Implémenter la logique de test dans le bloc try
# 7. Tester la fonction avec des cas OK/FAIL/WARN
# ==============================

