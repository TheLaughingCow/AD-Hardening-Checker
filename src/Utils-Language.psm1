function Get-SystemLanguage {
    [CmdletBinding()]
    param()
    
    try {
        $culture = [System.Globalization.CultureInfo]::CurrentCulture
        $uiCulture = [System.Globalization.CultureInfo]::CurrentUICulture
        
        # Check if French is detected
        if ($culture.TwoLetterISOLanguageName -eq "fr" -or $uiCulture.TwoLetterISOLanguageName -eq "fr") {
            return "French"
        }
        
        # Check Windows language
        $osLanguage = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OSLanguage
        if ($osLanguage -eq 1036) { # French
            return "French"
        }
        
        # Check registry
        $regLanguage = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name "Default" -ErrorAction SilentlyContinue
        if ($regLanguage -and $regLanguage.Default -eq "040c") { # French
            return "French"
        }
        
        # Default to English
        return "English"
    }
    catch {
        Write-Verbose "Language detection failed: $($_.Exception.Message)"
        return "English"
    }
}

function Get-LocalizedGroupName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$EnglishName
    )
    
    $language = Get-SystemLanguage
    
    $groupMappings = @{
        "English" = @{
            "Pre-Windows 2000 Compatible Access" = "Pre-Windows 2000 Compatible Access"
            "Protected Users" = "Protected Users"
            "Domain Admins" = "Domain Admins"
            "Enterprise Admins" = "Enterprise Admins"
            "Schema Admins" = "Schema Admins"
            "Everyone" = "Everyone"
            "Authenticated Users" = "Authenticated Users"
            "Anonymous Logon" = "Anonymous Logon"
            "Interactive" = "Interactive"
            "Network" = "Network"
            "Service" = "Service"
            "Batch" = "Batch"
            "Administrators" = "Administrators"
            "Users" = "Users"
            "Guests" = "Guests"
            "Power Users" = "Power Users"
            "Backup Operators" = "Backup Operators"
            "Account Operators" = "Account Operators"
            "Server Operators" = "Server Operators"
            "Print Operators" = "Print Operators"
            "Remote Desktop Users" = "Remote Desktop Users"
            "Performance Log Users" = "Performance Log Users"
            "Performance Monitor Users" = "Performance Monitor Users"
            "Distributed COM Users" = "Distributed COM Users"
            "Cryptographic Operators" = "Cryptographic Operators"
            "Event Log Readers" = "Event Log Readers"
            "Hyper-V Administrators" = "Hyper-V Administrators"
            "Access Control Assistance Operators" = "Access Control Assistance Operators"
            "Remote Management Users" = "Remote Management Users"
        }
        "French" = @{
            "Pre-Windows 2000 Compatible Access" = "Accès compatible pré-Windows 2000"
            "Protected Users" = "Utilisateurs protégés"
            "Domain Admins" = "Administrateurs du domaine"
            "Enterprise Admins" = "Administrateurs de l'entreprise"
            "Schema Admins" = "Administrateurs du schéma"
            "Everyone" = "Tout le monde"
            "Authenticated Users" = "Utilisateurs authentifiés"
            "Anonymous Logon" = "Connexion anonyme"
            "Interactive" = "Interactif"
            "Network" = "Réseau"
            "Service" = "Service"
            "Batch" = "Traitement par lots"
            "Administrators" = "Administrateurs"
            "Users" = "Utilisateurs"
            "Guests" = "Invités"
            "Power Users" = "Utilisateurs avec pouvoir"
            "Backup Operators" = "Opérateurs de sauvegarde"
            "Account Operators" = "Opérateurs de comptes"
            "Server Operators" = "Opérateurs de serveur"
            "Print Operators" = "Opérateurs d'impression"
            "Remote Desktop Users" = "Utilisateurs du Bureau à distance"
            "Performance Log Users" = "Utilisateurs du journal des performances"
            "Performance Monitor Users" = "Utilisateurs de l'analyseur de performances"
            "Distributed COM Users" = "Utilisateurs COM distribués"
            "Cryptographic Operators" = "Opérateurs de chiffrement"
            "Event Log Readers" = "Lecteurs du journal des événements"
            "Hyper-V Administrators" = "Administrateurs Hyper-V"
            "Access Control Assistance Operators" = "Opérateurs d'assistance au contrôle d'accès"
            "Remote Management Users" = "Utilisateurs de gestion à distance"
        }
    }
    
    if ($groupMappings.ContainsKey($language) -and $groupMappings[$language].ContainsKey($EnglishName)) {
        return $groupMappings[$language][$EnglishName]
    }
    
    return $EnglishName
}

function Get-LocalizedGPOInstructions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CheckName
    )
    
    $language = Get-SystemLanguage
    
    $gpoInstructions = @{
        "English" = @{
            "Password Policy Partially Compliant" = "Computer Config > Windows Settings > Security Settings > Account Policies > Password Policy"
            "LAPS Not Detected" = "Computer Config > Admin Templates > System > LAPS > 'Enable Local Admin Password Solution' = Enabled"
            "LSASS Unprotected" = "Computer Config > Admin Templates > System > Credential Guard > 'Turn On Credential Guard' = Enabled with UEFI lock"
            "Print Spooler Disabled" = "Computer Config > Admin Templates > Printers > 'Allow Print Spooler to accept client connections' = Disabled"
            "MachineAccountQuota Secured" = "Computer Config > Admin Templates > System > Net Logon > 'Machine account quota' = 0"
            "Default Credentials Secured" = "Computer Config > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Deny log on locally' = Add service accounts"
            "Service Accounts Not Secured" = "Computer Config > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Deny log on locally' = Add service accounts"
            "Unconstrained Delegation Detected" = "Computer Config > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Enable computer and user accounts to be trusted for delegation' = Remove all"
            "PASSWD_NOTREQD Accounts Found" = "Computer Config > Windows Settings > Security Settings > Account Policies > Password Policy > 'Password not required' = Disabled"
            "Kerberos Pre-Auth Fully Enforced" = "Computer Config > Windows Settings > Security Settings > Account Policies > Kerberos Policy > 'Enforce user logon restrictions' = Enabled"
            "Coercion Patches Missing" = "Windows Update > Install KB5005413, KB5006744, KB5007205, KB5007262 (PetitPotam/Relay patches)"
            "RID Brute Force Protection Partial" = "Computer Config > Admin Templates > System > Net Logon > 'Disable Net Logon' = Enabled"
            "Security Baseline Check Error" = "Computer Config > Windows Settings > Security Settings > Local Policies > Security Options > Review all settings"
            "Pre-Windows 2000 Check Error" = "Computer Config > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Access this computer from the network' = Remove Everyone"
            "Protected Users Group" = "Computer Config > Windows Settings > Security Settings > Restricted Groups > Add 'Protected Users' group"
            "Tiered Admin Model Missing" = "Create separate OUs for Tier 0, 1, 2 admin accounts with different GPOs"
            "Share ACL Restriction" = "Computer Config > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Access this computer from the network' = Remove Everyone"
        }
        "French" = @{
            "Password Policy Partially Compliant" = "Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Stratégies de comptes > Stratégie de mot de passe"
            "LAPS Not Detected" = "Configuration ordinateur > Modèles d'administration > Système > LAPS > 'Activer la solution de mot de passe administrateur local' = Activé"
            "LSASS Unprotected" = "Configuration ordinateur > Modèles d'administration > Système > Credential Guard > 'Activer Credential Guard' = Activé avec verrouillage UEFI"
            "Print Spooler Disabled" = "Configuration ordinateur > Modèles d'administration > Imprimantes > 'Autoriser le spouleur d'impression à accepter les connexions client' = Désactivé"
            "MachineAccountQuota Secured" = "Configuration ordinateur > Modèles d'administration > Système > Net Logon > 'Quota de compte d'ordinateur' = 0"
            "Default Credentials Secured" = "Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Stratégies locales > Attribution des droits utilisateur > 'Refuser l'ouverture de session locale' = Ajouter les comptes de service"
            "Service Accounts Not Secured" = "Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Stratégies locales > Attribution des droits utilisateur > 'Refuser l'ouverture de session locale' = Ajouter les comptes de service"
            "Unconstrained Delegation Detected" = "Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Stratégies locales > Attribution des droits utilisateur > 'Activer les comptes d'ordinateur et d'utilisateur pour qu'ils soient approuvés pour la délégation' = Supprimer tout"
            "PASSWD_NOTREQD Accounts Found" = "Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Stratégies de comptes > Stratégie de mot de passe > 'Le mot de passe n'est pas requis' = Désactivé"
            "Kerberos Pre-Auth Fully Enforced" = "Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Stratégies de comptes > Stratégie Kerberos > 'Appliquer les restrictions de connexion utilisateur' = Activé"
            "Coercion Patches Missing" = "Windows Update > Installer KB5005413, KB5006744, KB5007205, KB5007262 (correctifs PetitPotam/Relay)"
            "RID Brute Force Protection Partial" = "Configuration ordinateur > Modèles d'administration > Système > Net Logon > 'Désactiver Net Logon' = Activé"
            "Security Baseline Check Error" = "Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Stratégies locales > Options de sécurité > Examiner tous les paramètres"
            "Pre-Windows 2000 Check Error" = "Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Stratégies locales > Attribution des droits utilisateur > 'Accéder à cet ordinateur à partir du réseau' = Supprimer Tout le monde"
            "Protected Users Group" = "Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Groupes restreints > Ajouter le groupe 'Utilisateurs protégés'"
            "Tiered Admin Model Missing" = "Créer des UO séparées pour les comptes administrateur Tier 0, 1, 2 avec différents GPO"
            "Share ACL Restriction" = "Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Stratégies locales > Attribution des droits utilisateur > 'Accéder à cet ordinateur à partir du réseau' = Supprimer Tout le monde"
        }
    }
    
    if ($gpoInstructions.ContainsKey($language) -and $gpoInstructions[$language].ContainsKey($CheckName)) {
        return $gpoInstructions[$language][$CheckName]
    }
    
    # Fallback to English
    if ($gpoInstructions["English"].ContainsKey($CheckName)) {
        return $gpoInstructions["English"][$CheckName]
    }
    
    return "GPO configuration required"
}

function Get-LocalizedMessages {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MessageKey
    )
    
    $language = Get-SystemLanguage
    
    $messages = @{
        "English" = @{
            "LoadingCheckFunctions" = "Loading Check-* functions..."
            "FunctionsLoaded" = "Functions loaded"
            "LoadingRemediationFunctions" = "Loading Remediate-* functions..."
            "RemediationFunctionsLoaded" = "Remediation functions loaded"
            "ExecutingRemediations" = "Executing {0} remediation(s)..."
            "RemediationSummary" = "=== REMEDIATION SUMMARY ==="
            "RemediationsExecuted" = "Remediations executed"
            "GPOsCreated" = "GPOs created"
            "Failures" = "Failures"
            "CreatedGPOs" = "=== CREATED GPOs ==="
            "NextSteps" = "=== NEXT STEPS ==="
            "OpenGPMC" = "1. Open Group Policy Management Console (gpmc.msc)"
            "NavigateToGPOs" = "2. Navigate to 'Group Policy Objects'"
            "LinkGPOs" = "3. Link the created GPOs to your desired domains or OUs"
            "RunGPUpdate" = "4. Run 'gpupdate /force' on target computers"
            "FailedRemediations" = "=== FAILED REMEDIATIONS ==="
            "ExecutionCompleted" = "=== EXECUTION COMPLETED ==="
        }
        "French" = @{
            "LoadingCheckFunctions" = "Chargement des fonctions Check-*..."
            "FunctionsLoaded" = "Fonctions chargées"
            "LoadingRemediationFunctions" = "Chargement des fonctions Remediate-*..."
            "RemediationFunctionsLoaded" = "Fonctions de remediation chargées"
            "ExecutingRemediations" = "Exécution de {0} remediation(s)..."
            "RemediationSummary" = "=== RÉSUMÉ DE LA REMEDIATION ==="
            "RemediationsExecuted" = "Remediations exécutées"
            "GPOsCreated" = "GPO créés"
            "Failures" = "Échecs"
            "CreatedGPOs" = "=== GPO CRÉÉS ==="
            "NextSteps" = "=== ÉTAPES SUIVANTES ==="
            "OpenGPMC" = "1. Ouvrir la console de gestion des stratégies de groupe (gpmc.msc)"
            "NavigateToGPOs" = "2. Naviguer vers 'Objets de stratégie de groupe'"
            "LinkGPOs" = "3. Lier les GPO créés à vos domaines ou UO souhaités"
            "RunGPUpdate" = "4. Exécuter 'gpupdate /force' sur les ordinateurs cibles"
            "FailedRemediations" = "=== REMEDIATIONS ÉCHOUÉES ==="
            "ExecutionCompleted" = "=== EXÉCUTION TERMINÉE ==="
        }
    }
    
    if ($messages.ContainsKey($language) -and $messages[$language].ContainsKey($MessageKey)) {
        return $messages[$language][$MessageKey]
    }
    
    # Fallback to English
    if ($messages["English"].ContainsKey($MessageKey)) {
        return $messages["English"][$MessageKey]
    }
    
    return $MessageKey
}
