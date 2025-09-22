# ==============================

# TEMPLATE-Remediate.ps1

# Template to create a new remediation function

# ==============================



function Remediate-<Name> {

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs","")]

    param(

        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"

    )



    if (Test-Path $SettingsPath) {

        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json

    } else {

        $settings = @{ EnableWhatIfByDefault = $true }

    }



    Write-ADHCLog "Starting <Name> remediation (WhatIf: $($settings.EnableWhatIfByDefault))"



    try {

        # ==============================

        # VÉRIFICATIONS PRÉLIMINAIRES

        # ==============================

        

        # Exemple de vérification de permissions :

        # if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {

        #     Write-Error "Privilèges administrateur requis pour cette remédiation"

        #     return

        # }

        

        # Exemple de vérification de module :

        # if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {

        #     Write-Error "Module Active Directory non disponible. Impossible d'appliquer la remédiation."

        #     return

        # }

        

        # ==============================

        # LOGIQUE DE REMÉDIATION ICI

        # ==============================

        

        # APPEL OBLIGATOIRE À SHOULDPROCESS

        if ($PSCmdlet.ShouldProcess("<Name>", "Apply remediation steps")) {

            # ==============================

            # VOTRE LOGIQUE DE REMÉDIATION ICI

            # ==============================

            

            # Exemple de modification de registre :

            # $regPath = "HKLM:\Path\To\Registry\Key"

            # try {

            #     # Créer la clé si elle n'existe pas

            #     if (-not (Test-Path $regPath)) {

            #         New-Item -Path $regPath -Force | Out-Null

            #     }

            #     

            #     # Définir la valeur

            #     Set-ItemProperty -Path $regPath -Name "ValueName" -Value 0 -Force

            #     Write-Host "[Remediation] Configuration appliquée: $regPath" -ForegroundColor Green

            #     Write-ADHCLog "Registry remediation applied successfully"

            # }

            # catch {

            #     Write-Error "Erreur lors de la modification du registre : $($_.Exception.Message)"

            #     Write-ADHCLog "Registry remediation failed: $($_.Exception.Message)"

            # }

            

            # Exemple de modification de service :

            # $serviceName = "ServiceName"

            # try {

            #     # Arrêter le service

            #     Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue

            #     

            #     # Désactiver le service

            #     Set-Service -Name $serviceName -StartupType Disabled

            #     

            #     Write-Host "[Remediation] Service $serviceName arrêté et désactivé" -ForegroundColor Green

            #     Write-ADHCLog "Service remediation applied successfully"

            # }

            # catch {

            #     Write-Error "Erreur lors de la modification du service : $($_.Exception.Message)"

            #     Write-ADHCLog "Service remediation failed: $($_.Exception.Message)"

            # }

            

            # Exemple de modification Active Directory :

            # try {

            #     # Obtenir l'objet AD

            #     $adObject = Get-ADObject -Identity "CN=TestObject,DC=domain,DC=com" -ErrorAction SilentlyContinue

            #     if ($adObject) {

            #         # Modifier l'objet

            #         Set-ADObject -Identity $adObject.DistinguishedName -Replace @{ "attributeName" = "newValue" }

            #         Write-Host "[Remediation] Objet AD modifié" -ForegroundColor Green

            #         Write-ADHCLog "AD object remediation applied successfully"

            #     } else {

            #         Write-Warning "Objet AD non trouvé"

            #         Write-ADHCLog "AD object not found, skipping remediation"

            #     }

            # }

            # catch {

            #     Write-Error "Erreur lors de la modification AD : $($_.Exception.Message)"

            #     Write-ADHCLog "AD object remediation failed: $($_.Exception.Message)"

            # }

            

            # ==============================

            # FIN DE VOTRE LOGIQUE DE REMÉDIATION

            # ==============================

            

            # Journaliser l'action

            Write-ADHCLog "Remediation Applied: Remediate-<Name>"

            Write-Host "[Remediation] Remédiation appliquée avec succès" -ForegroundColor Green

        } else {

            # Cas où ShouldProcess retourne $false (WhatIf ou confirmation refusée)

            Write-ADHCLog "Remediation Skipped (WhatIf/Confirm): Remediate-<Name>"

            Write-Host "[Remediation] Simulation effectuée (WhatIf/Confirm)" -ForegroundColor Cyan

        }

        

    }

    catch {

        Write-Error "Erreur lors de la remédiation : $($_.Exception.Message)"

        Write-ADHCLog "Remediation Error: Remediate-<Name> - $($_.Exception.Message)"

    }

}



# ==============================

# INSTRUCTIONS D'UTILISATION

# ==============================

# 1. Copier ce fichier vers src/modules\Remediations/Remediate-<Name>.ps1

# 2. Remplacer <Name> par le nom de votre remédiation (ex: Remediate-SMBv2)

# 3. Remplacer ConfirmImpact par 'Low', 'Medium' ou 'High' selon l'impact

# 4. Implémenter la logique de remédiation dans le bloc if ($PSCmdlet.ShouldProcess(...))

# 5. L'appel à ShouldProcess est OBLIGATOIRE et déjà présent dans le template

# 6. Ajouter des vérifications de permissions si nécessaire

# 7. Tester avec -WhatIf d'abord, puis sans paramètres

# 8. Vérifier l'idempotence (peut être exécuté plusieurs fois)

# 9. Utiliser $settings pour éviter les avertissements de variables inutilisées

# 10. Ajouter Write-ADHCLog pour toutes les actions importantes

# ==============================

