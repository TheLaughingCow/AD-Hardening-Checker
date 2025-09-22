# AD Hardening Checker – Architecture

## 🎯 Objectif du projet
**AD Hardening Checker** est un outil PowerShell interactif qui permet de :
- **Auditer** l’état de durcissement d’un environnement Active Directory,
- **Analyser** les résultats et fournir des recommandations lisibles,
- **Appliquer** des remédiations ciblées, de manière contrôlée et sécurisée.

L’objectif est de fournir aux administrateurs, pentesters et équipes SOC un **outil unique** pour :
- Évaluer la posture de sécurité AD,
- Prioriser les actions correctives,
- Automatiser la mise en conformité, tout en gardant la main sur ce qui est appliqué.

---

## 🏗️ Architecture technique

### 1. Structure des fichiers
AD-Hardening-Checker/
├── src/
│ ├── AD-Hardening-Checker.ps1 # Point d'entrée principal
│ ├── modules/
│ │ ├── Checks/ # Fonctions Test-* (27 contrôles)
│ │ ├── Remediations/ # Fonctions Remediate-* pour correction
│ │ └── Utils.psm1 # Fonctions utilitaires (CSV, logs, affichage)
│ └── config/settings.json # Options de configuration (CSV path, seuils)
├── results/ # Rapports générés (CSV + logs)
└── docs/ # Documentation (ARCHITECTURE.md, USAGE.md…)


---

### 2. Phases d’exécution

#### Phase 1 – Audit
- Vérifie **27 points de durcissement AD**.
- Chaque vérification est encapsulée dans une fonction `Test-*` qui retourne un objet PowerShell avec :
  - `ID`
  - `Action`
  - `Status` (OK / FAIL / WARN)
  - `DetectedValue`
  - `Recommendation`
- Tous les résultats sont exportés dans un fichier CSV unique (`AD_Hardening_Report.csv`).

#### Phase 2 – Analyse
- Lit le CSV généré en phase 1.
- Agrège les résultats : compte les FAIL/WARN, affiche un résumé en console.
- Priorise les recommandations : les quick wins (LLMNR, NBT-NS, SMBv1, LSASS PPL…) sont signalés en premier.
- Génère un rapport texte ou HTML optionnel pour diffusion.

#### Phase 3 – Remédiation
- Applique uniquement les remédiations sélectionnées via `-RemediationList`.
- Chaque remédiation est encapsulée dans une fonction `Remediate-*`.
- Toutes les actions supportent `-WhatIf` et `-Confirm` pour éviter les changements non désirés.
- Les résultats (succès/erreur) sont loggés dans `results/logs/`.

---

### 3. Liste des 27 contrôles

| # | Contrôle | Objectif |
|---|----------|----------|
| 1 | LLMNR désactivé | Éviter le poisoning (Responder, etc.) |
| 2 | NBT-NS désactivé | Supprimer la résolution héritée vulnérable |
| 3 | mDNS désactivé | Réduire l’exposition Bonjour/Apple |
| 4 | MachineAccountQuota = 0 | Empêcher la création sauvage de machines dans l’AD |
| 5 | SMB Signing activé | Empêcher attaques relay man-in-the-middle |
| 6 | LDAP Signing activé | Forcer LDAP sécurisé / signed |
| 7 | Print Spooler désactivé sur DC | Bloquer attaques PrintNightmare |
| 8 | SMBv1 désactivé | Supprimer protocole obsolète vulnérable |
| 9 | LAPS déployé | Mots de passe locaux uniques et rotatifs |
| 10 | Unconstrained Delegation désactivée | Empêcher vol de TGT/Kerberos |
| 11 | Comptes sensibles → Protected Users | Bloquer NTLM, DES/RC4, délégation |
| 12 | LSASS protégé (RunAsPPL) | Empêcher dump mémoire (Mimikatz) |
| 13 | SMB Null Session désactivé | Supprimer accès anonyme IPC$ |
| 14 | LDAP Anonymous Bind désactivé | Supprimer requêtes LDAP non authentifiées |
| 15 | Password Policy renforcée | Complexité et expiration conformes |
| 16 | RID Brute Force Mitigation | Empêcher énumération SID massive |
| 17 | Groupe Pre-Win2k vide | Supprimer héritages inutiles |
| 18 | IPv6 correctement géré | Pas de désactivation brutale (compatibilité AD) |
| 19 | NTLM restreint / audit | Préparer migration vers NTLMv2 only |
| 20 | ACL de partages durcies | Moindre privilège sur shares |
| 21 | Credentials par défaut changés | Supprimer comptes admin locaux communs |
| 22 | Kerberos Pre-Auth forcée | Empêcher AS-REP roasting |
| 23 | Patch coercion (PetitPotam, etc.) | Mitiger NTLM relay via MS-EFSRPC, etc. |
| 24 | Tiering Admin Model / PAW | Réduire surface d'attaque comptes DA |
| 25 | Aucun compte PASSWD_NOTREQD | Supprimer comptes sans mot de passe |
| 26 | Comptes de service sécurisés / gMSA | Éviter Kerberoast / mots de passe faibles |
| 27 | Security Baseline appliquée | GPO avec paramètres UAC, Defender, Firewall, Audit, LSA, Réseau |

---

### 4. Design des fonctions

#### Exemple de fonction de test
```powershell
function Test-LLMNR {
    $reg = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue
    $status = if ($reg.EnableMulticast -eq 0) { "OK" } else { "FAIL" }
    [PSCustomObject]@{
        ID = 1
        Action = "LLMNR Disabled"
        Status = $status
        DetectedValue = $reg.EnableMulticast
        Recommendation = "Configurer la GPO 'Turn Off Multicast Name Resolution' sur Enabled."
    }
}

Exemple de fonction de remédiation

function Remediate-LLMNR {
    param([switch]$WhatIf, [switch]$Confirm)
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 0 -Force @PSBoundParameters
}

5. Journalisation et rapport

Tous les résultats de phase 1 sont enregistrés dans results/AD_Hardening_Report.csv.

Un fichier log texte est créé pour les actions de remédiation (results/logs/Remediation-yyyyMMdd.log).

Possibilité future d’exporter un rapport HTML (template à ajouter dans /docs/templates).

6. Extensibilité

Ajouter un nouveau contrôle = créer un fichier Test-NewCheck.ps1 dans modules/Checks/ et l’ajouter dans la liste de la phase Audit.

Ajouter une remédiation = fichier Remediate-NewCheck.ps1 dans modules/Remediations/.

7. Compatibilité

Compatible PowerShell 5.1+ et PowerShell 7.

Aucune dépendance externe (pas de PowerView / PowerSploit).

Fonctionne sur poste membre du domaine ou sur un DC (droits nécessaires pour certaines vérifications AD).

🚀 Roadmap