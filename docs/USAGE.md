# 📖 Guide d'utilisation – AD Hardening Checker

Ce guide explique comment utiliser le script `AD-Hardening-Checker.ps1` pour auditer, analyser et corriger la configuration de sécurité d'Active Directory.

---

## 🛠️ Prérequis

- **PowerShell 5.1+** (ou PowerShell 7.x recommandé pour portabilité).
- **Droits d'exécution** :
  - Pour les contrôles liés à Active Directory (MachineAccountQuota, Delegation…), il faut être membre du domaine et disposer de droits de lecture AD.
  - Pour certaines remédiations (désactivation services, modifications registre), exécuter **en tant qu'administrateur**.
- **Modules requis** : aucun module tiers, uniquement cmdlets natives Windows/PowerShell.

---

## 🚀 Utilisation de base

### 1️⃣ Phase 1 – Audit

Exécute le script en mode `Audit` pour vérifier les **27 points de durcissement AD**.

```powershell
.\src\AD-Hardening-Checker.ps1 -Mode Audit

Résultat : un fichier results/AD_Hardening_Report.csv contenant pour chaque contrôle :

ID → identifiant du contrôle

Action → nom du paramètre vérifié

Status → OK, FAIL, ou WARN

DetectedValue → valeur observée

Recommendation → recommandation de remédiation

Exemple de sortie console :

=== Phase Audit ===
27 contrôles exécutés
Résultats exportés dans .\results\AD_Hardening_Report.csv

2️⃣ Phase 2 – Analyse

Exécute le script en mode Analyse pour lire le CSV généré et afficher un résumé lisible.

.\src\AD-Hardening-Checker.ps1 -Mode Analyse
=== Résumé de l'Audit AD ===
Nombre de contrôles en échec : 8

[ID 1] LLMNR Disabled → Configurer la GPO 'Turn Off Multicast Name Resolution' sur Enabled.
[ID 8] SMBv1 Disabled → Désactiver SMBv1 (Remove-WindowsFeature FS-SMB1 ou Disable-WindowsOptionalFeature SMB1Protocol).
[ID 12] LSASS Protection → Activer RunAsPPL via clé de registre + redémarrage.
...

3️⃣ Phase 3 – Remédiation

Exécute le script en mode Remediate pour appliquer des corrections ciblées.
Il faut spécifier les ID à remédier avec -RemediationList.

.\src\AD-Hardening-Checker.ps1 -Mode Remediate -RemediationList 1,2,8 -WhatIf

-WhatIf : affiche les actions qui seraient effectuées, sans rien appliquer.

-Confirm : demande une confirmation avant chaque modification.

Pour appliquer réellement :

.\src\AD-Hardening-Checker.ps1 -Mode Remediate -RemediationList 1,2,8 -Confirm

📂 Fichiers générés
Fichier	Contenu
results/AD_Hardening_Report.csv	Rapport complet d’audit (27 lignes, une par contrôle).
results/logs/Remediation-YYYYMMDD.log	Journal des remédiations exécutées, avec résultat de chaque action.

⚠️ Bonnes pratiques

Toujours exécuter d’abord en mode Audit, puis analyser les résultats avant toute action.

Utiliser -WhatIf pour valider l’impact avant une remédiation réelle.

Tester les modifications en environnement de pré-production avant déploiement global.

Conserver les fichiers CSV comme preuve d’audit et pour comparer l’évolution dans le temps.

🎯 Exemple de workflow complet
# 1. Audit
.\src\AD-Hardening-Checker.ps1 -Mode Audit

# 2. Analyse des résultats
.\src\AD-Hardening-Checker.ps1 -Mode Analyse

# 3. Appliquer uniquement les remédiations prioritaires
.\src\AD-Hardening-Checker.ps1 -Mode Remediate -RemediationList 1,8,12 -Confirm


📌 Notes

Certains contrôles nécessitent d'être exécutés depuis un contrôleur de domaine pour remonter des données fiables (ex : MachineAccountQuota, Delegation).

Pour les environnements volumineux, il est recommandé d’exécuter le script en parallèle sur plusieurs DCs et agréger les résultats.

