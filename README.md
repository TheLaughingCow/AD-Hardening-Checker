# 🛡️ AD-Hardening-Checker

**PowerShell script for Active Directory hardening audit and remediation**

## 📋 Description

HardenADCheck is a comprehensive PowerShell tool that allows you to audit, analyze, and remediate 27 critical Active Directory security points. It operates in three distinct modes for a methodical approach to AD hardening.

## 🚀 Features

### **Audit Mode**
- Checks 27 AD security controls
- Exports results to CSV
- Automatic vulnerability detection
- Detailed logs of all checks

### **Analysis Mode**
- Analyzes audit results
- Counts failures and warnings
- Prioritizes corrections (QuickWin)2
- Exit codes for automation

### **Remediation Mode**
- Automatic correction of identified issues
- WhatIf and Confirm support for safety
- Selective remediation by ID
- Complete action logs

## 📦 Installation

### Prerequisites
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+
- Active Directory module (RSAT-AD-PowerShell)
- Administrator privileges

### Install AD Module
```powershell
# On Windows Server (usually already installed)
# On Windows 10/11
Install-WindowsFeature -Name RSAT-AD-PowerShell
```

### Download
```bash
git clone https://github.com/your-repo/HardenADCheck.git
cd HardenADCheck
```

## 🎯 Usage

### 1. Complete audit
```powershell
cd src
.\AD-Hardening-Checker.ps1 -Mode Audit
```

### 2. Analyze results
```powershell
.\AD-Hardening-Checker.ps1 -Mode Analyse
```

### 3. Simulate corrections
```powershell
.\AD-Hardening-Checker.ps1 -Mode Remediate -RemediationList 1,2,8 -WhatIf
```

### 4. Apply corrections
```powershell
.\AD-Hardening-Checker.ps1 -Mode Remediate -RemediationList 1,2,8 -Confirm
```

## 📊 Security Controls

| ID | Control                  | Description                       |
|----|--------------------------|-----------------------------------|
|  1 | LLMNR                    | Disable LLMNR                     |
|  2 | NBT-NS                   | Disable NBT-NS                    |
|  3 | mDNS/Bonjour             | Disable mDNS/Bonjour              |
|  4 | SMBv1                    | Disable SMBv1                     |
|  5 | SMB Signing              | Force SMB signing                 |
|  6 | LDAP Signing             | Force LDAP signing                |
|  7 | Print Spooler            | Disable print spooler             |
|  8 | Machine Account Quota    | Limit machine account creation    |
|  9 | LAPS                     | Check LAPS configuration          |
| 10 | Unconstrained Delegation | Disable unconstrained delegation  |
| 11 | Protected Users          | Check Protected Users group       |
| 12 | LSASS Protected Mode     | Enable LSASS protected mode       |
| 13 | SMB Null Session         | Disable SMB null sessions         |
| 14 | LDAP Anonymous Bind      | Disable LDAP anonymous binds      |
| 15 | Password Policy          | Check password policy             |
| 16 | RID Brute Force          | RID brute force mitigation        |
| 17 | Pre-Win2k Access         | Disable Pre-Windows 2000 access   |
| 18 | IPv6 Management          | Secure IPv6 management            |
| 19 | NTLM Restriction         | NTLM restriction                  |
| 20 | Share ACLs               | Share restrictions                |
| 21 | Default Credentials      | Eliminate default credentials     |
| 22 | Kerberos PreAuth         | Force Kerberos pre-authentication |
| 23 | Coercion Patches         | Anti-coercion patches             |
| 24 | Tiered Admin Model       | Tiered administration model       |
| 25 | PasswdNotReqd Flag       | Disable PasswdNotReqd flag        |
| 26 | Secure Service Accounts  | Secure service accounts           |
| 27 | Security Baseline        | General security baseline         |

## ⚙️ Configuration

The `config/settings.json` file allows customization:

```json
{
  "CsvPath": "./results/AD_Hardening_Report.csv",
  "LogPath": "./results/logs",
  "Color_OK": "Green",
  "Color_FAIL": "Red",
  "Color_WARN": "Yellow",
  "QuickWinPriority": [1,2,3,4,5,6,7,8,9,10,11,12],
  "WarnThreshold": 5,
  "FailThreshold": 1,
  "AllowedRemediations": [1,2,3,4,5,6,7,8,9,10,12,13,14,22,25,26]
}
```

## 🔄 Recommended Workflow

1. **Initial audit** : Identify vulnerabilities
2. **Analysis** : Prioritize corrections
3. **Simulation** : Test with `-WhatIf`
4. **Remediation** : Apply corrections
5. **Verification** : New audit to validate

## 🛡️ Security

- **Always test** with `-WhatIf` before application
- **Backup** AD before remediations
- **Test** on a test environment first
- **Verify** required AD permissions

## 📝 Logs and Reports

- **CSV** : `results/AD_Hardening_Report.csv`
- **Logs** : `results/logs/` (timestamped)
- **Console** : Real-time display with colors

## 🆘 Troubleshooting

### Missing AD Module
```powershell
Get-Module -Name ActiveDirectory -ListAvailable
Install-WindowsFeature -Name RSAT-AD-PowerShell
```

### Permission Errors
```powershell
# Check administrator privileges
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
```

### Execution Policy
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 🤝 Contributing

1. Fork the project
2. Create a feature branch
3. Commit changes
4. Push to the branch
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for details.

## 🔗 Useful Links

- [Microsoft AD Documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/)
- [AD Hardening Guide](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/)
- [PowerShell Security](https://docs.microsoft.com/en-us/powershell/scripting/security/)

---

**🎯 AD-Hardening-Checker - Secure your Active Directory with confidence!**
