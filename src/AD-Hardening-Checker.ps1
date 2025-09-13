#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Audit", "Analysis", "Remediation")]
    [string]$Mode,
    
    [Parameter(Mandatory = $false)]
    [string]$CsvPath,
    
    [Parameter(Mandatory = $false)]
    [int[]]$RemediationList
)

$ScriptRoot = Split-Path -Parent $PSCommandPath

$LoadModulesPath = Join-Path $ScriptRoot "Load-Modules.ps1"
if (Test-Path $LoadModulesPath) {
    . $LoadModulesPath
    $LoadedModules = Import-ADHCModules
    if ($LoadedModules) {
        Write-Verbose "Modules loaded: $($LoadedModules.Checks.Count) tests, $($LoadedModules.Remediations.Count) remediations"
    } else {
        Write-Error "Failed to load modules"
        exit 1
    }
} else {
    Write-Error "Load-Modules.ps1 script not found: $LoadModulesPath"
    exit 1
}

if (Get-Module -Name ActiveDirectory -ListAvailable) {
    try {
        Import-Module ActiveDirectory -Force -ErrorAction Stop
        Write-Verbose "Active Directory module imported successfully"
    }
    catch {
        Write-Warning "Unable to import Active Directory module: $($_.Exception.Message)"
        Write-Warning "Some AD checks will not work properly"
    }
} else {
    Write-Warning "Active Directory module not available on this system"
    Write-Warning "AD checks and remediations will not work"
    Write-Warning "Install with: Install-WindowsFeature -Name RSAT-AD-PowerShell"
}

$SettingsPath = Join-Path $ScriptRoot "config\settings.json"
$DefaultSettings = @{
    CsvPath = "results\AD_Hardening_Report.csv"
    LogPath = "results\logs"
    ShowRecommendationsInConsole = $true
    Color_OK = "Green"
    Color_FAIL = "Red"
    Color_WARN = "Yellow"
    QuickWinPriority = @(1, 2, 8, 5, 6, 7, 9, 10)
    FailThreshold = 1
    WarnThreshold = 5
    AllowedRemediations = @(1,2,3,4,5,6,7,8,9,10,12,13,14,22,25,26)
}

if (Test-Path $SettingsPath) {
    try {
        $SettingsContent = Get-Content $SettingsPath -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($SettingsContent)) {
            Write-Warning "Configuration file is empty, using default values"
            $Settings = $DefaultSettings
        } else {
            $Settings = $SettingsContent | ConvertFrom-Json
            Write-Verbose "Configuration loaded from: $SettingsPath"
            
            foreach ($key in $DefaultSettings.Keys) {
                if (-not $Settings.PSObject.Properties.Name -contains $key) {
                    $Settings | Add-Member -NotePropertyName $key -NotePropertyValue $DefaultSettings[$key] -Force
                    Write-Verbose "Missing property added: $key = $($DefaultSettings[$key])"
                }
            }
        }
    }
    catch {
        Write-Warning "Unable to load configuration: $($_.Exception.Message)"
        Write-Warning "Using safe default values"
        $Settings = $DefaultSettings
    }
} else {
    Write-Warning "Configuration file not found: $SettingsPath"
    Write-Warning "Using safe default values"
    $Settings = $DefaultSettings
}

if (-not $CsvPath) {
    if ($Settings.CsvPath) {
        if ([System.IO.Path]::IsPathRooted($Settings.CsvPath)) {
            $CsvPath = $Settings.CsvPath
        } else {
            $CsvPath = Join-Path $ScriptRoot $Settings.CsvPath
        }
        Write-Verbose "CSV path from configuration: $CsvPath"
    } else {
        $CsvPath = Join-Path $ScriptRoot "results\AD_Hardening_Report.csv"
        Write-Verbose "Default CSV path: $CsvPath"
    }
}

$LogPath = $Settings.LogPath
if (-not [System.IO.Path]::IsPathRooted($LogPath)) {
    $LogPath = Join-Path $ScriptRoot $LogPath
}
Write-Verbose "Log path: $LogPath"

$CsvDir = Split-Path $CsvPath -Parent
if ($CsvDir -and -not (Test-Path $CsvDir)) {
    try {
        New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
        Write-Verbose "CSV directory created: $CsvDir"
    }
    catch {
        Write-Warning "Unable to create CSV directory: $($_.Exception.Message)"
    }
}

if ($LogPath -and -not (Test-Path $LogPath)) {
    try {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        Write-Verbose "Log directory created: $LogPath"
    }
    catch {
        Write-Warning "Unable to create log directory: $($_.Exception.Message)"
    }
}

function Start-AuditMode {
    [CmdletBinding()]
    param(
        [string]$CsvPath,
        [object]$Settings,
        [object]$LoadedModules
    )
    
    Write-Host "=== AUDIT MODE ===" -ForegroundColor Cyan
    Write-Host "CSV Path: $CsvPath" -ForegroundColor Yellow
    Write-Host "Available test functions: $($LoadedModules.Checks.Count)" -ForegroundColor Yellow
    Write-Host ""
    
    $testFunctions = Get-Command -CommandType Function | Where-Object { $_.Name -like "Test-*" }
    Write-Host "Test-* functions discovered: $($testFunctions.Count)" -ForegroundColor Green
    
    if ($testFunctions.Count -eq 0) {
        Write-Warning "No Test-* functions found. Check that modules are loaded correctly."
        return
    }
    
    if (-not (Test-Path $CsvPath)) {
        $header = "ID,Action,Status,DetectedValue,Recommendation"
        $header | Out-File -FilePath $CsvPath -Encoding UTF8 -Force
        Write-Verbose "CSV file initialized: $CsvPath"
    }
    
    $totalChecks = 0
    $okCount = 0
    $failCount = 0
    $warnCount = 0
    
    foreach ($function in $testFunctions) {
        $totalChecks++
        Write-Host "Executing $($function.Name)..." -ForegroundColor Yellow
        
        try {
            $result = & $function.Name
            
            if ($result -and $result.PSObject.Properties.Name -contains "ID" -and $result.PSObject.Properties.Name -contains "Status") {
                $result | Export-Csv -Path $CsvPath -Append -NoTypeInformation -Encoding UTF8
                
                $color = switch ($result.Status) {
                    "OK" { $Settings.Color_OK }
                    "FAIL" { $Settings.Color_FAIL }
                    "WARN" { $Settings.Color_WARN }
                    default { "White" }
                }
                
                Write-Host "  [$($result.Status)] $($result.Action)" -ForegroundColor $color
                
                switch ($result.Status) {
                    "OK" { $okCount++ }
                    "FAIL" { $failCount++ }
                    "WARN" { $warnCount++ }
                }
            } else {
                Write-Warning "Invalid result from $($function.Name)"
                $warnCount++
            }
        }
        catch {
            Write-Warning "Error executing $($function.Name): $($_.Exception.Message)"
            $warnCount++
        }
    }
    
    Write-Host ""
    Write-Host "=== AUDIT SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Total controls: $totalChecks" -ForegroundColor White
    Write-Host "OK: $okCount" -ForegroundColor Green
    Write-Host "FAIL: $failCount" -ForegroundColor Red
    Write-Host "WARN: $warnCount" -ForegroundColor Yellow
    
    if ($totalChecks -gt 0) {
        $complianceRate = [math]::Round(($okCount / $totalChecks) * 100, 2)
        $complianceColor = if($complianceRate -ge 80) {"Green"} elseif($complianceRate -ge 60) {"Yellow"} else {"Red"}
        Write-Host "Compliance rate: $complianceRate%" -ForegroundColor $complianceColor
    }
    
    Write-Host ""
    Write-Host "Results exported to: $CsvPath" -ForegroundColor Green
}

function Start-AnalysisMode {
    [CmdletBinding()]
    param(
        [string]$CsvPath,
        [object]$Settings
    )
    
    Write-Host "=== ANALYSIS MODE ===" -ForegroundColor Cyan
    Write-Host "CSV file: $CsvPath" -ForegroundColor Yellow
    Write-Host ""
    
    if (-not (Test-Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        Write-Host "Run Audit mode first to generate results."
        return
    }
    
    $csvContent = Get-Content $CsvPath -Raw
    if ([string]::IsNullOrWhiteSpace($csvContent)) {
        Write-Error "CSV file is empty: $CsvPath"
        return
    }
    
    try {
        Write-Host "Importing audit results..." -ForegroundColor Yellow
        $results = Import-Csv -Path $CsvPath -Encoding UTF8 -ErrorAction Stop
        
        if ($results.Count -eq 0) {
            Write-Warning "No results found in CSV file"
            return
        }
        
        $requiredColumns = @("ID", "Action", "Status", "DetectedValue", "Recommendation")
        $csvColumns = $results[0].PSObject.Properties.Name
        
        $missingColumns = @()
        foreach ($col in $requiredColumns) {
            if ($col -notin $csvColumns) {
                $missingColumns += $col
            }
        }
        
        if ($missingColumns.Count -gt 0) {
            Write-Error "Missing columns in CSV: $($missingColumns -join ', ')"
            return
        }
        
        $groupedResults = $results | Group-Object -Property Status
        
        $okResults = ($groupedResults | Where-Object { $_.Name -eq "OK" }).Group
        $failResults = ($groupedResults | Where-Object { $_.Name -eq "FAIL" }).Group
        $warnResults = ($groupedResults | Where-Object { $_.Name -eq "WARN" }).Group
        
        Write-Host "=== ANALYSIS SUMMARY ===" -ForegroundColor Cyan
        Write-Host "Total controls: $($results.Count)" -ForegroundColor White
        Write-Host "OK: $($okResults.Count)" -ForegroundColor Green
        Write-Host "FAIL: $($failResults.Count)" -ForegroundColor Red
        Write-Host "WARN: $($warnResults.Count)" -ForegroundColor Yellow
        
        if ($failResults.Count -gt 0) {
            Write-Host ""
            Write-Host "=== DETECTED FAILURES (by priority) ===" -ForegroundColor Red
            
            if ($Settings.QuickWinPriority -and $Settings.QuickWinPriority.Count -gt 0) {
                $sortedFails = $failResults | Sort-Object { 
                    $index = $Settings.QuickWinPriority.IndexOf([int]$_.ID)
                    if ($index -ge 0) { $index } else { 999 }
                }
            } else {
                $sortedFails = $failResults | Sort-Object ID
            }
            
            foreach ($fail in $sortedFails) {
                Write-Host "[ID $($fail.ID)] $($fail.Action)" -ForegroundColor Red
                Write-Host "  Detected value: $($fail.DetectedValue)" -ForegroundColor Yellow
                Write-Host "  Recommendation: $($fail.Recommendation)" -ForegroundColor Cyan
                Write-Host ""
            }
        }
        
        if ($failResults.Count -ge $Settings.FailThreshold) {
            Write-Host "Failure threshold reached ($($Settings.FailThreshold)). Exit code: 2" -ForegroundColor Red
            exit 2
        } elseif ($warnResults.Count -ge $Settings.WarnThreshold) {
            Write-Host "Warning threshold reached ($($Settings.WarnThreshold)). Exit code: 1" -ForegroundColor Yellow
            exit 1
        } else {
            Write-Host "All thresholds respected. Exit code: 0" -ForegroundColor Green
            exit 0
        }
    }
    catch {
        Write-Error "Error analyzing CSV file: $($_.Exception.Message)"
        exit 3
    }
}

function Start-RemediationMode {
    [CmdletBinding()]
    param(
        [int[]]$RemediationList,
        [string]$CsvPath,
        [object]$Settings,
        [object]$LoadedModules
    )
    
    Write-Host "=== REMEDIATION MODE ===" -ForegroundColor Cyan
    Write-Host "IDs to remediate: $($RemediationList -join ', ')" -ForegroundColor Yellow
    Write-Host "Available remediation functions: $($LoadedModules.Remediations.Count)" -ForegroundColor Yellow
    Write-Host "WhatIf: $WhatIfPreference" -ForegroundColor Yellow
    Write-Host "Confirm: $ConfirmPreference" -ForegroundColor Yellow
    Write-Host ""
    
    if ($RemediationList.Count -eq 0) {
        Write-Error "No remediation ID specified. Use -RemediationList to specify controls to process."
        Write-Host ""
        Write-Host "Usage examples:" -ForegroundColor Yellow
        Write-Host "  .\AD-Hardening-Checker.ps1 -Mode Remediation -RemediationList 1,2,8" -ForegroundColor Cyan
        Write-Host "  .\AD-Hardening-Checker.ps1 -Mode Remediation -RemediationList 1,2,8 -WhatIf" -ForegroundColor Cyan
        Write-Host "  .\AD-Hardening-Checker.ps1 -Mode Remediation -RemediationList 1,2,8 -Confirm" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Available IDs (1-27):" -ForegroundColor Yellow
        Write-Host "  1=LLMNR, 2=NBT-NS, 3=mDNS/Bonjour, 4=MachineAccountQuota, 5=SMB Signing" -ForegroundColor Cyan
        Write-Host "  6=LDAP Signing, 7=Print Spooler, 8=SMBv1, 9=LAPS, 10=Unconstrained Delegation" -ForegroundColor Cyan
        Write-Host "  11=Protected Users, 12=LSASS Protected, 13=SMB Null Session, 14=LDAP Anonymous" -ForegroundColor Cyan
        Write-Host "  15=Password Policy, 16=RID Brute Force, 17=Pre-Win2k Access, 18=IPv6 Management" -ForegroundColor Cyan
        Write-Host "  19=NTLM Restriction, 20=Share ACLs, 21=Default Credentials, 22=Kerberos PreAuth" -ForegroundColor Cyan
        Write-Host "  23=Coercion Patches, 24=Tiered Admin, 25=PasswdNotReqd, 26=Secure Service Accounts" -ForegroundColor Cyan
        Write-Host "  27=Security Baseline" -ForegroundColor Cyan
        return
    }
    
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
    
    $totalProcessed = 0
    $successCount = 0
    $errorCount = 0
    $skippedCount = 0
    
    foreach ($id in $RemediationList) {
        $totalProcessed++
        
        if ($id -lt 1 -or $id -gt 27) {
            Write-Warning "Invalid ID ignored: $id (must be between 1 and 27)"
            $errorCount++
            continue
        }
        
        if ($Settings.AllowedRemediations -and $id -notin $Settings.AllowedRemediations) {
            Write-Warning "ID $id not allowed for remediation (see AllowedRemediations in settings.json)"
            $skippedCount++
            continue
        }
        
        $functionName = $remediationMapping[$id]
        
        if (-not $functionName) {
            Write-Warning "No remediation function found for ID: $id"
            $errorCount++
            continue
        }
        
        $function = Get-Command -Name $functionName -CommandType Function -ErrorAction SilentlyContinue
        if (-not $function) {
            Write-Warning "Remediation function not found: $functionName"
            $errorCount++
            continue
        }
        
        Write-Host "Processing ID $id ($functionName)..." -ForegroundColor Yellow
        
        try {
            $functionParams = $function.Parameters
            
            $paramHash = @{}
            
            if ($functionParams.ContainsKey("WhatIf")) {
                $paramHash["WhatIf"] = $WhatIfPreference
            }
            
            if ($functionParams.ContainsKey("Confirm")) {
                $paramHash["Confirm"] = $ConfirmPreference
            }
            
            & $functionName @paramHash
            
            if ($WhatIfPreference) {
                $status = "Skipped (WhatIf)"
                $skippedCount++
                Write-Host "  ✓ Simulation completed (WhatIf)" -ForegroundColor Cyan
            } else {
                $status = "Applied"
                $successCount++
                Write-Host "  ✓ Remediation applied" -ForegroundColor Green
            }
            
            Write-ADHCLog "Remediation ${status}: ${functionName} (ID: ${id})"
        }
        catch {
            Write-Error "Error during remediation ${functionName}: $($_.Exception.Message)"
            $errorCount++
            Write-ADHCLog "Remediation Error: ${functionName} (ID: ${id}) - $($_.Exception.Message)"
        }
    }
    
    Write-Host ""
    Write-Host "=== REMEDIATION SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Total processed: $totalProcessed" -ForegroundColor White
    Write-Host "Success: $successCount" -ForegroundColor Green
    Write-Host "Errors: $errorCount" -ForegroundColor Red
    Write-Host "Simulated (WhatIf): $skippedCount" -ForegroundColor Cyan
    
    if ($errorCount -gt 0) {
        Write-Host ""
        Write-Host "⚠ Errors encountered. Check logs for details." -ForegroundColor Yellow
    }
    
    if ($WhatIfPreference) {
        Write-Host ""
        Write-Host "ℹ Simulation mode active. No changes applied." -ForegroundColor Blue
        Write-Host "To apply remediations, run without -WhatIf" -ForegroundColor Blue
    }
    
    Write-Host ""
    Write-Host "=== REMEDIATION COMPLETED ===" -ForegroundColor Green
}

try {
    Write-Host "=== AD HARDENING CHECKER ===" -ForegroundColor Green
    Write-Host "Mode: $Mode" -ForegroundColor White
    Write-Host "Version: 1.0" -ForegroundColor White
    Write-Host "PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor White
    Write-Host ""
    
    switch ($Mode) {
        "Audit" {
            Start-AuditMode -CsvPath $CsvPath -Settings $Settings -LoadedModules $LoadedModules
        }
        "Analysis" {
            Start-AnalysisMode -CsvPath $CsvPath -Settings $Settings
        }
        "Remediation" {
            Start-RemediationMode -RemediationList $RemediationList -CsvPath $CsvPath -Settings $Settings -LoadedModules $LoadedModules
        }
        default {
            Write-Error "Unknown mode: $Mode"
            exit 1
        }
    }
    
    Write-Host ""
    Write-Host "=== EXECUTION COMPLETED ===" -ForegroundColor Green
}
catch {
    Write-Error ("Execution error: {0}" -f $_.Exception.Message)
    Write-Error ("Details: {0}" -f $_.Exception.StackTrace)
    exit 1
}
