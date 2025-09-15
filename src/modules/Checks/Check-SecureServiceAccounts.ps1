function Check-SecureServiceAccounts {

    [CmdletBinding()]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        Write-Verbose "settings.json not found, using default values"
        $settings = @{ }
    }

    $result = [PSCustomObject]@{
        ID                = 26
        Action            = "Service Accounts Security Status"
        Status            = "UNKNOWN"
        DetectedValue     = $null
        WeakAccounts      = @()
        MultiSPNAccounts  = @()
        Recommendation    = "Use gMSA (Group Managed Service Accounts) where possible, rotate passwords of traditional Service accounts every ≤90 days, and review accounts with multiple SPNs to reduce Kerberoasting risk."
    }

    try {
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.Action = "Service Accounts Security Check Skipped"
            $result.DetectedValue = "Active Directory module not available"
            return $result
        }

        $securityIndicators = @()

        $gmsaAccounts = Get-ADServiceAccount -Filter {ObjectClass -eq "msDS-GroupManagedServiceAccount"} -ErrorAction SilentlyContinue
        if ($gmsaAccounts) {
            $securityIndicators += "gMSA detected ($($gmsaAccounts.Count))"
        }

        $ServiceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet -ErrorAction SilentlyContinue
        foreach ($account in $ServiceAccounts) {
            $passwordAgeDays = ((Get-Date) - $account.PasswordLastSet).Days
            if ($passwordAgeDays -gt 90) {
                $result.WeakAccounts += [PSCustomObject]@{
                    SamAccountName   = $account.SamAccountName
                    PasswordLastSet  = $account.PasswordLastSet
                    AgeDays          = $passwordAgeDays
                }
            }
        }

        if ($result.WeakAccounts.Count -gt 0) {
            $securityIndicators += "$($result.WeakAccounts.Count) Service accounts with passwords older than 90 days"
        } elseif ($ServiceAccounts.Count -gt 0) {
            $securityIndicators += "All Service account passwords updated within last 90 days"
        }

        $multiSPNAccounts = $ServiceAccounts | Where-Object { $_.ServicePrincipalName.Count -gt 1 }
        if ($multiSPNAccounts) {
            $result.MultiSPNAccounts = $multiSPNAccounts | Select-Object SamAccountName, ServicePrincipalName
            $securityIndicators += "$($multiSPNAccounts.Count) accounts with multiple SPNs (review exposure)"
        }

        if ($gmsaAccounts -and $result.WeakAccounts.Count -eq 0 -and $multiSPNAccounts.Count -eq 0) {
            $result.Status = "OK"
            $result.Action = "Service Accounts Secured"
            $result.DetectedValue = "Strong security: $($securityIndicators -join ', ')"
        }
        elseif ($gmsaAccounts -or $ServiceAccounts.Count -gt 0) {
            $result.Status = "WARN"
            $result.Action = "Service Accounts Partially Secured"
            $result.DetectedValue = "Partial security: $($securityIndicators -join ', ')"
        }
        else {
            $result.Status = "FAIL"
            $result.Action = "Service Accounts Not Secured"
            $result.DetectedValue = "No gMSA and no Service accounts with recent password hygiene detected"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "Service Accounts Security Check Error"
        $result.DetectedValue = "Error: $($_.Exception.Message)"
    }

    if ($settings.ShowRecommendationsInConsole -eq $true) {
        $color = switch ($result.Status) {
            "OK"   { $settings.Color_OK }
            "FAIL" { $settings.Color_FAIL }
            "WARN" { $settings.Color_WARN }
            default { "White" }
        }

        Write-Host ("[ID {0}] {1} -> {2}" -f $result.ID, $result.Action, $result.Status) -ForegroundColor $color
        Write-Host ("   Detected: {0}" -f $result.DetectedValue) -ForegroundColor $color

        if ($result.WeakAccounts.Count -gt 0) {
            foreach ($acc in $result.WeakAccounts) {
                Write-Host ("   - Weak Account: {0} (Password last set: {1}, {2} days old)" -f `
                    $acc.SamAccountName, $acc.PasswordLastSet, $acc.AgeDays) -ForegroundColor Yellow
            }
        }

        if ($result.MultiSPNAccounts.Count -gt 0) {
            foreach ($acc in $result.MultiSPNAccounts) {
                Write-Host ("   - Multi-SPN Account: {0} (SPNs: {1})" -f `
                    $acc.SamAccountName, ($acc.ServicePrincipalName -join '; ')) -ForegroundColor Yellow
            }
        }
    }

    return $result
}
