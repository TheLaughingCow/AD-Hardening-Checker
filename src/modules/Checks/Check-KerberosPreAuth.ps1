function Check-KerberosPreAuth {

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
        ID                 = 22
        Action             = "Kerberos Pre-Authentication Status"
        Status             = "UNKNOWN"
        DetectedValue      = $null
        VulnerableAccounts = @()
        Recommendation     = "Ensure Kerberos Pre-Authentication is required (clear DONT_REQ_PREAUTH flag) to prevent AS-REP roasting attacks."
    }

    try {
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.Action = "Kerberos Pre-Auth Check Skipped"
            $result.DetectedValue = "Active Directory module not available"
            return $result
        }

        $accountsWithoutPreAuth = Get-ADUser -Filter "userAccountControl -band 4194304" `
            -Properties userAccountControl,SamAccountName,Enabled,DistinguishedName -ErrorAction SilentlyContinue

        if (-not $accountsWithoutPreAuth) {
            $result.Status = "OK"
            $result.Action = "Kerberos Pre-Auth Fully Enforced"
            $result.DetectedValue = "All accounts require Kerberos Pre-Authentication"
        }
        else {
            $activeAccounts   = $accountsWithoutPreAuth | Where-Object { $_.Enabled -eq $true }
            $disabledAccounts = $accountsWithoutPreAuth | Where-Object { $_.Enabled -eq $false }

            if ($activeAccounts.Count -gt 0) {
                $result.Status = "FAIL"
                $result.Action = "Kerberos Pre-Auth Missing (Active Accounts)"
                $result.DetectedValue = "$($activeAccounts.Count) active accounts do not require Kerberos Pre-Authentication"
                $result.VulnerableAccounts = $activeAccounts | Select-Object SamAccountName,Enabled,DistinguishedName
            }
            elseif ($disabledAccounts.Count -gt 0) {
                $result.Status = "WARN"
                $result.Action = "Kerberos Pre-Auth Missing (Disabled Accounts)"
                $result.DetectedValue = "$($disabledAccounts.Count) disabled accounts have DONT_REQ_PREAUTH flag (risk if re-enabled)"
                $result.VulnerableAccounts = $disabledAccounts | Select-Object SamAccountName,Enabled,DistinguishedName
            }
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "Kerberos Pre-Auth Check Error"
        $result.DetectedValue = "Error: $($_.Exception.Message)"
    }

    if ($settings.ShowRecommendationsInConsole -eq $true) {
        $color = switch ($result.Status) {
            "OK"   { $settings.Color_OK }
            "FAIL" { $settings.Color_FAIL }
            "WARN" { $settings.Color_WARN }
            default { "White" }
        }

        Write-Host ("[ID {0}] {1} -> {2} (Detected: {3})" -f `
            $result.ID, $result.Action, $result.Status, $result.DetectedValue) -ForegroundColor $color

        if ($result.VulnerableAccounts.Count -gt 0) {
            foreach ($acct in $result.VulnerableAccounts) {
                $state = if ($acct.Enabled) { "ENABLED" } else { "DISABLED" }
                Write-Host ("   - {0} [{1}] ({2})" -f $acct.SamAccountName, $state, $acct.DistinguishedName) -ForegroundColor Yellow
            }
        }
    }

    return $result
}
