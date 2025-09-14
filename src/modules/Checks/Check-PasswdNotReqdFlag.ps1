function Check-PasswdNotReqdFlag {

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
        ID                = 25
        Action            = "PASSWD_NOTREQD Flag Status"
        Status            = "UNKNOWN"
        DetectedValue     = $null
        FlaggedAccounts   = @()
        Recommendation    = "Remove PASSWD_NOTREQD flag from all accounts to enforce password requirement."
    }

    try {
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.Action = "PASSWD_NOTREQD Check Skipped"
            $result.DetectedValue = "Active Directory module not available"
            return $result
        }

        $accountsWithFlag = Get-ADUser -Filter { userAccountControl -band 0x0020 } `
            -Properties userAccountControl, SamAccountName, Enabled, PasswordLastSet `
            -ErrorAction SilentlyContinue

        if (-not $accountsWithFlag -or $accountsWithFlag.Count -eq 0) {
            $result.Status = "OK"
            $result.Action = "PASSWD_NOTREQD Cleared"
            $result.DetectedValue = "No accounts with PASSWD_NOTREQD flag"
        } else {
            $result.Status = "FAIL"
            $result.Action = "PASSWD_NOTREQD Accounts Found"
            $result.DetectedValue = "$($accountsWithFlag.Count) accounts with PASSWD_NOTREQD flag"
            $result.FlaggedAccounts = $accountsWithFlag | Select-Object SamAccountName, Enabled, PasswordLastSet
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "PASSWD_NOTREQD Check Error"
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

        if ($result.FlaggedAccounts.Count -gt 0) {
            foreach ($acct in $result.FlaggedAccounts) {
                $state = if ($acct.Enabled) { "ENABLED" } else { "DISABLED" }
                $pwdLast = if ($acct.PasswordLastSet) { $acct.PasswordLastSet } else { "Never" }
                Write-Host ("   - {0} [{1}] PasswordLastSet: {2}" -f $acct.SamAccountName, $state, $pwdLast) -ForegroundColor Yellow
            }
        }
    }

    return $result
}
