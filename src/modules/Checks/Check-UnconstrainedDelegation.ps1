function Check-UnconstrainedDelegation {

    [CmdletBinding()]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        Write-Verbose "settings.json not found, using default values."
        $settings = @{}
    }

    $result = [PSCustomObject]@{
        ID             = 10
        Action         = "Unconstrained Delegation Check"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        VulnerableAccounts = @()
        Recommendation = "Disable unconstrained delegation and enable 'Account is sensitive and cannot be delegated' on sensitive Users."
    }

    try {
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.Action = "Unconstrained Delegation Check Skipped"
            $result.DetectedValue = "Active Directory module not available"
            return $result
        }

        $unconstrainedComputers = Get-ADComputer -Filter { userAccountControl -band 0x80000 } -Properties Name, OperatingSystem -ErrorAction SilentlyContinue
        $unconstrainedUsers     = Get-ADUser     -Filter { userAccountControl -band 0x80000 } -Properties SamAccountName, Enabled -ErrorAction SilentlyContinue

        $totalUnconstrained = ($unconstrainedComputers | Measure-Object).Count + ($unconstrainedUsers | Measure-Object).Count

        if ($totalUnconstrained -eq 0) {
            $result.Status = "OK"
            $result.Action = "Unconstrained Delegation Disabled"
            $result.DetectedValue = "No computer or user accounts with unconstrained delegation"
        }
        else {
            $vulnList = @()

            if ($unconstrainedComputers) {
                $vulnList += $unconstrainedComputers | Select-Object @{Name="Type";Expression={"Computer"}}, Name, OperatingSystem
            }
            if ($unconstrainedUsers) {
                $vulnList += $unconstrainedUsers | Select-Object @{Name="Type";Expression={"User"}}, SamAccountName, Enabled
            }

            $result.Status = "FAIL"
            $result.Action = "Unconstrained Delegation Detected"
            $result.DetectedValue = "$totalUnconstrained accounts configured for unconstrained delegation"
            $result.VulnerableAccounts = $vulnList
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "Unconstrained Delegation Check Error"
        $result.DetectedValue = "Error while querying AD: $($_.Exception.Message)"
    }

    if ($settings.ShowRecommendationsInConsole -eq $true) {
        $color = switch ($result.Status) {
            "OK"   { $settings.Color_OK }
            "FAIL" { $settings.Color_FAIL }
            "WARN" { $settings.Color_WARN }
            default { "White" }
        }

        Write-Host ("[ID {0}] {1} -> {2}" -f $result.ID, $result.Action, $result.Status) -ForegroundColor $color
        Write-Host ("   Details: {0}" -f $result.DetectedValue) -ForegroundColor $color

        if ($result.VulnerableAccounts.Count -gt 0) {
            foreach ($acct in $result.VulnerableAccounts) {
                if ($acct.Type -eq "Computer") {
                    Write-Host ("   - Computer: {0} ({1})" -f $acct.Name, $acct.OperatingSystem) -ForegroundColor Yellow
                } else {
                    Write-Host ("   - User: {0} (Enabled={1})" -f $acct.SamAccountName, $acct.Enabled) -ForegroundColor Yellow
                }
            }
        }
    }

    return $result
}
