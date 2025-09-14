function Check-DefaultCredentials {
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
        ID                = 21
        Action            = "Default Credentials Check"
        Status            = "UNKNOWN"
        DetectedValue     = $null
        DetectedAccounts  = @()
        Recommendation    = "Change default credentials (local admin accounts, default passwords, common Service accounts)."
    }

    try {
        $defaultAdminAccounts = @("Administrator", "Admin", "root", "sa", "test", "guest")
        $foundDefaultAccounts = @()
        $adChecked = $false

        try {
            $localUsers = Get-LocalUser -ErrorAction SilentlyContinue
            foreach ($user in $localUsers) {
                if ($user.Name -in $defaultAdminAccounts -and $user.Enabled) {
                    $foundDefaultAccounts += [PSCustomObject]@{
                        Scope  = "Local"
                        Name   = $user.Name
                        Status = "Enabled"
                    }
                }
            }
        }
        catch {
            Write-Verbose "Unable to enumerate local Users: $($_.Exception.Message)"
        }

        if (Get-Module -Name ActiveDirectory -ListAvailable) {
            try {
                $adChecked = $true
                $domainUsers = Get-ADUser -Filter "Enabled -eq $true" -Properties Name -ErrorAction SilentlyContinue
                foreach ($user in $domainUsers) {
                    if ($user.Name -in $defaultAdminAccounts) {
                        $foundDefaultAccounts += [PSCustomObject]@{
                            Scope  = "Domain"
                            Name   = $user.Name
                            Status = "Enabled"
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Unable to query AD Users: $($_.Exception.Message)"
            }
        } else {
            Write-Verbose "Active Directory module not available, skipping domain account check"
        }

        try {
            $ServiceAccounts = Get-CimInstance -ClassName Win32_Service | Where-Object {
                $_.StartName -like "*Administrator*" -or $_.StartName -like "*sa*"
            }
            foreach ($Service in $ServiceAccounts) {
                $foundDefaultAccounts += [PSCustomObject]@{
                    Scope  = "Service"
                    Name   = $Service.Name
                    Status = $Service.StartName
                }
            }
        }
        catch {
            Write-Verbose "Unable to enumerate Services: $($_.Exception.Message)"
        }

        if ($foundDefaultAccounts.Count -eq 0) {
            $result.Status = "OK"
            $result.Action = "Default Credentials Secured"
            $result.DetectedValue = "No default accounts detected" + ($(if (-not $adChecked) { " (domain check skipped)" }))
        } else {
            $result.Status = "FAIL"
            $result.Action = "Default Credentials Detected"
            $result.DetectedValue = "$($foundDefaultAccounts.Count) default accounts found" + ($(if (-not $adChecked) { " (domain check skipped)" }))
            $result.DetectedAccounts = $foundDefaultAccounts
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "Default Credentials Check Error"
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

        if ($result.DetectedAccounts.Count -gt 0) {
            foreach ($acc in $result.DetectedAccounts) {
                Write-Host ("   - {0} Account: {1} [{2}]" -f $acc.Scope, $acc.Name, $acc.Status) -ForegroundColor Yellow
            }
        }
    }

    return $result
}