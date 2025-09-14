function Check-ProtectedUsersGroup {

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
        ID             = 11
        Action         = "Protected Users Group Membership"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        MissingAccounts = @()
        Recommendation = "Add sensitive accounts (Domain Admins, Enterprise Admins, Schema Admins) to the 'Protected Users' group to enforce stricter Kerberos/NTLM protections."
    }

    try {
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.Action = "Protected Users Group Check Skipped"
            $result.DetectedValue = "Active Directory module not available"
            return $result
        }

        # Try both English and French group names
        $groupNames = @(
            "Protected Users",
            "Users protégés"
        )
        
        $protectedUsers = $null
        $foundGroupName = $null
        
        foreach ($groupName in $groupNames) {
            try {
                $protectedUsers = Get-ADGroupMember -Identity $groupName -ErrorAction Stop
                $foundGroupName = $groupName
                break
            }
            catch {
                # Continue to next group name
            }
        }
        if (-not $protectedUsers) { $protectedUsers = @() }

        $sensitiveGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators / Administrators")
        $missingAccounts = @()
        $checkedAccounts = @()

        foreach ($groupName in $sensitiveGroups) {
            try {
                $groupMembers = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction SilentlyContinue
                foreach ($member in $groupMembers) {
                    if ($member.ObjectClass -eq "user") {
                        $checkedAccounts += $member.SamAccountName
                        $isProtected = $protectedUsers | Where-Object { $_.SID -eq $member.SID }
                        if (-not $isProtected) {
                            $missingAccounts += $member.SamAccountName
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Unable to enumerate group ${groupName}: $($_.Exception.Message)"
            }
        }

        if ($checkedAccounts.Count -eq 0) {
            $result.Status = "WARN"
            $result.Action = "No Sensitive Accounts Found"
            $result.DetectedValue = "No members found in Domain Admins/Enterprise Admins/Schema Admins to check"
        }
        elseif ($missingAccounts.Count -eq 0) {
            $result.Status = "OK"
            $result.Action = "Protected Users Group Compliant"
            $result.DetectedValue = "All $($checkedAccounts.Count) sensitive accounts are members of Protected Users group"
        }
        else {
            $result.Status = "FAIL"
            $result.Action = "Protected Users Group Incomplete"
            $result.DetectedValue = "$($missingAccounts.Count) sensitive accounts missing from Protected Users group"
            $result.MissingAccounts = $missingAccounts
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "Protected Users Group Check Error"
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

        if ($result.MissingAccounts.Count -gt 0) {
            foreach ($acc in $result.MissingAccounts) {
                Write-Host ("   - Missing: {0}" -f $acc) -ForegroundColor Yellow
            }
        }
    }

    return $result
}
