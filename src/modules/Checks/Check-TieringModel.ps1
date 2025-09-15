function Check-TieringModel {
    [CmdletBinding()]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        Write-Verbose "settings.json not found, using default values."
        $settings = @{ }
    }

    $result = [PSCustomObject]@{
        ID             = 24
        Action         = "Tiering Admin Model & PAW Implementation"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Implement a Tiering Admin Model (Tier 0/1/2) and Privileged Access Workstations (PAW) to limit credential exposure and attack paths."
    }

    try {
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.Action = "Tiering Admin Model Check Skipped"
            $result.DetectedValue = "Active Directory module not available"
            return $result
        }

        $tieredModelIndicators = @()
        $missingTierGroups = @()
        $tierGroups = @("Tier 0 Admins", "Tier 1 Admins", "Tier 2 Admins", "PAW Users")

        foreach ($groupName in $tierGroups) {
            try {
                $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
                if ($group) {
                    $tieredModelIndicators += "Group exists: $groupName"
                } else {
                    $missingTierGroups += $groupName
                }
            } catch { }
        }

        try {
            # Try both English and French group names
            $groupNames = @(
                "Domain Admins",
                "Administrators du domaine"
            )
            
            $domainAdmins = $null
            $foundGroupName = $null
            
            foreach ($groupName in $groupNames) {
                try {
                    $domainAdmins = Get-ADGroupMember -Identity $groupName -ErrorAction Stop
                    $foundGroupName = $groupName
                    break
                }
                catch {
                    # Continue to next group name
                }
            }
            if ($domainAdmins) {
                if ($domainAdmins.Count -le 5) {
                    $tieredModelIndicators += "Domain Admins limited ($($domainAdmins.Count) members)"
                } else {
                    $tieredModelIndicators += "Domain Admins numerous ($($domainAdmins.Count) members)"
                }
            }
        } catch { }

        try {
            # Try both English and French group names
            $groupNames = @(
                "Enterprise Admins",
                "Administrators de l'entreprise"
            )
            
            $enterpriseAdmins = $null
            $foundGroupName = $null
            
            foreach ($groupName in $groupNames) {
                try {
                    $enterpriseAdmins = Get-ADGroupMember -Identity $groupName -ErrorAction Stop
                    $foundGroupName = $groupName
                    break
                }
                catch {
                    # Continue to next group name
                }
            }
            if ($enterpriseAdmins) {
                if ($enterpriseAdmins.Count -le 3) {
                    $tieredModelIndicators += "Enterprise Admins limited ($($enterpriseAdmins.Count) members)"
                } else {
                    $tieredModelIndicators += "Enterprise Admins numerous ($($enterpriseAdmins.Count) members)"
                }
            }
        } catch { }

        try {
            $pawComputers = Get-ADComputer -Filter "Name -like '*PAW*'" -ErrorAction SilentlyContinue
            if ($pawComputers -and $pawComputers.Count -gt 0) {
                $tieredModelIndicators += "PAW computers detected ($($pawComputers.Count))"
            }
        } catch { }

        if ($tieredModelIndicators.Count -ge 3 -and $missingTierGroups.Count -eq 0) {
            $result.Status = "OK"
            $result.Action = "Tiering Admin Model Implemented"
            $result.DetectedValue = "Full implementation detected: $($tieredModelIndicators -join '; ')"
        }
        elseif ($tieredModelIndicators.Count -gt 0) {
            $result.Status = "WARN"
            $result.Action = "Tiering Admin Model Partial"
            $result.DetectedValue = "Partial implementation: $($tieredModelIndicators -join '; '); Missing groups: $($missingTierGroups -join ', ')"
        }
        else {
            $result.Status = "FAIL"
            $result.Action = "Tiering Admin Model Missing"
            $result.DetectedValue = "No Tiering Admin Model detected. Recommended groups: $($tierGroups -join ', ')"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "Tiering Admin Model Check Error"
        $result.DetectedValue = "Error during check: $($_.Exception.Message)"
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
    }

    return $result
}