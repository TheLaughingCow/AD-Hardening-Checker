function Check-PreWin2000CompatibleAccess {

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
        ID            = 17
        Action        = "Pre-Windows 2000 Compatible Access Group Status"
        Status        = "UNKNOWN"
        DetectedValue = $null
        Members       = @()
        Recommendation = "Ensure the 'Pre-Windows 2000 Compatible Access' group is empty to avoid excessive permissions inheritance."
    }

    try {
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.Action = "Pre-Windows 2000 Check Skipped"
            $result.DetectedValue = "Active Directory module not available"
            return $result
        }

        # Try both English and French group names
        $groupNames = @(
            "Pre-Windows 2000 Compatible Access",
            "Accès compatible pré-Windows 2000"
        )
        
        $preWin2000Group = $null
        $foundGroupName = $null
        
        foreach ($groupName in $groupNames) {
            try {
                $preWin2000Group = Get-ADGroupMember -Identity $groupName -ErrorAction Stop
                $foundGroupName = $groupName
                break
            }
            catch {
                # Continue to next group name
            }
        }

        if (-not $preWin2000Group -or $preWin2000Group.Count -eq 0) {
            $result.Status = "OK"
            $result.Action = "Pre-Windows 2000 Group Secured"
            $result.DetectedValue = "Group is empty"
        } else {
            $members = $preWin2000Group | Select-Object -ExpandProperty SamAccountName
            $result.Status = "FAIL"
            $result.Action = "Pre-Windows 2000 Group Populated"
            $result.DetectedValue = "Group '$foundGroupName' contains $($members.Count) members (high privilege risk)"
            $result.Members = $members
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "Pre-Windows 2000 Check Error"
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

        if ($result.Members.Count -gt 0) {
            foreach ($member in $result.Members) {
                Write-Host ("   - Member: {0}" -f $member) -ForegroundColor Yellow
            }
        }
    }

    return $result
}
