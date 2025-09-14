function Check-CoercionPatches {

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
        ID             = 23
        Action         = "Coercion Patches Status"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Apply coercion patches (PetitPotam, relay) or recent cumulative updates to mitigate NTLM relay attacks."
    }

    try {
        $patches = @()
        $isPatched = $false

        $petitPotamPatch = Get-HotFix -Id "KB5005413" -ErrorAction SilentlyContinue
        if ($petitPotamPatch) {
            $patches += "PetitPotam (KB5005413)"
            $isPatched = $true
        }

        $coercionPatches = Get-HotFix | Where-Object {
            $_.Description -like "*coercion*" -or 
            $_.Description -like "*relay*" -or 
            $_.Description -like "*PetitPotam*"
        }
        if ($coercionPatches) {
            foreach ($patch in $coercionPatches) {
                $patches += "$($patch.HotFixID) - $($patch.Description)"
            }
            $isPatched = $true
        }

        $recentSecurityUpdates = Get-HotFix | Where-Object {
            $_.InstalledOn -gt (Get-Date).AddMonths(-6) -and 
            ($_.Description -like "*Security*" -or $_.Description -like "*Cumulative*")
        } | Sort-Object InstalledOn -Descending | Select-Object -First 5

        if ($recentSecurityUpdates) {
            $patches += "Recent security updates (last 6 months): $($recentSecurityUpdates.Count) updates"
            $isPatched = $true
        } else {
            $lastUpdate = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
            if ($lastUpdate) {
                $daysSinceLastUpdate = (Get-Date) - $lastUpdate.InstalledOn
                if ($daysSinceLastUpdate.Days -gt 180) {
                    $patches += "CRITICAL: No updates in $($daysSinceLastUpdate.Days) days (last: $($lastUpdate.InstalledOn.ToString('yyyy-MM-dd')))"
                    $isPatched = $false
                }
            }
        }

        $osVersion = [System.Environment]::OSVersion.Version
        $buildNumber = $osVersion.Build
        if ($buildNumber -ge 19044) {
            $patches += "Recent build ($buildNumber) - coercion patches included"
            $isPatched = $true
        }

        if ($isPatched) {
            $result.Status = "OK"
            $result.Action = "Coercion Patches Applied"
            $result.DetectedValue = "Coercion protection detected: $($patches -join ', ')"
        } else {
            $result.Status = "FAIL"
            $result.Action = "Coercion Patches Missing (PetitPotam/Relay)"
            $result.DetectedValue = "No coercion mitigations detected. System likely vulnerable to PetitPotam (EFSRPC), MS-RPRN, MS-FSRVP and WebDav NTLM relay. Install KB5005413 or a recent cumulative update."
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "Coercion Patches Check Error"
        $errorMessage = $_.Exception.Message
        if ($errorMessage -like "*n'est pas reconnu*" -or $errorMessage -like "*not recognized*") {
            $errorMessage = "Command not recognized or not available"
        }
        $result.DetectedValue = "Error: $errorMessage"
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
    }

    return $result
}
