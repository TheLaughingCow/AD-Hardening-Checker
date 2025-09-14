function Check-ShareACLRestriction {

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
        ID             = 20
        Action         = "Network Share ACL Review"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        InsecureShares = @()
        Recommendation = "Restrict share permissions to avoid Everyone / Everyone/Anonymous/Domain Users having Full Control or Change rights."
    }

    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.ShareType -eq "FileSystemDirectory" }
        $totalShares = $shares.Count
        $insecureShares = @()
        $detailedFindings = @()

        foreach ($share in $shares) {
            try {
                $shareAccess = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                if ($shareAccess) {
                    $badPerms = $shareAccess | Where-Object {
                        ($_.AccountName -match "Everyone / Everyone|Anonymous Logon / Connexion Anonymous|Domain Users") -and 
                        ($_.AccessRight -eq "Full" -or $_.AccessRight -eq "Change")
                    }

                    if ($badPerms) {
                        $insecureShares += $share.Name
                        $permSummary = $badPerms | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }
                        $detailedFindings += "$($share.Name) => $($permSummary -join ', ')"
                    }
                } else {
                    $detailedFindings += "$($share.Name) => Unable to read permissions"
                }
            } catch {
                $detailedFindings += "$($share.Name) => Error reading ACL"
            }
        }

        if ($totalShares -eq 0) {
            $result.Status = "OK"
            $result.Action = "No Network Shares Found"
            $result.DetectedValue = "No file shares were detected on this host"
        } elseif ($insecureShares.Count -eq 0) {
            $result.Status = "OK"
            $result.Action = "All Share ACLs Compliant"
            $result.DetectedValue = "All $totalShares shares use restrictive permissions (no Everyone / Everyone/Domain Users with Full or Change access)"
        } else {
            $result.Status = "FAIL"
            $result.Action = "Insecure Share Permissions Detected"
            $result.DetectedValue = "$($insecureShares.Count)/$totalShares shares have overly permissive ACLs"
            $result.InsecureShares = $detailedFindings
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "Share ACL Review Error"
        $result.DetectedValue = "Error while enumerating shares: $($_.Exception.Message)"
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

        if ($result.InsecureShares.Count -gt 0) {
            foreach ($finding in $result.InsecureShares) {
                Write-Host ("   - {0}" -f $finding) -ForegroundColor Yellow
            }
        }
    }

    return $result
}
