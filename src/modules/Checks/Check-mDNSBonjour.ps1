function Check-mDNSBonjour {

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
        ID             = 3
        Action         = "mDNS / Bonjour Status"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Uninstall Bonjour Service (Apple), disable mDNSResponder, and block UDP/5353 if not needed."
    }

    try {
        $bonjourService = Get-Service -Name "Bonjour Service" -ErrorAction SilentlyContinue
        $bonjourInstalled = $null -ne $bonjourService

        $mdnsProcesses = Get-Process -Name "*mdns*" -ErrorAction SilentlyContinue

        $port5353Processes = @()
        try {
            $udpEndpoints = Get-NetUDPEndpoint -LocalPort 5353 -ErrorAction SilentlyContinue
            foreach ($endpoint in $udpEndpoints) {
                if ($endpoint.OwningProcess) {
                    $process = Get-Process -Id $endpoint.OwningProcess -ErrorAction SilentlyContinue
                    if ($process) {
                        $port5353Processes += $process.Name
                    }
                }
            }
        } catch {
        }

        $allProcesses = @()
        if ($mdnsProcesses) { $allProcesses += $mdnsProcesses.Name }
        if ($port5353Processes) { $allProcesses += $port5353Processes }
        $allProcesses = $allProcesses | Sort-Object -Unique

        if (-not $bonjourInstalled -and $allProcesses.Count -eq 0) {
            $result.Status = "OK"
            $result.Action = "mDNS / Bonjour Disabled"
            $result.DetectedValue = "No Bonjour Service or mDNS processes detected (UDP/5353 quiet)"
        }
        elseif ($bonjourService -and $bonjourService.Status -eq "Running") {
            $result.Status = "FAIL"
            $result.Action = "mDNS / Bonjour Active"
            $result.DetectedValue = "Bonjour Service running (mdnsresponder.exe active)"
        }
        elseif ($bonjourInstalled) {
            $result.Status = "WARN"
            $result.Action = "mDNS / Bonjour Installed"
            $result.DetectedValue = "Bonjour Service installed but currently stopped"
        }
        elseif ($allProcesses.Count -gt 0) {
            $result.Status = "FAIL"
            $result.Action = "mDNS Processes Detected"
            $result.DetectedValue = "Processes listening on UDP/5353: $($allProcesses -join ', ')"
        }
        else {
            $result.Status = "WARN"
            $result.Action = "mDNS / Bonjour Verification Inconclusive"
            $result.DetectedValue = "Unable to fully verify mDNS / Bonjour status"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "mDNS / Bonjour Check Error"
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
    }

    return $result
}
