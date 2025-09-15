function Check-PrintSpooler {

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
        ID            = 7
        Action        = "Print Spooler Service Status"
        Status        = "UNKNOWN"
        DetectedValue = $null
        Recommendation = "Disable the Print Spooler Service on Domain Controllers and servers that do not require printing to mitigate PrintNightmare (CVE-2021-34527)."
    }

    try {
        $domainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
        $isDC = $domainRole -in @(4, 5)  # 4 = BDC, 5 = PDC

        $spoolerService = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue

        if (-not $spoolerService) {
            $result.Status = "OK"
            $result.Action = "Print Spooler Not Installed"
            $result.DetectedValue = "Service not present on this system"
        }
        elseif ($spoolerService.Status -eq "Stopped") {
            $result.Status = "OK"
            $result.Action = "Print Spooler Disabled"
            $result.DetectedValue = "Print Spooler Service is stopped"
        }
        elseif ($isDC -and $spoolerService.Status -eq "Running") {
            $result.Status = "FAIL"
            $result.Action = "Print Spooler Running on DC"
            $result.DetectedValue = "Print Spooler is active on a Domain Controller (high risk: CVE-2021-34527)"
        }
        elseif (-not $isDC -and $spoolerService.Status -eq "Running") {
            $result.Status = "WARN"
            $result.Action = "Print Spooler Running"
            $result.DetectedValue = "Print Spooler running on a member server - review if necessary"
        }
        else {
            $result.Status = "WARN"
            $result.Action = "Print Spooler Unknown State"
            $result.DetectedValue = "Unable to determine exact status"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "Print Spooler Check Error"
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
