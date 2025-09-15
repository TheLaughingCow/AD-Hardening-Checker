function Check-LLMNR {
    [CmdletBinding()]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        Write-Verbose "settings.json not found, using default values"
        $settings = @{ }
    }

    $result = [PSCustomObject]@{
        ID             = 1
        Action         = "LLMNR Configuration Status"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Disable LLMNR via GPO: Computer Configuration > Administrative Templates > Network > DNS Client > 'Turn Off Multicast Name Resolution' (EnableMulticast=0)."
    }

    try {
        $details = @()
        $regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
        $reg = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

        if ($null -eq $reg -or $null -eq $reg.EnableMulticast) {
            $result.Status = "FAIL"
            $result.Action = "LLMNR Enabled"
            $result.DetectedValue = "LLMNR is active (no registry key found, default = Enabled)"
            $details += "EnableMulticast not set (default: 1)"
        }
        elseif ($reg.EnableMulticast -eq 0) {
            $result.Status = "OK"
            $result.Action = "LLMNR Disabled"
            $result.DetectedValue = "LLMNR is disabled via policy (EnableMulticast=0)"
            $details += "EnableMulticast=0 (secured)"
        }
        elseif ($reg.EnableMulticast -eq 1) {
            $result.Status = "FAIL"
            $result.Action = "LLMNR Enabled"
            $result.DetectedValue = "LLMNR is explicitly enabled (EnableMulticast=1)"
            $details += "EnableMulticast=1"
        }
        else {
            $result.Status = "WARN"
            $result.Action = "LLMNR Status Unknown"
            $result.DetectedValue = "Unexpected EnableMulticast value: $($reg.EnableMulticast)"
            $details += "EnableMulticast=$($reg.EnableMulticast) (unexpected)"
        }

        if ($details.Count -gt 0) {
            $result.DetectedValue += " | Details: $($details -join '; ')"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "LLMNR Check Error"
        $result.DetectedValue = "Error reading registry: $($_.Exception.Message)"
    }

    return $result
}