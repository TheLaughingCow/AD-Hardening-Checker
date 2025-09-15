function Check-NBTNS {

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
        ID             = 2
        Action         = "NBT-NS Status"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        InterfacesAtRisk = @()
        Recommendation = "Disable NetBIOS over TCP/IP (NetbiosOptions=2) on all Network interfaces."
    }

    try {
        $interfaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $nbtEnabled = @()

        foreach ($interface in $interfaces) {
            $guid = $interface.InterfaceGuid
            $regPath = "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$guid"
            $nbtConfig = Get-ItemProperty -Path $regPath -Name "NetbiosOptions" -ErrorAction SilentlyContinue

            if ($nbtConfig) {
                switch ($nbtConfig.NetbiosOptions) {
                    0 { 
                        $nbtEnabled += "$($interface.Name) (Default: DHCP controlled)" 
                        $result.InterfacesAtRisk += [PSCustomObject]@{ Interface=$interface.Name; Mode="DHCP Controlled" }
                    }
                    1 { 
                        $nbtEnabled += "$($interface.Name) (Enabled)" 
                        $result.InterfacesAtRisk += [PSCustomObject]@{ Interface=$interface.Name; Mode="Enabled" }
                    }
                    2 { }
                    default { 
                        $nbtEnabled += "$($interface.Name) (Unknown: $($nbtConfig.NetbiosOptions))" 
                        $result.InterfacesAtRisk += [PSCustomObject]@{ Interface=$interface.Name; Mode="Unknown ($($nbtConfig.NetbiosOptions))" }
                    }
                }
            } else {
                $nbtEnabled += "$($interface.Name) (No NetbiosOptions key)"
                $result.InterfacesAtRisk += [PSCustomObject]@{ Interface=$interface.Name; Mode="Registry Missing" }
            }
        }

        if ($nbtEnabled.Count -eq 0) {
            $result.Status = "OK"
            $result.Action = "NBT-NS Disabled"
            $result.DetectedValue = "NetBIOS disabled (NetbiosOptions=2) on all active interfaces"
        }
        else {
            $result.Status = "FAIL"
            $result.Action = "NBT-NS Active"
            $result.DetectedValue = "NetBIOS enabled or misconfigured on: $($nbtEnabled -join ', ')"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "NBT-NS Check Error"
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

        if ($result.InterfacesAtRisk.Count -gt 0) {
            foreach ($iface in $result.InterfacesAtRisk) {
                Write-Host ("   - {0} : {1}" -f $iface.Interface, $iface.Mode) -ForegroundColor Yellow
            }
        }
    }

    return $result
}
