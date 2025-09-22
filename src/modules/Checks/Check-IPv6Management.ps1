function Check-IPv6Management {

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
        ID             = 18
        Action         = "IPv6 Security Status"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        ActiveIPv6     = @()
        Recommendation = "Disable IPv6 (DisabledComponents=0xFF) or harden it with IPsec, RA Guard, DHCPv6 Guard."
    }

    try {
        $ipv6Enabled = $false
        $ipv6FullyDisabled = $false
        $ipv6PartialConfig = $false
        $isDomainController = $false

        try {
            $domainRole = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole
            if ($domainRole -eq 4 -or $domainRole -eq 5) {
                $isDomainController = $true
            }
        }
        catch { }

        $ipv6Interfaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
            Get-NetIPAddress -InterfaceIndex $_.IfIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue
        }

        if ($ipv6Interfaces) {
            $ipv6Enabled = $true
            $result.ActiveIPv6 = $ipv6Interfaces | Select-Object InterfaceAlias,IPAddress,PrefixLength
        }

        $ipv6Path = "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters"
        $ipv6Reg = Get-ItemProperty -Path $ipv6Path -Name "DisabledComponents" -ErrorAction SilentlyContinue

        if ($ipv6Reg) {
            switch ($ipv6Reg.DisabledComponents) {
                0xFF { $ipv6FullyDisabled = $true }
                {$_ -ne 0} { $ipv6PartialConfig = $true }
            }
        }

        $ipv6Service = Get-Service -Name "TCPIP6" -ErrorAction SilentlyContinue
        $ipv6ServiceRunning = $ipv6Service -and $ipv6Service.Status -eq "Running"

        if ($ipv6FullyDisabled) {
            $result.Status = "OK"
            $result.Action = "IPv6 Fully Disabled"
            $result.DetectedValue = "IPv6 is fully disabled (DisabledComponents=0xFF)"
        }
        elseif ($ipv6PartialConfig) {
            $result.Status = "WARN"
            $result.Action = "IPv6 Partially Disabled"
            $result.DetectedValue = "IPv6 partially disabled (DisabledComponents=$($ipv6Reg.DisabledComponents))"
        }
        elseif ($ipv6Reg -and $ipv6Reg.DisabledComponents -eq 0) {
            # IPv6 explicitly enabled (DisabledComponents=0)
            $result.Status = "FAIL"
            $result.Action = "IPv6 Active (Unhardened)"
            $activeList = if ($result.ActiveIPv6.Count -gt 0) { ($result.ActiveIPv6 | ForEach-Object { $_.IPAddress }) -join ", " } else { "No active interfaces detected" }
            $dcNote = if ($isDomainController) { " (DC: consider hardening with RA/DHCPv6 Guard or disable if not required)" } else { " (consider disabling if not required or applying RA/DHCPv6 Guard)" }
            $result.DetectedValue = "IPv6 enabled but not hardened: $activeList$dcNote"
        }
        elseif (-not $ipv6Reg) {
            # No DisabledComponents key = IPv6 is enabled by default
            $result.Status = "FAIL"
            $result.Action = "IPv6 Active (Unhardened)"
            $activeList = if ($result.ActiveIPv6.Count -gt 0) { ($result.ActiveIPv6 | ForEach-Object { $_.IPAddress }) -join ", " } else { "No active interfaces detected" }
            $dcNote = if ($isDomainController) { " (DC: consider hardening with RA/DHCPv6 Guard or disable if not required)" } else { " (consider disabling if not required or applying RA/DHCPv6 Guard)" }
            $result.DetectedValue = "IPv6 enabled by default (DisabledComponents not set): $activeList$dcNote"
        }
        else {
            # Fallback case
            $result.Status = "WARN"
            $result.Action = "IPv6 Status Unknown"
            $result.DetectedValue = "Unable to determine IPv6 status"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "IPv6 Check Error"
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

        if ($result.ActiveIPv6.Count -gt 0) {
            foreach ($ip in $result.ActiveIPv6) {
                Write-Host ("   - {0}: {1}/{2}" -f $ip.InterfaceAlias, $ip.IPAddress, $ip.PrefixLength) -ForegroundColor Yellow
            }
        }
    }

    return $result
}
