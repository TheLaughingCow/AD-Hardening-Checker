function Check-MachineAccountQuota {

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
        ID             = 4
        Action         = "MachineAccountQuota Status"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Set ms-DS-MachineAccountQuota to 0 to prevent standard Users from creating machine accounts (default = 10)."
    }

    try {
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            $result.Status = "WARN"
            $result.Action = "MachineAccountQuota Check Skipped"
            $result.DetectedValue = "Active Directory module not available"
            return $result
        }

        $domain = Get-ADDomain -ErrorAction SilentlyContinue
        if (-not $domain) {
            $result.Status = "WARN"
            $result.Action = "MachineAccountQuota Check Error"
            $result.DetectedValue = "Cannot access Active Directory domain"
            return $result
        }

        $domainObject = Get-ADObject -Identity $domain.DistinguishedName -Properties ms-DS-MachineAccountQuota -ErrorAction SilentlyContinue
        $quota = if ($domainObject -and $domainObject.'ms-DS-MachineAccountQuota' -ne $null) {
            [int]$domainObject.'ms-DS-MachineAccountQuota'
        } else {
            [int]$domain.MachineAccountQuota
        }

        if ($quota -eq 0) {
            $result.Status = "OK"
            $result.Action = "MachineAccountQuota Secured"
            $result.DetectedValue = "MachineAccountQuota set to 0 (standard Users cannot create machine accounts)"
        }
        elseif ($quota -le 10) {
            $result.Status = "WARN"
            $result.Action = "MachineAccountQuota Default"
            $result.DetectedValue = "MachineAccountQuota = $quota (default allows up to $quota computer accounts per user)"
        }
        else {
            $result.Status = "FAIL"
            $result.Action = "MachineAccountQuota Too Permissive"
            $result.DetectedValue = "MachineAccountQuota = $quota (high risk, should be 0)"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "MachineAccountQuota Check Error"
        $result.DetectedValue = "Error reading MachineAccountQuota: $($_.Exception.Message)"
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
