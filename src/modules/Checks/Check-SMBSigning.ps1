function Check-SMBSigning {

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
        ID             = 5
        Action         = "SMB Signing Enabled"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Enable and enforce SMB signing (RequireSecuritySignature=1, EnableSecuritySignature=1) to prevent MITM attacks."
    }

    try {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if (-not $smbConfig) {
            $result.Status = "WARN"
            $result.DetectedValue = "Unable to access SMB server configuration"
            return $result
        }

        $require = $smbConfig.RequireSecuritySignature
        $enable  = $smbConfig.EnableSecuritySignature

        $details = @()
        if ($enable) { $details += "EnableSecuritySignature=1" } else { $details += "EnableSecuritySignature=0" }
        if ($require) { $details += "RequireSecuritySignature=1" } else { $details += "RequireSecuritySignature=0" }

        if ($require -and $enable) {
            $result.Status = "OK"
            $result.DetectedValue = "SMB signing enabled and enforced ($($details -join ', '))"
        } elseif ($enable -and -not $require) {
            $result.Status = "WARN"
            $result.DetectedValue = "SMB signing supported but not enforced ($($details -join ', '))"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "SMB signing disabled ($($details -join ', '))"
        }
    }
    catch {
        $result.Status = "WARN"
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
