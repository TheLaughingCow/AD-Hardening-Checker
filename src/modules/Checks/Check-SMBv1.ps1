function Check-SMBv1 {

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
        ID             = 8
        Action         = "SMBv1 Status"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Disable SMBv1 (obsolete and insecure, vulnerable to EternalBlue)."
    }

    try {
        $smbv1Detected = $false
        $smbv1Enabled  = $false
        $detectionDetails = @()

        try {
            $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            if ($smbConfig) {
                $smbv1Detected = $true
                $smbv1Enabled  = $smbConfig.EnableSMB1Protocol -eq $true
                $detectionDetails += "Get-SmbServerConfiguration: EnableSMB1Protocol=$($smbConfig.EnableSMB1Protocol)"
            }
        } catch { }

        if (-not $smbv1Detected) {
            try {
                $smbv1Feature = Get-WindowsFeature -Name "FS-SMB1" -ErrorAction SilentlyContinue
                if ($smbv1Feature) {
                    $smbv1Detected = $true
                    $smbv1Enabled  = $smbv1Feature.InstallState -eq "Installed"
                    $detectionDetails += "Get-WindowsFeature: SMB1=$($smbv1Feature.InstallState)"
                }
            } catch { }
        }

        if (-not $smbv1Detected) {
            try {
                $smbv1Client = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -ErrorAction SilentlyContinue
                $smbv1Server = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -ErrorAction SilentlyContinue
                if ($smbv1Client -or $smbv1Server) {
                    $smbv1Detected = $true
                    $clientEnabled = $smbv1Client -and $smbv1Client.State -eq "Enabled"
                    $serverEnabled = $smbv1Server -and $smbv1Server.State -eq "Enabled"
                    $smbv1Enabled  = $clientEnabled -or $serverEnabled
                    $detectionDetails += "OptionalFeature: Client=$($smbv1Client.State), Server=$($smbv1Server.State)"
                }
            } catch { }
        }

        if (-not $smbv1Detected) {
            try {
                $smb1RegPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
                $smb1Reg = Get-ItemProperty -Path $smb1RegPath -Name "SMB1" -ErrorAction SilentlyContinue
                if ($smb1Reg) {
                    $smbv1Detected = $true
                    $smbv1Enabled  = $smb1Reg.SMB1 -eq 1
                    $detectionDetails += "Registry: SMB1=$($smb1Reg.SMB1)"
                }
            } catch { }
        }

        if (-not $smbv1Detected) {
            $result.Status = "WARN"
            $result.Action = "SMBv1 Status Unknown"
            $result.DetectedValue = "Unable to determine SMBv1 status (no detection method succeeded)"
        }
        elseif ($smbv1Enabled) {
            $result.Status = "FAIL"
            $result.Action = "SMBv1 Enabled"
            $result.DetectedValue = "SMBv1 is ACTIVE - High risk (EternalBlue). Details: $($detectionDetails -join '; ')"
        }
        else {
            $result.Status = "OK"
            $result.Action = "SMBv1 Disabled"
            $result.DetectedValue = "SMBv1 is DISABLED - Secure. Details: $($detectionDetails -join '; ')"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "SMBv1 Check Error"
        $result.DetectedValue = "Error while checking SMBv1: $($_.Exception.Message)"
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
    }

    return $result
}
