function Check-LSASSProtectedMode {

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
        ID             = 12
        Action         = "LSASS Protection Status"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Enable LSASS protection (RunAsPPL=1 and RunAsPPLBoot=1) to block credential dumping tools like Mimikatz."
    }

    try {
        $details = @()
        $lsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
        $runAsPPL = Get-ItemProperty -Path $lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue
        $runAsPPLBoot = Get-ItemProperty -Path $lsaPath -Name "RunAsPPLBoot" -ErrorAction SilentlyContinue

        if ($null -eq $runAsPPL) {
            $result.Status = "FAIL"
            $result.Action = "LSASS Unprotected"
            $result.DetectedValue = "RunAsPPL not configured (LSASS unprotected)"
            $details += "RunAsPPL key missing (default: 0)"
        }
        elseif ($runAsPPL.RunAsPPL -eq 1) {
            $result.Status = "OK"
            $result.Action = "LSASS Protected"
            $result.DetectedValue = "LSASS is protected (RunAsPPL=1)"
            $details += "RunAsPPL=1 (enabled)"
        }
        else {
            $result.Status = "FAIL"
            $result.Action = "LSASS Unprotected"
            $result.DetectedValue = "LSASS protection explicitly disabled (RunAsPPL=$($runAsPPL.RunAsPPL))"
            $details += "RunAsPPL=$($runAsPPL.RunAsPPL)"
        }

        if ($runAsPPLBoot) {
            if ($runAsPPLBoot.RunAsPPLBoot -eq 1) {
                $details += "RunAsPPLBoot=1 (secure boot integration enabled)"
            } else {
                $details += "RunAsPPLBoot=$($runAsPPLBoot.RunAsPPLBoot) (not enforced)"
            }
        } else {
            $details += "RunAsPPLBoot key missing"
        }

        if ($details.Count -gt 0) {
            $result.DetectedValue += " | Details: $($details -join '; ')"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "LSASS Protection Check Error"
        $result.DetectedValue = "Error reading registry keys: $($_.Exception.Message)"
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
