# ==============================

# TEMPLATE-Test.ps1

# Template to create a new check function

# ==============================



function Check-<Name> {

    [CmdletBinding()]

    param(

        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"

    )



    # Load configuration

    if (Test-Path $SettingsPath) {

        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json

    } else {

        Write-Verbose "settings.json not found, using default values"

        $settings = @{ }

    }



    # Default result object

    $result = [PSCustomObject]@{

        ID             = <ID_NUMBER>                    # Replace with ID number (1-27)

        Action         = "<Action Name>"                # Replace with action name

        Status         = "UNKNOWN"                      # Will be updated based on result

        DetectedValue  = $null                          # Value detected by the test

        Recommendation = "<Recommendation Text>"        # Replace with recommendation

    }



    try {

        # ==============================

        # TEST LOGIC HERE

        # ==============================

        

        # Registry check example:

        # $regPath = "HKLM:\Path\To\Registry\Key"

        # $regValue = Get-ItemProperty -Path $regPath -Name "ValueName" -ErrorAction SilentlyContinue

        # if ($regValue -and $regValue.ValueName -eq 0) {

        #     $result.Status = "OK"

        #     $result.DetectedValue = "Correctly configured"

        # } else {

        #     $result.Status = "FAIL"

        #     $result.DetectedValue = "Not configured or incorrect value"

        # }

        

        # Service check example:

        # $service = Get-Service -Name "ServiceName" -ErrorAction SilentlyContinue

        # if ($service -and $service.Status -eq "Stopped") {

        #     $result.Status = "OK"

        #     $result.DetectedValue = "Service stopped"

        # } else {

        #     $result.Status = "FAIL"

        #     $result.DetectedValue = "Service running or not found"

        # }

        

        # Active Directory check example:

        # if (Get-Module -Name ActiveDirectory -ListAvailable) {

        #     $adObject = Get-ADObject -Filter "Name -eq 'TestObject'" -ErrorAction SilentlyContinue

        #     if ($adObject) {

        #         $result.Status = "OK"

        #         $result.DetectedValue = "AD object found"

        #     } else {

        #         $result.Status = "FAIL"

        #         $result.DetectedValue = "AD object not found"

        #     }

        # } else {

        #     $result.Status = "WARN"

        #     $result.DetectedValue = "Active Directory module not available"

        # }

        

        # ==============================

        # END OF TEST LOGIC

        # ==============================

        

        # If no status was set, set default

        if ($result.Status -eq "UNKNOWN") {

            $result.Status = "WARN"

            $result.DetectedValue = "Test not implemented"

            $result.Recommendation = "Implement test logic"

        }

    }

    catch {

        # In case of error, set as WARN with error message

        $result.Status = "WARN"

        $result.DetectedValue = "Error: $($_.Exception.Message)"

        $result.Recommendation = "Review configuration and permissions"

    }



    # Display status if configured

    if ($settings.ShowRecommendationsInConsole -eq $true) {

        $color = switch ($result.Status) {

            "OK"   { $settings.Color_OK   }

            "FAIL" { $settings.Color_FAIL }

            "WARN" { $settings.Color_WARN }

            default { "White" }

        }

        Write-Host ("[ID {0}] {1} -> {2} (Detected: {3})" -f `

            $result.ID, $result.Action, $result.Status, $result.DetectedValue) -ForegroundColor $color

    }



    return $result

}



# ==============================

# USAGE INSTRUCTIONS

# ==============================

# 1. Copy this file to src/modules/Checks/Check-<Name>.ps1

# 2. Replace <Name> with your check name (ex: Check-SMBv2)

# 3. Replace <ID_NUMBER> with ID number (1-27)

# 4. Replace <Action Name> with action name

# 5. Replace <Recommendation Text> with recommendation

# 6. Implement test logic in the try block

# 7. Test the function with OK/FAIL/WARN cases

# ==============================



