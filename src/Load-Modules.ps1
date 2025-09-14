$Root = $PSScriptRoot

$script:ModulesLoaded = $false

$script:LoadedFunctions = @{
    Checks = @()
    Remediations = @()
}

function Import-ADHCModules {
    [CmdletBinding()]
    param()

    if ($script:ModulesLoaded) {
        Write-Verbose "Modules already loaded. Returning available functions."
        return $script:LoadedFunctions
    }

    Write-Verbose "Loading AD Hardening Checker modules..."

    try {
        $utilsPath = Join-Path $Root "Utils.psm1"
        if (Test-Path $utilsPath) {
            try {
                Import-Module $utilsPath -Force -ErrorAction Stop
                Write-Verbose "Utils.psm1 module loaded"
            }
            catch {
                Write-Warning "Unable to load Utils.psm1: $($_.Exception.Message)"
            }
        } else {
            Write-Warning "Utils.psm1 file not found: $utilsPath"
        }

        $checksPath = Join-Path $Root "modules\Checks"
        if (Test-Path $checksPath) {
            $checkFiles = Get-ChildItem -Path $checksPath -Filter "Check-*.ps1" -File -ErrorAction SilentlyContinue
            foreach ($file in $checkFiles) {
                try {
                    $content = Get-Content $file.FullName -Raw -Encoding UTF8
                    Invoke-Expression $content
                    $functionName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                    $script:LoadedFunctions.Checks += $functionName
                    Write-Verbose "Test module loaded: $($file.Name)"
                }
                catch {
                    Write-Warning "Unable to load $($file.Name): $($_.Exception.Message)"
                }
            }
        } else {
            Write-Verbose "Checks folder not found: $checksPath"
        }

        $remediationsPath = Join-Path $Root "modules\Remediations"
        if (Test-Path $remediationsPath) {
            $remediationFiles = Get-ChildItem -Path $remediationsPath -Filter "Remediate-*.ps1" -File -ErrorAction SilentlyContinue
            foreach ($file in $remediationFiles) {
                try {
                    $content = Get-Content $file.FullName -Raw -Encoding UTF8
                    Invoke-Expression $content
                    $functionName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                    $script:LoadedFunctions.Remediations += $functionName
                    Write-Verbose "Remediation module loaded: $($file.Name)"
                }
                catch {
                    Write-Warning "Unable to load $($file.Name): $($_.Exception.Message)"
                }
            }
        } else {
            Write-Verbose "Remediations folder not found: $remediationsPath"
        }

        $script:ModulesLoaded = $true

        Write-Verbose "Module loading completed."
        Write-Verbose "Test functions loaded: $($script:LoadedFunctions.Checks.Count)"
        Write-Verbose "Remediation functions loaded: $($script:LoadedFunctions.Remediations.Count)"

        return $script:LoadedFunctions
    }
    catch {
        Write-Error "Error loading modules: $($_.Exception.Message)"
        return $null
    }
}

function Get-ADHCLoadedFunctions {
    [CmdletBinding()]
    param()

    return $script:LoadedFunctions
}

function Reset-ADHCModules {
    [CmdletBinding()]
    param()

    $script:ModulesLoaded = $false
    $script:LoadedFunctions = @{
        Checks = @()
        Remediations = @()
    }
    Write-Verbose "Module state reset"
}