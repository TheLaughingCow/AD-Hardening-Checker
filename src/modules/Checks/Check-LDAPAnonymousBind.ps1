function Check-LDAPAnonymousBind {

    [CmdletBinding()]
    param(
        [string]$SettingsPath = "$PSScriptRoot\..\..\..\config\settings.json"
    )

    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        $settings = @{ }
    }

    $result = [PSCustomObject]@{
        ID             = 14
        Action         = "LDAP Anonymous Bind Check"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Désactiver l'anonymous bind en laissant dSHeuristics non défini (ou 7e caractère ≠ '2'). Optionnel : supprimer toute ACE ANONYMOUS LOGON sur CN=Users. Le LDAP signing est vérifié par un contrôle séparé."
    }

    try {
        $anonymousEnabled   = $false
        $anonAcePresent     = $false
        $details = @()

        try {
            $root     = [ADSI]"LDAP://RootDSE"
            $configNC = $root.configurationNamingContext
            $dsObject = [ADSI]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$configNC"

            $dsHeuristics = $null
            try { $dsHeuristics = $dsObject.Get("dSHeuristics") } catch {}
            if ($dsHeuristics) {
                $s = [string]$dsHeuristics
                $details += "dSHeuristics=$s"
                if ($s.Length -ge 7 -and $s.Substring(6,1) -eq '2') { $anonymousEnabled = $true }
            } else {
                $details += "dSHeuristics=absent"
            }
        } catch {
            $details += "dSHeuristics read error: $($_.Exception.Message)"
        }

        try {
            $domainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
            $usersAdsi = [ADSI]("LDAP://CN=Users,$domainDN")
            $anonSid   = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-7'  # ANONYMOUS LOGON
            $acl       = $usersAdsi.PSBase.ObjectSecurity
            foreach ($rule in $acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
                if ($rule.IdentityReference -eq $anonSid) {
                    if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                        if ($rule.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericRead) -or
                            $rule.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::ListChildren) -or
                            $rule.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty)) {
                            $anonAcePresent = $true
                            break
                        }
                    }
                }
            }
            $details += "CN=Users:AnonymousReadACE=" + ($anonAcePresent)
        } catch {
            $details += "CN=Users ACL read error: $($_.Exception.Message)"
        }

        try {
            $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
            $lsi = (Get-ItemProperty -Path $regPath -Name LDAPServerIntegrity -ErrorAction SilentlyContinue).LDAPServerIntegrity
            $rsb = (Get-ItemProperty -Path $regPath -Name RequireSecureSimpleBind -ErrorAction SilentlyContinue).RequireSecureSimpleBind
            if ($null -ne $lsi) { $details += "LDAPServerIntegrity=$lsi" } else { $details += "LDAPServerIntegrity=unset" }
            if ($null -ne $rsb) { $details += "RequireSecureSimpleBind=$rsb" } else { $details += "RequireSecureSimpleBind=unset" }
        } catch {
            $details += "LDAPServerIntegrity read error"
        }

        if ($anonymousEnabled) {
            $result.Status = "FAIL"
            $result.Action = "LDAP Anonymous Bind Enabled"
            $result.DetectedValue = ($details -join '; ')
        }
        elseif ($anonAcePresent) {
            $result.Status = "WARN"
            $result.Action = "Anonymous ACE Present on CN=Users"
            $result.DetectedValue = ($details -join '; ')
            $result.Recommendation = "Supprimer l'ACE ANONYMOUS LOGON (droits de lecture) sur CN=Users. dSHeuristics doit rester absent (ou 7e caractère ≠ '2')."
        }
        else {
            $result.Status = "OK"
            $result.Action = "LDAP Anonymous Bind Disabled"
            $result.DetectedValue = ($details -join '; ')
        }
    }
    catch {
        $result.Status = "WARN"
        $result.Action = "LDAP Anonymous Bind Check Error"
        $result.DetectedValue = "Error: $($_.Exception.Message)"
    }

    if ($settings.ShowRecommendationsInConsole -eq $true) {
        $color = switch ($result.Status) {
            "OK"   { $settings.Color_OK }
            "FAIL" { $settings.Color_FAIL }
            "WARN" { $settings.Color_WARN }
            default { "White" }
        }
        Write-Host ("[ID {0}] {1} -> {2} (Detected: {3})" -f $result.ID, $result.Action, $result.Status, $result.DetectedValue) -ForegroundColor $color
    }

    return $result
}
