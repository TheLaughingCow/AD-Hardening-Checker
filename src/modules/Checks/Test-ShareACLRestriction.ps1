function Test-ShareACLRestriction {
    [CmdletBinding()]
    param(
        [string]$SettingsPath = "$PSScriptRoot/../../../config/settings.json"
    )

    # Charger la configuration
    if (Test-Path $SettingsPath) {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
    } else {
        Write-Verbose "Fichier settings.json introuvable, utilisation des valeurs par défaut."
        $settings = @{ }
    }

    $result = [PSCustomObject]@{
        ID             = 20
        Action         = "Share ACLs Restricted (Least Privilege)"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Restreindre les ACLs des partages selon le principe du moindre privilège."
    }

    try {
        # Obtenir tous les partages
        $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {$_.ShareType -eq "FileSystemDirectory"}
        
        $insecureShares = @()
        $totalShares = $shares.Count
        
        foreach ($share in $shares) {
            try {
                # Vérifier les permissions du partage
                $shareAccess = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                
                # Vérifier si le partage a des permissions trop permissives
                $hasEveryone = $shareAccess | Where-Object {$_.AccountName -eq "Everyone" -and $_.AccessRight -eq "Full"}
                $hasAnonymous = $shareAccess | Where-Object {$_.AccountName -eq "ANONYMOUS LOGON"}
                $hasDomainUsers = $shareAccess | Where-Object {$_.AccountName -eq "Domain Users" -and $_.AccessRight -eq "Full"}
                
                if ($hasEveryone -or $hasAnonymous -or $hasDomainUsers) {
                    $insecureShares += $share.Name
                }
            }
            catch {
                # Ignore les erreurs d'accès aux permissions
            }
        }
        
        if ($totalShares -eq 0) {
            $result.Status = "OK"
            $result.DetectedValue = "Aucun partage de fichiers détecté"
        } elseif ($insecureShares.Count -eq 0) {
            $result.Status = "OK"
            $result.DetectedValue = "Tous les partages ont des ACLs restrictives"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "$($insecureShares.Count)/$totalShares partages avec ACLs permissives: $($insecureShares -join ', ')"
        }
    }
    catch {
        $result.Status = "WARN"
        $result.DetectedValue = "Error: $($_.Exception.Message)"
    }

    if ($settings.ShowRecommendationsInConsole -eq $true) {
        $color = switch ($result.Status) {
            "OK"   { $settings.Color_OK   }
            "FAIL" { $settings.Color_FAIL }
            "WARN" { $settings.Color_WARN }
            default { "White" }
        }
        Write-Host ("[ID {0}] {1} → {2} (Detected: {3})" -f `
            $result.ID, $result.Action, $result.Status, $result.DetectedValue) -ForegroundColor $color
    }

    return $result
}

