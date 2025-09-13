function Test-NTLMRestriction {
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
        ID             = 19
        Action         = "NTLM Restricted and Audited"
        Status         = "UNKNOWN"
        DetectedValue  = $null
        Recommendation = "Restreindre et auditer NTLM pour préparer la migration vers NTLMv2 only."
    }

    try {
        # Vérifier la configuration NTLM
        $ntlmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $ntlmAudit = Get-ItemProperty -Path $ntlmPath -Name "AuditNTLMInDomain" -ErrorAction SilentlyContinue
        $ntlmRestriction = Get-ItemProperty -Path $ntlmPath -Name "RestrictNTLMInDomain" -ErrorAction SilentlyContinue
        
        # Vérifier la configuration de sécurité NTLM
        $ntlmSecurityPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        $ntlmSecurity = Get-ItemProperty -Path $ntlmSecurityPath -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
        
        $restrictions = @()
        
        # Vérifier l'audit NTLM
        if ($ntlmAudit -and $ntlmAudit.AuditNTLMInDomain -eq 1) {
            $restrictions += "Audit NTLM activé"
        }
        
        # Vérifier la restriction NTLM
        if ($ntlmRestriction -and $ntlmRestriction.RestrictNTLMInDomain -eq 1) {
            $restrictions += "Restriction NTLM activée"
        }
        
        # Vérifier la restriction d'envoi NTLM
        if ($ntlmSecurity -and $ntlmSecurity.RestrictSendingNTLMTraffic -eq 1) {
            $restrictions += "Restriction envoi NTLM activée"
        }
        
        if ($restrictions.Count -ge 2) {
            $result.Status = "OK"
            $result.DetectedValue = "NTLM restreint et audité: $($restrictions -join ', ')"
        } elseif ($restrictions.Count -eq 1) {
            $result.Status = "WARN"
            $result.DetectedValue = "Restriction NTLM partielle: $($restrictions -join ', ')"
        } else {
            $result.Status = "FAIL"
            $result.DetectedValue = "NTLM non restreint ni audité"
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

