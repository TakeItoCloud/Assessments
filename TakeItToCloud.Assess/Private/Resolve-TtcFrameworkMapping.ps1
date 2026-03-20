function Resolve-TtcFrameworkMapping {
    <#
    .SYNOPSIS
        Resolves a framework mapping string to its full components.
    .DESCRIPTION
        Takes a compact framework mapping (e.g., "NIST-Protect") and returns
        the framework name, domain, and objective for reporting purposes.
    .PARAMETER Mapping
        The compact mapping string.
    .EXAMPLE
        Resolve-TtcFrameworkMapping -Mapping "NIST-Protect"
        # Returns: @{ Framework="NIST CSF"; Domain="Protect"; Objective="Implement safeguards..." }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Mapping
    )

    $frameworkLookup = @{
        # NIST CSF
        'NIST-Identify'  = @{ Framework = 'NIST CSF'; Domain = 'Identify';  Objective = 'Develop organizational understanding to manage cybersecurity risk' }
        'NIST-Protect'   = @{ Framework = 'NIST CSF'; Domain = 'Protect';   Objective = 'Implement safeguards to ensure delivery of critical services' }
        'NIST-Detect'    = @{ Framework = 'NIST CSF'; Domain = 'Detect';    Objective = 'Implement activities to identify cybersecurity events' }
        'NIST-Respond'   = @{ Framework = 'NIST CSF'; Domain = 'Respond';   Objective = 'Take action regarding a detected cybersecurity incident' }
        'NIST-Recover'   = @{ Framework = 'NIST CSF'; Domain = 'Recover';   Objective = 'Maintain plans for resilience and restore capabilities' }

        # CIS Controls
        'CIS-AccessControl'          = @{ Framework = 'CIS Controls'; Domain = 'Access Control';          Objective = 'Manage credentials and access rights for user and admin accounts' }
        'CIS-SecureConfig'           = @{ Framework = 'CIS Controls'; Domain = 'Secure Configuration';    Objective = 'Establish and maintain secure configurations for enterprise assets' }
        'CIS-ContinuousMonitoring'   = @{ Framework = 'CIS Controls'; Domain = 'Continuous Monitoring';   Objective = 'Continuously monitor to detect anomalies and security events' }
        'CIS-IncidentResponse'       = @{ Framework = 'CIS Controls'; Domain = 'Incident Response';       Objective = 'Establish an incident response program to address security incidents' }

        # ISO 27001
        'ISO27001-A.5'  = @{ Framework = 'ISO 27001'; Domain = 'A.5 Information Security Policies';           Objective = 'Management direction for information security' }
        'ISO27001-A.6'  = @{ Framework = 'ISO 27001'; Domain = 'A.6 Organization of Information Security';    Objective = 'Internal organization and mobile/teleworking' }
        'ISO27001-A.8'  = @{ Framework = 'ISO 27001'; Domain = 'A.8 Asset Management';                       Objective = 'Responsibility for and classification of assets' }
        'ISO27001-A.9'  = @{ Framework = 'ISO 27001'; Domain = 'A.9 Access Control';                         Objective = 'Business requirements and user access management' }
        'ISO27001-A.10' = @{ Framework = 'ISO 27001'; Domain = 'A.10 Cryptography';                          Objective = 'Cryptographic controls policy and key management' }
        'ISO27001-A.12' = @{ Framework = 'ISO 27001'; Domain = 'A.12 Operations Security';                   Objective = 'Operational procedures, protection from malware, logging' }
        'ISO27001-A.13' = @{ Framework = 'ISO 27001'; Domain = 'A.13 Communications Security';               Objective = 'Network security management and information transfer' }
        'ISO27001-A.14' = @{ Framework = 'ISO 27001'; Domain = 'A.14 System Acquisition & Development';      Objective = 'Security requirements and development processes' }
        'ISO27001-A.16' = @{ Framework = 'ISO 27001'; Domain = 'A.16 Incident Management';                   Objective = 'Management of information security incidents' }
        'ISO27001-A.17' = @{ Framework = 'ISO 27001'; Domain = 'A.17 Business Continuity';                   Objective = 'Information security continuity and redundancies' }
        'ISO27001-A.18' = @{ Framework = 'ISO 27001'; Domain = 'A.18 Compliance';                            Objective = 'Compliance with legal, regulatory, and contractual requirements' }
    }

    $result = $frameworkLookup[$Mapping]

    if ($result) {
        return [PSCustomObject]@{
            Framework = $result.Framework
            Domain    = $result.Domain
            Objective = $result.Objective
            Mapping   = $Mapping
        }
    }
    else {
        return [PSCustomObject]@{
            Framework = 'Unknown'
            Domain    = $Mapping
            Objective = ''
            Mapping   = $Mapping
        }
    }
}
