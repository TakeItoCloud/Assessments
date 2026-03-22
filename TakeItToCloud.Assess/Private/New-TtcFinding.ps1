function New-TtcFinding {
    <#
    .SYNOPSIS
        Internal factory for creating standardized finding objects.
    .DESCRIPTION
        Creates a PSCustomObject matching the TakeItToCloud.Assess finding schema.
        Used by assessor functions to produce consistent output.
        All parameters have defaults so assessors only need to specify what's relevant.
    .PARAMETER FindingId
        Unique finding ID in format WORKLOAD-CATEGORY-NNN.
    .EXAMPLE
        New-TtcFinding -FindingId "AD-SEC-001" -Workload "ActiveDirectory" -CheckName "Stale admins" `
            -Category "Security" -Severity "High" -Status "Fail" `
            -IssueDetected "3 admin accounts inactive >90 days" `
            -Explanation "Stale privileged accounts are a lateral movement risk." `
            -PossibleSolution "Remove or disable inactive admin accounts."
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FindingId,
        [string]$Workload            = '',
        [string]$Component           = '',
        [Parameter(Mandatory)][string]$CheckName,
        [string]$Category            = 'Security',
        [ValidateSet('Critical','High','Medium','Low','Informational')]
        [string]$Severity            = 'Medium',
        [ValidateSet('Fail','Pass','Warning','Error','NotAssessed')]
        [string]$Status              = 'NotAssessed',
        [string]$IssueDetected       = '',
        [string]$Explanation         = '',
        [string]$PossibleSolution    = '',
        [string]$Impact              = '',
        [string]$RiskLevel           = '',
        [string]$FrameworkMapping    = '',
        [string]$ZeroTrustPillar     = '',
        [string]$SecureScoreMapping  = '',
        [string]$DataSource          = '',
        [string]$Remediation         = '',
        [string]$AutoFixAvailable    = 'No',
        [string]$RemediationPriority = 'P3',
        [string]$MitreAttack         = '',
        [string]$Notes               = '',
        [string]$Timestamp           = ''
    )

    # Auto-derive RiskLevel from Severity if not provided
    if ([string]::IsNullOrWhiteSpace($RiskLevel)) {
        $RiskLevel = switch ($Severity) {
            'Critical'      { 'Critical' }
            'High'          { 'High' }
            'Medium'        { 'Medium' }
            'Low'           { 'Low' }
            'Informational' { 'Low' }
            default         { 'Medium' }
        }
    }

    # Auto-derive RemediationPriority from Severity if default
    if ($RemediationPriority -eq 'P3' -and $Severity -in @('Critical','High')) {
        $RemediationPriority = switch ($Severity) {
            'Critical' { 'P1' }
            'High'     { 'P2' }
        }
    }

    if ([string]::IsNullOrWhiteSpace($Timestamp)) {
        $Timestamp = Get-Date -Format 'o'
    }

    [PSCustomObject]@{
        FindingId           = $FindingId
        Workload            = $Workload
        Component           = $Component
        CheckName           = $CheckName
        Category            = $Category
        Severity            = $Severity
        Status              = $Status
        IssueDetected       = $IssueDetected
        Explanation         = $Explanation
        PossibleSolution    = $PossibleSolution
        Impact              = $Impact
        RiskLevel           = $RiskLevel
        FrameworkMapping    = $FrameworkMapping
        ZeroTrustPillar     = $ZeroTrustPillar
        SecureScoreMapping  = $SecureScoreMapping
        DataSource          = $DataSource
        Remediation         = $Remediation
        AutoFixAvailable    = $AutoFixAvailable
        RemediationPriority = $RemediationPriority
        MitreAttack         = $MitreAttack
        Notes               = $Notes
        Timestamp           = $Timestamp
    }
}
