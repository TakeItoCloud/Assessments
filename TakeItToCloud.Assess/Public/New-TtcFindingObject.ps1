function New-TtcFindingObject {
    <#
    .SYNOPSIS
        Creates a standardized TakeItToCloud assessment finding object.
    .DESCRIPTION
        Public function for creating finding objects that conform to the
        TakeItToCloud.Assess schema. Includes parameter validation and
        auto-derivation of fields like RiskLevel and RemediationPriority.
    .PARAMETER FindingId
        Unique identifier in format WORKLOAD-CATEGORY-NNN (e.g., AD-SEC-001).
    .PARAMETER Workload
        The workload being assessed.
    .PARAMETER CheckName
        Human-readable name of the check.
    .PARAMETER Severity
        Severity level: Critical, High, Medium, Low, Informational.
    .PARAMETER Status
        Finding status: Fail, Pass, Warning, Error, NotAssessed.
    .PARAMETER IssueDetected
        One-line summary of the detected issue.
    .PARAMETER Explanation
        Why this finding matters.
    .PARAMETER PossibleSolution
        What to do about it.
    .OUTPUTS
        PSCustomObject matching the TakeItToCloud.Assess finding schema.
    .EXAMPLE
        $finding = New-TtcFindingObject -FindingId "AD-SEC-001" `
            -Workload "ActiveDirectory" -CheckName "Stale admin accounts" `
            -Category "Security" -Severity "High" -Status "Fail" `
            -IssueDetected "3 admin accounts have not signed in for 90+ days" `
            -Explanation "Stale privileged accounts increase attack surface." `
            -PossibleSolution "Disable or remove inactive privileged accounts." `
            -FrameworkMapping "CIS-AccessControl" -ZeroTrustPillar "Identity"
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Z]{2,4}-[A-Z]{3}-\d{3}$')]
        [string]$FindingId,

        [Parameter(Mandatory)]
        [ValidateSet('ActiveDirectory', 'ExchangeOnline', 'HybridIdentity', 'EntraID', 'Defender', 'Collaboration')]
        [string]$Workload,

        [string]$Component = '',

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CheckName,

        [ValidateSet('Health', 'Configuration', 'Security', 'Identity', 'Compliance', 'Monitoring', 'Resilience', 'Governance')]
        [string]$Category = 'Security',

        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$Severity = 'Medium',

        [ValidateSet('Fail', 'Pass', 'Warning', 'Error', 'NotAssessed')]
        [string]$Status = 'NotAssessed',

        [string]$IssueDetected    = '',
        [string]$Explanation       = '',
        [string]$PossibleSolution  = '',
        [string]$Impact            = '',
        [string]$RiskLevel         = '',
        [string]$FrameworkMapping  = '',
        [string]$ZeroTrustPillar   = '',
        [string]$SecureScoreMapping = '',
        [string]$DataSource        = '',
        [string]$Remediation       = '',

        [ValidateSet('Yes', 'No', 'Partial')]
        [string]$AutoFixAvailable = 'No',

        [ValidateSet('P1', 'P2', 'P3', 'P4')]
        [string]$RemediationPriority = 'P3',

        [string]$MitreAttack = '',

        [string]$Notes = ''
    )

    New-TtcFinding @PSBoundParameters
}
