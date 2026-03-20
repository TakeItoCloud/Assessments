@{
    RootModule        = 'TakeItToCloud.Assess.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'Carlos - TakeItToCloud'
    CompanyName       = 'TakeItToCloud'
    Copyright         = '(c) 2026 TakeItToCloud. All rights reserved.'
    Description       = 'Production-grade Microsoft 365, Hybrid Identity, and Infrastructure assessment framework. Evaluates health, security posture, and compliance alignment across AD, Entra ID, Exchange, Defender, and collaboration workloads.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-TtcAssessment'
        'Export-TtcCsvReport'
        'Export-TtcHtmlReport'
        'Get-TtcAssessmentScore'
        'New-TtcFindingObject'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
    PrivateData        = @{
        PSData = @{
            Tags       = @('Assessment', 'Security', 'Microsoft365', 'HybridIdentity', 'EntraID', 'ZeroTrust', 'NIST', 'CIS', 'ISO27001')
            ProjectUri = 'https://github.com/TakeItoCloud/TakeItToCloud.Assess'
        }
    }
}
