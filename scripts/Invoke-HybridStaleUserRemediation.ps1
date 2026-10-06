<#
.SYNOPSIS
    Safely disables stale AD user accounts and deletes validated disabled-stale
    AD user accounts from an approved CSV report.

.DESCRIPTION
    This report-driven remediation framework:
      - Imports a stale-user CSV report and a semicolon-delimited exclusions CSV.
      - Disables enabled stale candidates.
      - Deletes only disabled-stale candidates.
      - Revalidates every object against live Active Directory immediately before action.
      - Revalidates deletion candidates against all writable DCs in the source domain.
      - Excludes built-in, service-account, privileged, protected and explicitly excluded users.
      - Requires -Execute before making changes.
      - Supports -WhatIf and -Confirm.
      - Produces candidate, action, error and directory-lifetime reports.

    The script does not modify Microsoft Entra ID, licences, mailboxes, sessions,
    groups, home directories or user data.

.NOTES
    IMPORTANT DISCLAIMER

    This example was generated with AI assistance from generalised operational
    patterns. It contains no customer-specific data and is not a copy of a
    production script.

    It has been statically reviewed but has not been tested against a live AD
    forest. Treat it as an educational framework. Review and test it in an
    isolated non-production environment before use.

    Deletion is destructive. Active Directory Recycle Bin recovery is available
    only when the feature was enabled before the object was deleted and while the
    object remains within the applicable deleted-object lifetime. If Recycle Bin
    is not enabled, restoration is not equivalent and may require authoritative
    restore or other recovery processes.

    The script refuses live deletion when Recycle Bin is disabled unless
    -AllowDeleteWithoutRecycleBin is explicitly supplied.

.EXAMPLE
    .\Invoke-HybridStaleUserRemediation.ps1 `
        -ReportPath C:\SecureInput\All-Hybrid-Users.csv `
        -ExclusionPath C:\SecureInput\UserExclusions.csv `
        -OutputPath C:\SecureOutput

    Preview only. No directory objects are changed.

.EXAMPLE
    .\Invoke-HybridStaleUserRemediation.ps1 `
        -ReportPath C:\SecureInput\All-Hybrid-Users.csv `
        -ExclusionPath C:\SecureInput\UserExclusions.csv `
        -OutputPath C:\SecureOutput `
        -Mode Both `
        -Execute `
        -Confirm

    Performs approved actions after live validation and interactive confirmation.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ReportPath,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ExclusionPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [ValidateSet('Disable', 'Delete', 'Both')]
    [string]$Mode = 'Both',

    [ValidateRange(30, 3650)]
    [int]$DisabledRetentionDays = 180,

    [ValidateRange(1, 365)]
    [int]$MaximumReportAgeDays = 7,

    [switch]$Execute,

    [switch]$AllowOldReport,

    [switch]$AllowLegacyReport,

    [switch]$AllowDeleteWithoutRecycleBin
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helper functions

function ConvertTo-BooleanValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [bool]) {
        return $Value
    }

    $Text = $Value.ToString().Trim()

    if ($Text -match '^(?i:true|yes|1)$') {
        return $true
    }

    if ($Text -match '^(?i:false|no|0)$') {
        return $false
    }

    return $null
}

function Get-PropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string[]]$Name
    )

    foreach ($CandidateName in $Name) {
        $Property = $InputObject.PSObject.Properties[$CandidateName]

        if ($null -ne $Property) {
            return $Property.Value
        }
    }

    return $null
}

function Test-HasProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    return $null -ne $InputObject.PSObject.Properties[$Name]
}

function Test-BuiltInSid {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Sid
    )

    if ([string]::IsNullOrWhiteSpace($Sid)) {
        return $false
    }

    return $Sid -match '-(500|501|502)$'
}

function Get-DomainFromDistinguishedName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName
    )

    $DcParts = [regex]::Matches(
        $DistinguishedName,
        '(?i)(?<!\\)DC=([^,]+)'
    )

    if ($DcParts.Count -eq 0) {
        return $null
    }

    return (($DcParts | ForEach-Object { $_.Groups[1].Value }) -join '.')
}

function Get-DirectoryRetentionConfiguration {
    [CmdletBinding()]
    param()

    $RootDse = Get-ADRootDSE
    $DirectoryServiceDn =
        "CN=Directory Service,CN=Windows NT,CN=Services,$($RootDse.ConfigurationNamingContext)"

    $DirectoryService = Get-ADObject `
        -Identity $DirectoryServiceDn `
        -Properties tombstoneLifetime, msDS-DeletedObjectLifetime

    $ConfiguredTsl = $DirectoryService.tombstoneLifetime
    $ConfiguredDol = $DirectoryService.'msDS-DeletedObjectLifetime'

    $EffectiveTsl = if ($null -eq $ConfiguredTsl) {
        60
    }
    else {
        [int]$ConfiguredTsl
    }

    $EffectiveDol = if ($null -eq $ConfiguredDol) {
        $EffectiveTsl
    }
    else {
        [int]$ConfiguredDol
    }

    $RecycleFeature = Get-ADOptionalFeature `
        -Identity 'Recycle Bin Feature' `
        -Properties EnabledScopes

    $RecycleBinEnabled = @($RecycleFeature.EnabledScopes).Count -gt 0

    [PSCustomObject]@{
        ForestName                         = (Get-ADForest).Name
        RecycleBinEnabled                  = $RecycleBinEnabled
        RecycleBinEnabledScopes            = (@($RecycleFeature.EnabledScopes) -join '; ')
        ConfiguredTombstoneLifetimeDays    = $ConfiguredTsl
        EffectiveTombstoneLifetimeDays     = $EffectiveTsl
        ConfiguredDeletedObjectLifetimeDays = $ConfiguredDol
        EffectiveDeletedObjectLifetimeDays = $EffectiveDol
        Interpretation = if ($RecycleBinEnabled) {
            'Deleted objects remain restorable in deleted state for the effective deleted-object lifetime; recycled-object cleanup then follows tombstone-lifetime behavior.'
        }
        else {
            'Recycle Bin is not enabled. Standard Recycle Bin restoration is unavailable for newly deleted objects.'
        }
    }
}

function Get-LiveUserAcrossWritableDomainControllers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SourceDomain,

        [Parameter(Mandatory)]
        [Guid]$ObjectGuid
    )

    $Observations = [System.Collections.Generic.List[object]]::new()

    try {
        $DomainControllers = @(
            Get-ADDomainController `
                -Filter * `
                -Server $SourceDomain |
            Where-Object { $_.IsReadOnly -eq $false } |
            Sort-Object HostName
        )
    }
    catch {
        return [PSCustomObject]@{
            Status                    = 'FailedToEnumerateWritableDCs'
            DomainControllersFound    = 0
            SuccessfulQueries         = 0
            FailedQueries             = 0
            LatestWhenChangedUtc      = $null
            LatestWhenChangedDc       = $null
            AllSuccessfulStatesDisabled = $false
            Observations              = @()
            ErrorMessage              = $_.Exception.Message
        }
    }

    foreach ($DomainController in $DomainControllers) {
        try {
            $LiveUser = Get-ADUser `
                -Identity $ObjectGuid `
                -Server $DomainController.HostName `
                -Properties whenChanged, Enabled, SID, ObjectGUID, DistinguishedName,
                    PasswordNeverExpires, ServicePrincipalName, adminCount,
                    ProtectedFromAccidentalDeletion `
                -ErrorAction Stop

            $Observations.Add([PSCustomObject]@{
                DomainController              = $DomainController.HostName
                QuerySuccessful               = $true
                Found                         = $true
                Enabled                       = $LiveUser.Enabled
                WhenChangedUtc                = ([DateTime]$LiveUser.whenChanged).ToUniversalTime()
                SID                           = $LiveUser.SID.Value
                DistinguishedName             = $LiveUser.DistinguishedName
                PasswordNeverExpires          = $LiveUser.PasswordNeverExpires
                ServicePrincipalNameCount     = @($LiveUser.ServicePrincipalName).Count
                AdminCount                    = $LiveUser.adminCount
                ProtectedFromAccidentalDeletion = $LiveUser.ProtectedFromAccidentalDeletion
                ErrorMessage                  = $null
            })
        }
        catch {
            $Observations.Add([PSCustomObject]@{
                DomainController              = $DomainController.HostName
                QuerySuccessful               = $false
                Found                         = $false
                Enabled                       = $null
                WhenChangedUtc                = $null
                SID                           = $null
                DistinguishedName             = $null
                PasswordNeverExpires          = $null
                ServicePrincipalNameCount     = $null
                AdminCount                    = $null
                ProtectedFromAccidentalDeletion = $null
                ErrorMessage                  = $_.Exception.Message
            })
        }
    }

    $Successful = @($Observations | Where-Object { $_.QuerySuccessful })
    $Failed = @($Observations | Where-Object { -not $_.QuerySuccessful })
    $Latest = $Successful |
        Where-Object { $null -ne $_.WhenChangedUtc } |
        Sort-Object WhenChangedUtc -Descending |
        Select-Object -First 1

    $Status = if ($DomainControllers.Count -eq 0) {
        'NoWritableDomainControllersFound'
    }
    elseif ($Failed.Count -gt 0) {
        'IncompleteValidation'
    }
    elseif ($Successful.Count -eq 0) {
        'NoSuccessfulQueries'
    }
    else {
        'ValidatedAgainstAllWritableDCs'
    }

    [PSCustomObject]@{
        Status                      = $Status
        DomainControllersFound      = $DomainControllers.Count
        SuccessfulQueries           = $Successful.Count
        FailedQueries               = $Failed.Count
        LatestWhenChangedUtc        = if ($null -ne $Latest) { $Latest.WhenChangedUtc } else { $null }
        LatestWhenChangedDc         = if ($null -ne $Latest) { $Latest.DomainController } else { $null }
        AllSuccessfulStatesDisabled = (
            $Successful.Count -gt 0 -and
            @($Successful | Where-Object { $_.Enabled -eq $true }).Count -eq 0
        )
        Observations                = @($Observations)
        ErrorMessage                = $null
    }
}

function Add-ActionResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[object]]$Collection,

        [Parameter(Mandatory)]
        [string]$Action,

        [Parameter(Mandatory)]
        [string]$Outcome,

        [AllowNull()]
        [object]$ReportRow,

        [AllowNull()]
        [object]$LiveUser,

        [AllowNull()]
        [string]$Reason,

        [AllowNull()]
        [string]$ErrorMessage,

        [AllowNull()]
        [object]$Validation
    )

    $Collection.Add([PSCustomObject]@{
        TimestampUtc              = (Get-Date).ToUniversalTime()
        Action                    = $Action
        Outcome                   = $Outcome
        ADObjectGUID              = Get-PropertyValue -InputObject $ReportRow -Name @('ADObjectGUID', 'ObjectGUID')
        SamAccountName            = Get-PropertyValue -InputObject $ReportRow -Name @('SamAccountName', 'samAccountName')
        UserPrincipalName         = Get-PropertyValue -InputObject $ReportRow -Name @('UserPrincipalName', 'Email')
        SourceDomain              = Get-PropertyValue -InputObject $ReportRow -Name @('SourceDomain')
        LiveDistinguishedName     = if ($null -ne $LiveUser) { $LiveUser.DistinguishedName } else { $null }
        LiveEnabledBeforeAction   = if ($null -ne $LiveUser) { $LiveUser.Enabled } else { $null }
        Reason                    = $Reason
        ValidationStatus          = if ($null -ne $Validation) { $Validation.Status } else { $null }
        ValidatedWhenChangedUtc   = if ($null -ne $Validation) { $Validation.LatestWhenChangedUtc } else { $null }
        ValidatedWhenChangedDc    = if ($null -ne $Validation) { $Validation.LatestWhenChangedDc } else { $null }
        DomainControllersFound    = if ($null -ne $Validation) { $Validation.DomainControllersFound } else { $null }
        SuccessfulDcQueries       = if ($null -ne $Validation) { $Validation.SuccessfulQueries } else { $null }
        FailedDcQueries           = if ($null -ne $Validation) { $Validation.FailedQueries } else { $null }
        ErrorMessage              = $ErrorMessage
    })
}

#endregion Helper functions

#region Initial validation

Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$ReportFile = Get-Item -LiteralPath $ReportPath
$ReportAgeDays = ((Get-Date) - $ReportFile.LastWriteTime).TotalDays

if ($ReportAgeDays -gt $MaximumReportAgeDays -and -not $AllowOldReport) {
    throw "The report is $([math]::Round($ReportAgeDays, 1)) days old, exceeding MaximumReportAgeDays=$MaximumReportAgeDays. Generate a fresh report or explicitly use -AllowOldReport."
}

$ReportRows = @(Import-Csv -LiteralPath $ReportPath)
$ExclusionRows = @(Import-Csv -LiteralPath $ExclusionPath -Delimiter ';')

if ($ReportRows.Count -eq 0) {
    throw 'The report contains no data rows.'
}

$RequiredBaseColumns = @('ADObjectGUID', 'SamAccountName', 'SourceDomain')
$MissingBaseColumns = @(
    $RequiredBaseColumns |
    Where-Object { -not (Test-HasProperty -InputObject $ReportRows[0] -Name $_) }
)

if ($MissingBaseColumns.Count -gt 0) {
    throw "The report is missing required columns: $($MissingBaseColumns -join ', ')."
}

$ExclusionGuidIndex = @{}
$ExclusionSamIndex = @{}

foreach ($Exclusion in $ExclusionRows) {
    $GuidValue = Get-PropertyValue -InputObject $Exclusion -Name @('ADObjectGUID', 'ObjectGUID')
    $SamValue = Get-PropertyValue -InputObject $Exclusion -Name @('SamAccountName', 'samAccountName')

    if (-not [string]::IsNullOrWhiteSpace([string]$GuidValue)) {
        $ExclusionGuidIndex[$GuidValue.ToString().Trim().ToLowerInvariant()] = $Exclusion
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$SamValue)) {
        $ExclusionSamIndex[$SamValue.ToString().Trim().ToLowerInvariant()] = $Exclusion
    }
}

$Retention = Get-DirectoryRetentionConfiguration
$RunId = Get-Date -Format 'yyyyMMdd-HHmmss'
$Retention | Export-Csv -LiteralPath (Join-Path $OutputPath "Directory-Retention-$RunId.csv") -NoTypeInformation -Encoding UTF8

if (
    ($Mode -in @('Delete', 'Both')) -and
    $Execute -and
    -not $Retention.RecycleBinEnabled -and
    -not $AllowDeleteWithoutRecycleBin
) {
    throw 'Live deletion refused because AD Recycle Bin is not enabled. Enable it through an approved forest change, or explicitly use -AllowDeleteWithoutRecycleBin after accepting the recovery risk.'
}

#endregion Initial validation

#region Candidate selection

$DisableCandidates = [System.Collections.Generic.List[object]]::new()
$DeleteCandidates = [System.Collections.Generic.List[object]]::new()
$SelectionResults = [System.Collections.Generic.List[object]]::new()

foreach ($Row in $ReportRows) {
    $GuidText = [string](Get-PropertyValue -InputObject $Row -Name @('ADObjectGUID', 'ObjectGUID'))
    $SamText = [string](Get-PropertyValue -InputObject $Row -Name @('SamAccountName', 'samAccountName'))
    $GuidKey = $GuidText.Trim().ToLowerInvariant()
    $SamKey = $SamText.Trim().ToLowerInvariant()

    $ExplicitlyExcluded =
        $ExclusionGuidIndex.ContainsKey($GuidKey) -or
        $ExclusionSamIndex.ContainsKey($SamKey)

    $ReportExcluded = ConvertTo-BooleanValue (
        Get-PropertyValue -InputObject $Row -Name @('IsExcluded')
    )

    $ServiceCandidate = ConvertTo-BooleanValue (
        Get-PropertyValue -InputObject $Row -Name @('ServiceAccountCandidate')
    )

    $Classification = [string](
        Get-PropertyValue -InputObject $Row -Name @('Classification')
    )

    $AdEnabled = ConvertTo-BooleanValue (
        Get-PropertyValue -InputObject $Row -Name @('ADEnabled', 'Enabled')
    )

    $AdStale = ConvertTo-BooleanValue (
        Get-PropertyValue -InputObject $Row -Name @('ADStale')
    )

    $EntraStale = ConvertTo-BooleanValue (
        Get-PropertyValue -InputObject $Row -Name @('EntraStale', 'MGStale')
    )

    $TrueStale = ConvertTo-BooleanValue (
        Get-PropertyValue -InputObject $Row -Name @('TrueStale')
    )

    $AccountOldEnough = ConvertTo-BooleanValue (
        Get-PropertyValue -InputObject $Row -Name @('AccountOldEnough')
    )

    $SyncConfirmed = ConvertTo-BooleanValue (
        Get-PropertyValue -InputObject $Row -Name @('OnPremisesSyncEnabled', 'OnPremiseSyncEnabled')
    )

    $DisabledStale = ConvertTo-BooleanValue (
        Get-PropertyValue -InputObject $Row -Name @('DisabledStale')
    )

    $DcValidationStatus = [string](
        Get-PropertyValue -InputObject $Row -Name @('DCValidationStatus')
    )

    $ProtectedByReport =
        $ExplicitlyExcluded -or
        $ReportExcluded -eq $true -or
        $ServiceCandidate -eq $true

    $ModernDisableEvidence =
        $Classification -eq 'Enabled stale candidate - owner validation required' -and
        $AdEnabled -eq $true -and
        $AdStale -eq $true -and
        $EntraStale -eq $true -and
        $AccountOldEnough -eq $true -and
        $SyncConfirmed -eq $true

    $LegacyDisableEvidence =
        $AllowLegacyReport -and
        $TrueStale -eq $true -and
        $AdEnabled -eq $true -and
        $AdStale -eq $true -and
        $EntraStale -eq $true

    $ModernDeleteEvidence =
        $DisabledStale -eq $true -and
        $DcValidationStatus -eq 'ValidatedAgainstAllWritableDCs'

    $LegacyDeleteEvidence =
        $AllowLegacyReport -and
        $DisabledStale -eq $true

    if (-not $ProtectedByReport -and ($ModernDisableEvidence -or $LegacyDisableEvidence)) {
        $DisableCandidates.Add($Row)
    }

    if (-not $ProtectedByReport -and ($ModernDeleteEvidence -or $LegacyDeleteEvidence)) {
        $DeleteCandidates.Add($Row)
    }

    $SelectionResults.Add([PSCustomObject]@{
        ADObjectGUID           = $GuidText
        SamAccountName         = $SamText
        ExplicitlyExcluded     = $ExplicitlyExcluded
        ReportExcluded        = $ReportExcluded
        ServiceCandidate      = $ServiceCandidate
        SelectedForDisable    = (-not $ProtectedByReport -and ($ModernDisableEvidence -or $LegacyDisableEvidence))
        SelectedForDelete     = (-not $ProtectedByReport -and ($ModernDeleteEvidence -or $LegacyDeleteEvidence))
        Classification        = $Classification
        DCValidationStatus    = $DcValidationStatus
    })
}

$SelectionResults |
    Export-Csv -LiteralPath (Join-Path $OutputPath "Candidate-Selection-$RunId.csv") -NoTypeInformation -Encoding UTF8

#endregion Candidate selection

#region Remediation

$ActionResults = [System.Collections.Generic.List[object]]::new()
$DcObservationResults = [System.Collections.Generic.List[object]]::new()
$DeletionCutoffUtc = (Get-Date).ToUniversalTime().AddDays(-$DisabledRetentionDays)

if ($Mode -in @('Disable', 'Both')) {
    foreach ($Candidate in $DisableCandidates) {
        $GuidText = [string](Get-PropertyValue -InputObject $Candidate -Name @('ADObjectGUID', 'ObjectGUID'))
        $SourceDomain = [string](Get-PropertyValue -InputObject $Candidate -Name @('SourceDomain'))

        try {
            $ObjectGuid = [Guid]$GuidText
            $Server = (Get-ADDomainController -Discover -DomainName $SourceDomain -Writable).HostName
            $LiveUser = Get-ADUser `
                -Identity $ObjectGuid `
                -Server $Server `
                -Properties Enabled, SID, PasswordNeverExpires,
                    ServicePrincipalName, adminCount,
                    ProtectedFromAccidentalDeletion `
                -ErrorAction Stop

            $LiveProtectionReasons = [System.Collections.Generic.List[string]]::new()

            if (Test-BuiltInSid -Sid $LiveUser.SID.Value) {
                $LiveProtectionReasons.Add('Built-in RID 500, 501 or 502')
            }

            if ($LiveUser.PasswordNeverExpires) {
                $LiveProtectionReasons.Add('PasswordNeverExpires is True')
            }

            if (@($LiveUser.ServicePrincipalName).Count -gt 0) {
                $LiveProtectionReasons.Add('User has one or more SPNs')
            }

            if ($LiveUser.adminCount -eq 1) {
                $LiveProtectionReasons.Add('adminCount is 1')
            }

            if (-not $LiveUser.Enabled) {
                $LiveProtectionReasons.Add('Account is already disabled')
            }

            if ($LiveProtectionReasons.Count -gt 0) {
                Add-ActionResult -Collection $ActionResults -Action 'Disable' -Outcome 'Skipped' `
                    -ReportRow $Candidate -LiveUser $LiveUser `
                    -Reason ($LiveProtectionReasons -join '; ') -ErrorMessage $null -Validation $null
                continue
            }

            if (-not $Execute) {
                Add-ActionResult -Collection $ActionResults -Action 'Disable' -Outcome 'PreviewWouldDisable' `
                    -ReportRow $Candidate -LiveUser $LiveUser `
                    -Reason 'Passed report and live safety checks' -ErrorMessage $null -Validation $null
                continue
            }

            if ($PSCmdlet.ShouldProcess($LiveUser.DistinguishedName, 'Disable AD user account')) {
                Disable-ADAccount `
                    -Identity $LiveUser.ObjectGUID `
                    -Server $Server `
                    -Confirm:$false `
                    -ErrorAction Stop

                $PostUser = Get-ADUser -Identity $ObjectGuid -Server $Server -Properties Enabled

                if ($PostUser.Enabled) {
                    throw 'Post-action validation shows that the account is still enabled.'
                }

                Add-ActionResult -Collection $ActionResults -Action 'Disable' -Outcome 'Disabled' `
                    -ReportRow $Candidate -LiveUser $LiveUser `
                    -Reason 'Disabled and verified' -ErrorMessage $null -Validation $null
            }
        }
        catch {
            Add-ActionResult -Collection $ActionResults -Action 'Disable' -Outcome 'Failed' `
                -ReportRow $Candidate -LiveUser $null `
                -Reason 'Disable operation failed' -ErrorMessage $_.Exception.Message -Validation $null
        }
    }
}

if ($Mode -in @('Delete', 'Both')) {
    foreach ($Candidate in $DeleteCandidates) {
        $GuidText = [string](Get-PropertyValue -InputObject $Candidate -Name @('ADObjectGUID', 'ObjectGUID'))
        $SourceDomain = [string](Get-PropertyValue -InputObject $Candidate -Name @('SourceDomain'))
        $Validation = $null
        $LiveUser = $null

        try {
            $ObjectGuid = [Guid]$GuidText
            $Validation = Get-LiveUserAcrossWritableDomainControllers `
                -SourceDomain $SourceDomain `
                -ObjectGuid $ObjectGuid

            foreach ($Observation in $Validation.Observations) {
                $DcObservationResults.Add([PSCustomObject]@{
                    ADObjectGUID      = $GuidText
                    SamAccountName    = Get-PropertyValue -InputObject $Candidate -Name @('SamAccountName', 'samAccountName')
                    SourceDomain      = $SourceDomain
                    DomainController  = $Observation.DomainController
                    QuerySuccessful   = $Observation.QuerySuccessful
                    Enabled           = $Observation.Enabled
                    WhenChangedUtc    = $Observation.WhenChangedUtc
                    ErrorMessage      = $Observation.ErrorMessage
                })
            }

            if ($Validation.Status -ne 'ValidatedAgainstAllWritableDCs') {
                Add-ActionResult -Collection $ActionResults -Action 'Delete' -Outcome 'Skipped' `
                    -ReportRow $Candidate -LiveUser $null `
                    -Reason "Live DC validation incomplete: $($Validation.Status)" `
                    -ErrorMessage $Validation.ErrorMessage -Validation $Validation
                continue
            }

            if (-not $Validation.AllSuccessfulStatesDisabled) {
                Add-ActionResult -Collection $ActionResults -Action 'Delete' -Outcome 'Skipped' `
                    -ReportRow $Candidate -LiveUser $null `
                    -Reason 'At least one writable DC reports the account as enabled' `
                    -ErrorMessage $null -Validation $Validation
                continue
            }

            if (
                $null -eq $Validation.LatestWhenChangedUtc -or
                $Validation.LatestWhenChangedUtc -gt $DeletionCutoffUtc
            ) {
                Add-ActionResult -Collection $ActionResults -Action 'Delete' -Outcome 'Skipped' `
                    -ReportRow $Candidate -LiveUser $null `
                    -Reason 'Latest live whenChanged observation is missing or newer than the deletion cutoff' `
                    -ErrorMessage $null -Validation $Validation
                continue
            }

            $Server = $Validation.LatestWhenChangedDc
            $LiveUser = Get-ADUser `
                -Identity $ObjectGuid `
                -Server $Server `
                -Properties Enabled, SID, PasswordNeverExpires,
                    ServicePrincipalName, adminCount,
                    ProtectedFromAccidentalDeletion `
                -ErrorAction Stop

            $LiveProtectionReasons = [System.Collections.Generic.List[string]]::new()

            if (Test-BuiltInSid -Sid $LiveUser.SID.Value) {
                $LiveProtectionReasons.Add('Built-in RID 500, 501 or 502')
            }

            if ($LiveUser.PasswordNeverExpires) {
                $LiveProtectionReasons.Add('PasswordNeverExpires is True')
            }

            if (@($LiveUser.ServicePrincipalName).Count -gt 0) {
                $LiveProtectionReasons.Add('User has one or more SPNs')
            }

            if ($LiveUser.adminCount -eq 1) {
                $LiveProtectionReasons.Add('adminCount is 1')
            }

            if ($LiveUser.ProtectedFromAccidentalDeletion) {
                $LiveProtectionReasons.Add('ProtectedFromAccidentalDeletion is True')
            }

            if ($LiveUser.Enabled) {
                $LiveProtectionReasons.Add('Account is currently enabled')
            }

            if ($LiveProtectionReasons.Count -gt 0) {
                Add-ActionResult -Collection $ActionResults -Action 'Delete' -Outcome 'Skipped' `
                    -ReportRow $Candidate -LiveUser $LiveUser `
                    -Reason ($LiveProtectionReasons -join '; ') -ErrorMessage $null -Validation $Validation
                continue
            }

            if (-not $Execute) {
                Add-ActionResult -Collection $ActionResults -Action 'Delete' -Outcome 'PreviewWouldDelete' `
                    -ReportRow $Candidate -LiveUser $LiveUser `
                    -Reason 'Passed report and live safety checks' -ErrorMessage $null -Validation $Validation
                continue
            }

            if ($PSCmdlet.ShouldProcess($LiveUser.DistinguishedName, 'Delete AD user account')) {
                Remove-ADUser `
                    -Identity $LiveUser.ObjectGUID `
                    -Server $Server `
                    -Confirm:$false `
                    -ErrorAction Stop

                $StillExists = Get-ADUser `
                    -Identity $ObjectGuid `
                    -Server $Server `
                    -ErrorAction SilentlyContinue

                if ($null -ne $StillExists) {
                    throw 'Post-action validation shows that the user object still exists.'
                }

                Add-ActionResult -Collection $ActionResults -Action 'Delete' -Outcome 'Deleted' `
                    -ReportRow $Candidate -LiveUser $LiveUser `
                    -Reason 'Deleted and absence verified on the target DC' `
                    -ErrorMessage $null -Validation $Validation
            }
        }
        catch {
            Add-ActionResult -Collection $ActionResults -Action 'Delete' -Outcome 'Failed' `
                -ReportRow $Candidate -LiveUser $LiveUser `
                -Reason 'Delete operation failed' -ErrorMessage $_.Exception.Message -Validation $Validation
        }
    }
}

#endregion Remediation

#region Output

$ActionResults |
    Export-Csv -LiteralPath (Join-Path $OutputPath "Remediation-Actions-$RunId.csv") -NoTypeInformation -Encoding UTF8

$DcObservationResults |
    Export-Csv -LiteralPath (Join-Path $OutputPath "Deletion-DC-Validation-$RunId.csv") -NoTypeInformation -Encoding UTF8

$Summary = [PSCustomObject]@{
    RunId                      = $RunId
    ExecutionMode              = if ($Execute) { 'Execute' } else { 'Preview' }
    RequestedMode              = $Mode
    ReportPath                 = $ReportPath
    ReportLastWriteTime        = $ReportFile.LastWriteTime
    ReportAgeDays              = [math]::Round($ReportAgeDays, 2)
    ExclusionPath              = $ExclusionPath
    RecycleBinEnabled          = $Retention.RecycleBinEnabled
    EffectiveDeletedObjectLifetimeDays = $Retention.EffectiveDeletedObjectLifetimeDays
    EffectiveTombstoneLifetimeDays     = $Retention.EffectiveTombstoneLifetimeDays
    DisableCandidates          = $DisableCandidates.Count
    DeleteCandidates           = $DeleteCandidates.Count
    Disabled                   = @($ActionResults | Where-Object Outcome -eq 'Disabled').Count
    Deleted                    = @($ActionResults | Where-Object Outcome -eq 'Deleted').Count
    PreviewWouldDisable        = @($ActionResults | Where-Object Outcome -eq 'PreviewWouldDisable').Count
    PreviewWouldDelete         = @($ActionResults | Where-Object Outcome -eq 'PreviewWouldDelete').Count
    Skipped                    = @($ActionResults | Where-Object Outcome -eq 'Skipped').Count
    Failed                     = @($ActionResults | Where-Object Outcome -eq 'Failed').Count
}

$Summary |
    Export-Csv -LiteralPath (Join-Path $OutputPath "Remediation-Summary-$RunId.csv") -NoTypeInformation -Encoding UTF8

$Summary | Format-List

#endregion Output
