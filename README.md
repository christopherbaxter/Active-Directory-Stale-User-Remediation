# Active Directory Stale User Remediation

Managing stale user accounts in Active Directory sounds simple. Find the accounts that are no longer used, disable them, wait for an approved retention period, and then delete them.

Simple, right?

Well, not really.

The difficult part is making sure that an account is genuinely stale, has been reviewed, is not a service or privileged identity, is not protected by an exclusion, and has not changed since the report was generated.

This repository contains a report-driven PowerShell framework for:

- Disabling approved stale Active Directory user accounts
- Deleting validated disabled-stale user accounts
- Applying a persistent exclusions list
- Revalidating live AD state before each action
- Revalidating deletion candidates across writable domain controllers
- Checking Active Directory Recycle Bin and directory-retention settings
- Producing detailed audit and error reports

> [!CAUTION]
> This script can disable and delete Active Directory user accounts when `-Execute` is supplied. Preview is the default. Review and test the framework in an isolated non-production environment before considering production use.

## Before you run this script!

This is the remediation companion to the [Hybrid Stale User Management reporting framework](https://github.com/christopherbaxter/Hybrid-Stale-User-Management).

Generate and review the stale-user report first. The report is an input into the remediation process. It is not automatic approval to modify an account.

Do not point this script at a production report, add `-Execute`, and hope for the best.

Start in preview mode, review every candidate, investigate every skipped or failed result, test the exclusions, and use an approved change process before performing live actions.

## What is needed for this script to function?

You will need:

- Windows PowerShell 5.1 or PowerShell 7 with compatible AD module support
- The Active Directory PowerShell module
- Read access to the forest, domains, writable domain controllers, and required user attributes
- Delegated permission to disable approved AD user accounts
- Delegated permission to delete approved AD user accounts
- Network access to the writable domain controllers in each source domain
- A recent CSV report from the reporting framework
- A reviewed semicolon-delimited exclusions file
- A secure output location
- A tested recovery process
- An approved change record before live execution

The remediation script does not call Microsoft Graph. It consumes the Microsoft Entra information already written into the stale-user report.

It does not modify:

- Microsoft Entra ID users
- Microsoft 365 licences
- Mailboxes
- Sign-in sessions or tokens
- Group membership
- Home folders or profiles
- File ownership
- Application data

These processes must be handled separately through the organisation's approved lifecycle procedures.

# Disclaimer

Ok, so this is the important part.

This example was generated with the assistance of AI, using generalised ideas and patterns from scripts and operational processes I have worked with previously. It is not a copy of a production script and contains no customer names, domains, accounts, object IDs, server names, internal paths, or environment-specific information.

I have statically reviewed the public code and logic, but I have not tested this version against a live Active Directory forest. Your environment will be different from mine. Permissions, replication health, protection settings, report formats, PowerShell versions, and directory design can all affect the result.

Please test this properly before using it. Start with preview mode. Use `-WhatIf`. Review every output file. Make sure that you understand why every account is in the disablement or deletion list.

Deletion is destructive. Active Directory Recycle Bin helps only when it was enabled before the account was deleted and the object remains within the applicable retention period.

# Christopher, enough ramble, how does this thing work?

The script has two jobs:

1. Disable approved enabled stale-user accounts.
2. Delete disabled-stale accounts that pass additional live validation.

The reporting and remediation processes are deliberately separate. This provides a review and approval point between identifying an account and changing it.

```text
Generate report
    ↓
Review candidates
    ↓
Update exclusions
    ↓
Run remediation preview
    ↓
Investigate skipped and failed accounts
    ↓
Run with -Execute -WhatIf
    ↓
Obtain approval
    ↓
Disable approved stale users
    ↓
Delete only validated disabled-stale users
```

## Safety controls

The framework includes the following safeguards:

- Preview mode by default
- Explicit `-Execute` requirement
- Standard PowerShell `-WhatIf` and `-Confirm` support
- Report-age validation
- External and report-based exclusions
- AD object GUID matching
- Live account revalidation before action
- Built-in RID 500, 501, and 502 protection
- Service-account indicator checks
- `adminCount` checks
- Accidental-deletion protection checks
- Cross-DC validation before deletion
- Recycle Bin validation before live deletion
- Post-action validation
- Timestamped audit reports

The script fails closed. If required evidence is missing or cross-DC validation is incomplete, the account is skipped for manual review.

## Repository structure

```text
Active-Directory-Stale-User-Remediation/
├── README.md
├── LICENSE
├── SECURITY.md
├── .gitignore
├── scripts/
│   └── Invoke-HybridStaleUserRemediation.ps1
├── examples/
│   └── UserExclusions.example.csv
└── docs/
    └── STALE-USER-REMEDIATION.md
```

## The script

The remediation script will be located at:

```text
scripts/Invoke-HybridStaleUserRemediation.ps1
```

The detailed walkthrough will be located at:

```text
docs/STALE-USER-REMEDIATION.md
```

## The exclusions file

The exclusions file is semicolon-delimited and should use the AD object GUID as the primary identifier.

```csv
ADObjectGUID;SamAccountName;Reason;Owner;ReviewDate
00000000-0000-0000-0000-000000000000;;Emergency access identity;Identity Operations;2027-01-31
;example-service;Application dependency;Application Owner;2027-03-31
```

The example values are fictional.

Copy the example file outside the repository before entering real information. Never commit a completed exclusions file containing organisational data.

## Running the script

### Preview both operations

This is where I would start:

```powershell
.\scripts\Invoke-HybridStaleUserRemediation.ps1 `
    -ReportPath "C:\SecureInput\All-Hybrid-Users.csv" `
    -ExclusionPath "C:\SecureInput\UserExclusions.csv" `
    -OutputPath "C:\SecureOutput" `
    -Mode Both
```

No accounts are modified.

### Exercise the PowerShell `WhatIf` path

```powershell
.\scripts\Invoke-HybridStaleUserRemediation.ps1 `
    -ReportPath "C:\SecureInput\All-Hybrid-Users.csv" `
    -ExclusionPath "C:\SecureInput\UserExclusions.csv" `
    -OutputPath "C:\SecureOutput" `
    -Mode Both `
    -Execute `
    -WhatIf
```

### Disable approved stale users

```powershell
.\scripts\Invoke-HybridStaleUserRemediation.ps1 `
    -ReportPath "C:\SecureInput\All-Hybrid-Users.csv" `
    -ExclusionPath "C:\SecureInput\UserExclusions.csv" `
    -OutputPath "C:\SecureOutput" `
    -Mode Disable `
    -Execute `
    -Confirm
```

### Delete validated disabled-stale users

```powershell
.\scripts\Invoke-HybridStaleUserRemediation.ps1 `
    -ReportPath "C:\SecureInput\All-Hybrid-Users.csv" `
    -ExclusionPath "C:\SecureInput\UserExclusions.csv" `
    -OutputPath "C:\SecureOutput" `
    -Mode Delete `
    -DisabledRetentionDays 180 `
    -Execute `
    -Confirm
```

The `180`-day value is an example framework setting, not a universal Microsoft requirement. Use the retention period approved for your environment.

## Reports produced

Each run creates timestamped reports covering:

- Candidate selection
- Directory retention and Recycle Bin state
- Disablement and deletion outcomes
- Skip reasons and errors
- Cross-DC deletion validation
- Run-level totals

The files are:

```text
Candidate-Selection-<timestamp>.csv
Directory-Retention-<timestamp>.csv
Remediation-Actions-<timestamp>.csv
Deletion-DC-Validation-<timestamp>.csv
Remediation-Summary-<timestamp>.csv
```

Do not commit generated reports to GitHub. They contain identity and directory information.

## Active Directory Recycle Bin

The script checks whether Active Directory Recycle Bin is enabled before permitting live deletion.

Recycle Bin is not enabled by default. It must have been enabled before an object was deleted for that object to be restored through the Recycle Bin. Enabling the feature is irreversible.

The script refuses live deletion when Recycle Bin is disabled unless the high-risk override is explicitly supplied:

```powershell
-AllowDeleteWithoutRecycleBin
```

This is a risk-acceptance option, not a recommendation.

## Tombstone lifetime and deleted-object lifetime

Do not assume that the applicable lifetime is always 60 or 180 days.

The script queries:

- `tombstoneLifetime`
- `msDS-DeletedObjectLifetime`
- Recycle Bin enabled scopes

It records both configured and effective values in the directory-retention report.

## HUGE CAVEAT

### `whenChanged` is not a disablement date

The deletion logic uses `whenChanged` as a conservative object-change age indicator.

It does not identify which attribute changed, who changed it, why it changed, or whether the account remained disabled continuously. The value is also non-replicated, so different DCs can return different local values.

The script therefore queries every returned writable DC and uses the most recent value it receives. Even then, it remains an object-change indicator, not an authoritative disablement timestamp.

If an authoritative disablement date is required, record it separately through the approved change-management or identity-governance process.

## What this script intentionally refuses to do

The framework refuses to:

- Delete from `DisabledStale = True` alone
- Delete when cross-DC validation is incomplete
- Delete an enabled account
- Delete built-in RID 500, 501, or 502 accounts
- Delete an account with an SPN
- Delete an account with a non-expiring password
- Delete an `adminCount = 1` account
- Delete an account protected from accidental deletion
- Delete without Recycle Bin unless explicitly overridden
- Process an old report unless explicitly overridden
- Modify anything unless `-Execute` is supplied

I would rather have a false negative remain for manual review than have a false positive deleted.

## Security and privacy

Do not commit:

- Production reports
- Completed exclusion files
- Real user information
- Domains or tenant information
- Object GUIDs or SIDs
- Server or DC names
- Credentials, tokens, certificates, or keys
- PowerShell transcripts containing organisational data
- Internal links, screenshots, tickets, or meeting content

Use [SECURITY.md](SECURITY.md) for responsible reporting of security concerns.

## Related project

The report-first companion project is available here:

[Hybrid Stale User Management](https://github.com/christopherbaxter/Hybrid-Stale-User-Management)

Use the reporting framework to generate and review the input before using this remediation framework.

## Microsoft documentation

- [Disable-ADAccount](https://learn.microsoft.com/en-us/powershell/module/activedirectory/disable-adaccount?view=windowsserver2025-ps)
- [Remove-ADUser](https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-aduser?view=windowsserver2025-ps)
- [Enable and use Active Directory Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin)
- [Tombstone lifetime and deleted-object lifetime](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1887de08-2a9e-4694-95e2-898cde411180)
- [Lingering objects and tombstone-lifetime guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/information-lingering-objects)
- [Restore-ADObject](https://learn.microsoft.com/en-us/powershell/module/activedirectory/restore-adobject?view=windowsserver2025-ps)

## Licence

This project is licensed under the terms in [LICENSE](LICENSE).

# Final thoughts

The report is not the decision.

The exclusions file is not the decision.

The script is not the decision.

They are controls that help us execute an already reviewed and approved identity-lifecycle decision consistently.

For every account, I want to be able to answer:

1. Why was this account selected?
2. What live evidence was checked?
3. Why was the account not excluded?
4. Who approved the action?
5. What evidence shows that the action succeeded?
6. How will the account be recovered if the decision was wrong?

If we cannot answer those questions, the account is not ready for automated remediation.
