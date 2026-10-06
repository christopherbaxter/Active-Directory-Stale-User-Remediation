# Security Policy

## Supported versions

This repository is an educational, community-supported PowerShell framework rather than a formally supported product.

Security fixes will be applied to the latest version on the default branch where practical. Older commits, forks, copied scripts, local modifications, and environment-specific versions are not maintained by this repository.

| Version | Supported |
|---|---|
| Latest version on the default branch | Yes |
| Older commits or downloaded copies | No |
| Forks and modified versions | No |

## Reporting a security vulnerability

Please do not report suspected security vulnerabilities through a public issue, pull request, discussion, screenshot, or social-media post.

Use GitHub's private vulnerability reporting feature for this repository:

1. Open the repository's **Security** page.
2. Open **Advisories**.
3. Select **Report a vulnerability**.
4. Provide enough information to understand, reproduce, and assess the issue without including real organisational data.

If the **Report a vulnerability** option is not visible, open a public issue containing only a request for a private reporting channel. Do not include vulnerability details in that issue.

## What to include

A useful report should contain:

- A clear description of the vulnerability
- The affected script, function, parameter, or workflow
- The affected commit or version, if known
- The expected behavior
- The actual behavior
- Safe reproduction steps using fictional or synthetic identities
- The potential impact
- Any conditions required for exploitation
- A suggested mitigation, if available

Please remove or replace all sensitive identifiers before submitting the report.

## What not to include

Do not submit:

- Real names, email addresses, or user principal names
- Production AD domains, forests, tenants, or OU structures
- Real object GUIDs, SIDs, distinguished names, or SAM account names
- Domain-controller or server names
- IP addresses or internal DNS information
- Credentials, access tokens, certificates, private keys, or secrets
- Production stale-user reports
- Completed exclusions files
- PowerShell transcripts containing organisational data
- Screenshots from a production environment
- Internal tickets, chats, meeting transcripts, or document links
- Customer, employer, or organisational information

Use fictional placeholders and the example files in this repository when demonstrating an issue.

## Security issues that are in scope

Examples of issues that may be in scope include:

- A condition that could allow an excluded account to be selected for remediation
- Incorrect account correlation that could target the wrong AD object
- A bypass of preview mode, `-Execute`, `-WhatIf`, or `ShouldProcess`
- A condition that could delete an enabled account
- A condition that could delete an account without the required cross-DC validation
- A failure to protect built-in RID 500, 501, or 502 accounts
- A failure to honor service-account, privilege, or accidental-deletion protections
- Unsafe handling of report or exclusion data
- Command, path, CSV, or formula injection caused by repository code
- Exposure of credentials, secrets, or sensitive directory data
- Log or output behavior that unexpectedly discloses sensitive information
- A repository dependency or workflow that introduces a credible security risk

## Issues that are not security vulnerabilities

The following should normally be raised as a standard issue rather than a private vulnerability report:

- General PowerShell syntax questions
- Feature requests
- Documentation corrections
- Unsupported report-column names
- Environment-specific permission errors
- AD replication or connectivity problems not caused by repository code
- Requests to customize the script for a particular organisation
- Accounts being skipped because a safety check worked as designed
- Problems caused by removing safeguards or modifying the script
- Recovery requests for production objects

Do not use this repository as an emergency support channel for a production Active Directory incident.

## Safe testing expectations

Only test the framework in an environment where you are explicitly authorized to do so.

Use:

- A dedicated non-production forest or isolated lab
- Fictional user accounts
- Synthetic report data
- The example exclusions file
- Preview mode
- `-WhatIf`
- Limited delegated permissions
- A tested backup and recovery process

Do not test a suspected vulnerability by disabling or deleting real user accounts.

## Destructive-operation warning

This repository contains code that can disable and delete Active Directory user accounts when live execution is enabled.

The framework includes safeguards, but no public script can understand every organisation's identity, application, mailbox, service-account, legal, retention, and recovery requirements.

Before live use:

1. Generate a fresh report.
2. Review and approve the candidate list.
3. Review the exclusions file.
4. Run the script in preview mode.
5. Review every skipped and failed result.
6. Use `-Execute -WhatIf`.
7. Obtain the required change approval.
8. Validate Active Directory Recycle Bin and retention settings.
9. Confirm that a tested recovery process exists.
10. Retain the remediation audit output securely.

## Active Directory Recycle Bin

Active Directory Recycle Bin is not a substitute for correct candidate selection, change approval, backup, or recovery planning.

If Recycle Bin was not enabled before an object was deleted, that object cannot be restored through the Recycle Bin. Recovery also depends on the object remaining within the applicable deleted-object lifetime.

The remediation script refuses live deletion when Recycle Bin is disabled unless the explicit high-risk override is supplied. Removing or bypassing this protection is the operator's responsibility.

## Secrets and sensitive files

Never commit secrets or production identity data to this repository.

Before every commit, check the staged changes:

```powershell
git diff --cached
```

The repository `.gitignore` should exclude common generated reports, transcripts, logs, and local configuration files. A `.gitignore` entry is not a security boundary. Always inspect staged content before committing.

If sensitive information is committed, removing it in a later commit does not remove it from Git history. Treat exposed credentials or secrets as compromised, revoke or rotate them immediately, and follow the appropriate incident-response process.

## Coordinated disclosure

Please allow a reasonable opportunity to investigate and address a reported vulnerability before public disclosure.

A submitted report may be:

- Confirmed as a repository vulnerability
- Closed as not reproducible
- Reclassified as a normal bug or documentation issue
- Determined to be environment-specific
- Determined to result from unsupported modification or removal of safeguards

Fixes may include code changes, safer defaults, additional validation, documentation changes, or a security advisory.

## No warranty or service-level commitment

This project is provided under the terms of the repository licence and without a formal support or response-time commitment.

Submitting a report does not create a contractual support relationship, warranty, or guaranteed remediation timeline.

## Public discussion after remediation

Once a vulnerability has been investigated and addressed, a public advisory or release note may describe:

- The affected component
- The security impact
- The fixed version or commit
- Recommended upgrade or mitigation steps
- Credit to the reporter, if requested and appropriate

Organisational or environment-specific information will not be included.

## Thank you

Responsible reporting helps make this framework safer for everyone using it as a starting point for their own Active Directory lifecycle processes.
