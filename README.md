# BigDACLEnergy

[![Markdown Lint](https://github.com/franklesniak/BigDACLEnergy/actions/workflows/markdownlint.yml/badge.svg)](https://github.com/franklesniak/BigDACLEnergy/actions/workflows/markdownlint.yml)
[![PowerShell CI](https://github.com/franklesniak/BigDACLEnergy/actions/workflows/powershell-ci.yml/badge.svg)](https://github.com/franklesniak/BigDACLEnergy/actions/workflows/powershell-ci.yml)

An Active Directory delegation and DACL analysis tool for security
assessments. BigDACLEnergy extracts AD security descriptors, resolves
permissions, identifies insecure delegations against Tier 0 assets, and
exports risk-scored findings to CSV.

## Features

- **Multi-domain forest scanning** — Automatically discovers all domains in
  the forest via RootDSE bootstrap and enumerates all naming contexts
  returned by RootDSE (including Domain, Configuration, Schema, and
  application partitions)
- **Security descriptor extraction** — Retrieves and parses binary security
  descriptors from AD objects, extracting individual ACEs with full access
  mask and object type resolution
- **Inherited vs. explicit ACE filtering** — Distinguishes explicit
  delegations from inherited permissions, focusing analysis on intentional
  security changes
- **Default/built-in permission filtering** — Filters out well-known default
  ACEs (schema defaults, trusted system principals, read-only rights) to
  surface only meaningful delegations
- **SID resolution** — Resolves Security Identifiers to human-readable
  display names using a four-step priority chain: cache, .NET `Translate()`,
  LDAP lookup, and raw SID fallback
- **Dangerous delegation detection** — Identifies 27 dangerous delegation
  types across five categories: full control, dangerous writes, control
  access rights, create/delete operations, and validated writes
- **Risk classification** — Applies a four-level graduated severity model
  (Critical, High, Medium, Informational) based on a three-dimensional
  matrix of unsafe trustee, Tier 0 resource, and delegation category
- **Current user exploitability** — Annotates each finding with whether the
  current user's group memberships allow exploitation of the delegation
- **CSV export** — Produces deterministic, RFC 4180-compliant CSV output with
  seven columns: Resource, Trustee, Trustee type, Category, Details, Risk
  Level, and Current User Can Exploit
- **Delegation and template system** — Uses XML-based delegation definitions
  with XSD validation for extensible risk classification rules
- **Configurable verbosity** — Supports adjustable verbosity and file-based
  logging with UTC timestamps (verbosity level mechanics are being finalized
  as part of the PowerShell implementation)

## Prerequisites

- **Windows PowerShell 1.0–5.1** on Windows Server 2003 and later — The
  tool targets .NET Framework 2.0 compatibility for maximum portability
  across legacy Windows Server environments
- **PowerShell 7.x+** on supported modern Windows versions — For current,
  supported Windows platforms that run PowerShell 7.x or later
- **Active Directory environment** — The tool requires access to an AD
  forest with appropriate read permissions on directory objects and security
  descriptors
- **Network connectivity** — LDAP/LDAPS access to domain controllers in the
  target forest

## Usage

BigDACLEnergy scans an Active Directory forest, analyzes delegations, and
exports findings to CSV.

> **Note:** The `BigDACLEnergy.ps1` entry point script is not yet available;
> it is being developed and will be added in a future update. The examples
> below illustrate the planned interface.

```powershell
# Basic scan using current credentials (SSO)
.\BigDACLEnergy.ps1 -Csv .\results.csv

# Scan with increased verbosity
.\BigDACLEnergy.ps1 -Csv .\results.csv -Verbose

# Export only findings at or above a risk threshold
.\BigDACLEnergy.ps1 -RiskCsv .\risk-findings.csv -RiskLevel High

# Target a specific domain controller
.\BigDACLEnergy.ps1 -Server dc01.example.com -Csv .\results.csv

# Exclude specific subtrees from the scan
.\BigDACLEnergy.ps1 -Csv .\results.csv -ExcludeDN "OU=Workstations,DC=example,DC=com"
```

### Authentication

BigDACLEnergy supports three authentication methods (in priority order):

1. **Single sign-on (SSO)** — Uses the current Windows identity (default;
   no credential parameters required)
2. **Interactive password** — Supply `-Username <user> -Password *` to be
   prompted for a password securely without echo
3. **Environment variable** — Supply `-Username <user> -PasswordEnv
   <VARIABLE_NAME>` to read the password from a named environment variable
   (no cleartext passwords on the command line)

> **Note:** Cleartext passwords on the command line are not supported.
> If automation requires non-interactive credential supply, use the
> `-PasswordEnv` option.

### Output

Results are written to a UTF-8 encoded CSV file without BOM with the
following columns:

| Column | Description |
| --- | --- |
| Resource | The resource identifier associated with the finding. This is often an AD object (such as a DN), but may also be a schema reference or the literal `Global` (see spec §10 and §16.2 for all cases). |
| Trustee | The trustee associated with the finding. This may be a resolved security principal, the literal `Global`, or an unresolvable raw SID (see spec §10 for resolution rules). |
| Trustee type | A high-level classification of the trustee when resolvable (for example: `User`, `Group`, `Computer`, `External`). May be empty for unresolvable SIDs (see spec §10). |
| Category | The finding category, including delegation categories (e.g., full control, dangerous write) and non-delegation categories (`Warning`, `Owner`, `Allow ACE`). See spec §16.2 for the complete list. |
| Details | Specific permission details and object type information relevant to the finding. |
| Risk Level | Graduated severity when present: `Critical`, `High`, `Medium`, or `Informational`; may be empty when no risk rule matches. |
| Current User Can Exploit | `Yes` when the finding is determined to be exploitable by the current user context; otherwise empty. |

For the complete and authoritative CSV schema, including all allowed values
and edge cases for each column, see
[docs/spec/specifications.md](docs/spec/specifications.md), sections 10 and
16.2.

## Contributing

Contributions are welcome! Please read the [Contributing Guide](CONTRIBUTING.md)
for development setup, coding standards, and pull request guidelines.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
details.

## Security

To report a security vulnerability, please follow the instructions in
[SECURITY.md](SECURITY.md). Do **not** open a public issue for security
reports.

## Acknowledgments

BigDACLEnergy is independently implemented but was inspired by the approaches
of these excellent tools:

- **[ADeleg](https://github.com/mtth-bfft/adeleg)** by
  [@mtth-bfft](https://github.com/mtth-bfft) — AD delegation management and
  inventory tool
- **[ADeleginator](https://github.com/techspence/ADeleginator)** by
  [@techspence](https://github.com/techspence) — Insecure AD delegation
  finder

No source code from either project is used in BigDACLEnergy. See
[ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md) for details.
