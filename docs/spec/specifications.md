# Active Directory Delegation Analysis Tool — Technical Specification (PowerShell)

## Revision History

This document supersedes the .NET Framework 2.0 / C# technical specification, which has been archived at [`docs/spec/archive/specifications-dotnet-framework.md`](archive/specifications-dotnet-framework.md).

The original specification defined the tool's behavior in terms of a C# executable targeting .NET Framework 2.0. This new specification redefines the tool as a PowerShell script that targets Windows PowerShell 1.0 through 5.1 and PowerShell 7.x on Windows, using the same underlying .NET Framework `System.DirectoryServices` and `System.DirectoryServices.ActiveDirectory` APIs.

## Table of Contents

0. [Target Platform Matrix](#0-target-platform-matrix)
    - [Platform Exclusions](#platform-exclusions)
    - [Version Detection and Conditional Feature Use](#version-detection-and-conditional-feature-use)
1. [Active Directory Scope and Query Locations](#1-active-directory-scope-and-query-locations)
2. [Directory Query Mechanics](#2-directory-query-mechanics)
3. [Paging, Performance, and Query Configuration](#3-paging-performance-and-query-configuration)
4. [Security Descriptor Retrieval and ACE Processing](#4-security-descriptor-retrieval-and-ace-processing)
5. [Detection of Inherited vs. Explicit Permissions](#5-detection-of-inherited-vs-explicit-permissions)
6. [Filtering of Default or Built-in Permissions](#6-filtering-of-default-or-built-in-permissions)
7. [Security Identifier (SID) Resolution](#7-security-identifier-sid-resolution)
8. [Permission and Rights Interpretation](#8-permission-and-rights-interpretation)
9. [Data Processing and Transformation Pipeline](#9-data-processing-and-transformation-pipeline)
10. [CSV Export Structure](#10-csv-export-structure)
11. [Delegation and Template System](#11-delegation-and-template-system)
12. [Handling of Special or Edge Cases](#12-handling-of-special-or-edge-cases)
13. [Usability and Operational Concerns](#13-usability-and-operational-concerns)
14. [Security Considerations](#14-security-considerations)
15. [Assumptions and Limitations](#15-assumptions-and-limitations)
16. [Risk Classification and Insecure Delegation Detection](#16-risk-classification-and-insecure-delegation-detection)
17. [Dangerous Delegation Type Detection](#17-dangerous-delegation-type-detection)
18. [Risk Classification Rules](#18-risk-classification-rules)
19. [Current User Context Reporting](#19-current-user-context-reporting)
20. [Risk Output and Console Feedback](#20-risk-output-and-console-feedback)

---

## 0. Target Platform Matrix

This tool MUST support the following PowerShell versions and their corresponding .NET dependencies:

| PowerShell Version | .NET Dependency | Oldest Supported OS |
| --- | --- | --- |
| Windows PowerShell 1.0 | .NET Framework 2.0 | Windows XP / Windows Server 2003 |
| Windows PowerShell 2.0 | .NET Framework 2.0 | Windows XP / Windows Server 2003 |
| Windows PowerShell 3.0 | .NET Framework 4.0 | Windows Server 2008 |
| Windows PowerShell 4.0 | .NET Framework 4.5 | Windows 7 / Windows Server 2008 R2 |
| Windows PowerShell 5.0 | .NET Framework 4.5 | Windows 7 / Windows Server 2008 R2 |
| Windows PowerShell 5.1 | .NET Framework 4.5 | Windows 7 SP1 / Windows Server 2008 R2 SP1 |
| PowerShell 7.x (Windows only) | .NET Core 3.1 | Windows Server 2012 |

> **Note on Windows PowerShell 5.1:** The actual .NET Framework minimum for Windows PowerShell 5.1 may be 4.5.2, but this specification conservatively assumes .NET Framework 4.5 as the baseline.

### Platform Exclusions

The following platforms are explicitly **not supported**:

#### PowerShell Core 6.x

**Not supported.** PowerShell Core 6.x is end-of-life and was a transitional release. The `System.DirectoryServices` and `System.DirectoryServices.ActiveDirectory` assemblies that this tool depends on are not reliably available on PowerShell Core 6.x even on Windows, and are completely unavailable on Linux/macOS. Supporting this version provides no value.

#### PowerShell 7.x on Linux/macOS

**Not supported.** This tool relies on `System.DirectoryServices`, `System.DirectoryServices.ActiveDirectory`, `WindowsIdentity`, and ADSI-backed LDAP APIs that are Windows-only. These assemblies are not available in the .NET runtime on Linux/macOS. There is no cross-platform equivalent that provides the same functionality (ADSI bindings, Windows DC locator integration, SSPI/Negotiate authentication, `tokenGroups` constructed attribute, etc.).

#### Remote Server Administration Tools (RSAT)

This tool MUST NOT use or rely on the ActiveDirectory PowerShell module or any other component from RSAT. RSAT is not available on all systems where this tool may need to run (e.g., workstations without RSAT installed, older servers, locked-down environments). All AD interaction must use the .NET Framework's `System.DirectoryServices` and `System.DirectoryServices.ActiveDirectory` namespaces directly, which are part of the .NET Framework itself and do not require RSAT.

### Version Detection and Conditional Feature Use

At runtime, the script MUST detect the PowerShell version and .NET capabilities, and conditionally use newer features when available:

- **PowerShell version detection:** Use `$PSVersionTable.PSVersion` to detect the running PowerShell version (note: `$PSVersionTable` does not exist in PowerShell 1.0; its absence indicates PowerShell 1.0).
- **.NET version detection:** Use `[System.Environment]::Version` or check for type availability (e.g., `[System.Collections.Generic.HashSet[string]]`) to detect .NET capabilities.

The following conditional feature tiers define what language and framework features are available at each level:

#### Tier 1 — Baseline (PowerShell 1.0/2.0 on .NET Framework 2.0)

All code MUST work at this tier. The following features are **not available**:

- `HashSet<T>` (not available until .NET 3.5)
- LINQ (`System.Linq.Enumerable`)
- `Enum.HasFlag()` (not available until .NET 4.0)
- `[ordered]` hashtables (not available until PowerShell 3.0)
- `[PSCustomObject]` literal syntax (not available until PowerShell 3.0)

At this tier, use:

- `Dictionary<string, bool>` (via `New-Object 'System.Collections.Generic.Dictionary[string,bool]'`) for set membership testing
- Explicit loops for filtering and transformation
- Manual bitwise `-band` / `-bnot` for flag checks

#### Tier 2 — PowerShell 3.0 on .NET Framework 4.0

In addition to Tier 1 capabilities, the following features become available:

- `HashSet<T>` (available since .NET 3.5, which is included in .NET 4.0)
- `Enum.HasFlag()` (available since .NET 4.0)
- `[ordered]` hashtables
- `[PSCustomObject]` literal syntax

#### Tier 3 — PowerShell 4.0+ on .NET Framework 4.5

In addition to Tier 2 capabilities, the following features become available:

- LINQ via `[System.Linq.Enumerable]` static methods (the `System.Core.dll` assembly containing LINQ is present in .NET 4.0 but more reliable to use from PowerShell 4.0+)

#### Tier 4 — PowerShell 7.x on .NET Core 3.1

In addition to Tier 3 capabilities, the following features become available:

- Modern .NET Core features
- `System.DirectoryServices` is available via the Windows Compatibility Pack on .NET Core 3.1+ on Windows

---

## 1. Active Directory Scope and Query Locations

### Naming Contexts Queried

The tool queries the following Active Directory partitions, discovered dynamically at runtime from the RootDSE:

| Partition | RootDSE Attribute | Purpose |
| --- | --- | --- |
| Schema | `schemaNamingContext` | Retrieve class definitions, attribute definitions, default security descriptors |
| Configuration | `configurationNamingContext` | Retrieve extended rights, control access rights, validated writes, property sets |
| All naming contexts | `namingContexts` | Scan every object in each naming context (including schema, configuration, domain, and application partitions) for explicit (non-inherited) ACEs |
| Root domain | `rootDomainNamingContext` | Used as a fallback domain reference |

### RootDSE Bootstrap

On startup, the tool reads the RootDSE to retrieve essential directory metadata:

```powershell
# Intentionally empty trap statement to prevent terminating errors from halting processing
trap { }

$rootDSE = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://RootDSE"

# Read attributes and use $rootDSE...
# (error-prone operations MUST be wrapped in a function using the trap-based
# error handling pattern — see below)

# Dispose the DirectoryEntry when no longer needed
if ($rootDSE -ne $null) {
    $rootDSE.Dispose()
}
```

**Resource cleanup in PowerShell:** `DirectoryEntry` implements `IDisposable` and MUST be disposed after use to avoid leaking unmanaged ADSI handles. PowerShell does not have a `using` statement equivalent to C#'s `using (IDisposable)` pattern — even in PowerShell 5.1, the `using` keyword is only for namespace and module imports, not for automatic `IDisposable` cleanup.

> **Important:** The `try`, `catch`, and `finally` constructs MUST NOT be used anywhere in this tool. These constructs were introduced in PowerShell 2.0 and cause a **parser error** on PowerShell 1.0 — the script will fail to parse entirely, even if the `try/catch/finally` code is inside a conditional branch that would never execute on v1.0. Since this tool targets PowerShell 1.0 through 7.x from a single script, no `try/catch/finally` may appear in the source code.

**Resource cleanup pattern:** The tool uses the `trap`-based error handling pattern for all error-prone operations, including resource cleanup. An intentionally empty `trap { }` statement is placed within the enclosing scope (either a function body or a script block) to prevent terminating errors from halting processing. When a terminating error occurs, the empty `trap` block suppresses it and execution continues with the next statement, allowing subsequent `.Dispose()` calls to be reached during normal control flow. This applies to all `DirectoryEntry` and `DirectorySearcher` instances throughout the tool.

**Error handling via function wrappers:** All error-prone operations (such as reading attributes from a `DirectoryEntry`, executing `DirectorySearcher.FindAll()`, or calling managed API methods that contact a domain controller) MUST be wrapped in a function that follows one of two patterns from the repository reference code:

- **`reference-code/_RobustCloudServiceFunctionTemplate.ps1`** — for calls that contact an external system (e.g., a domain controller) and may benefit from retry logic with exponential backoff.
- **`reference-code/_SimpleFunctionTemplate.ps1`** — for local operations that do not need retry logic but still require error detection.

Both templates use the same core mechanism: `trap { }` suppresses terminating errors, and `$global:ErrorActionPreference = SilentlyContinue` suppresses non-terminating error output. The `Get-ReferenceToLastError` and `Test-ErrorOccurred` helper functions detect whether an error occurred by comparing `$Error` stack references before and after the operation. See the repository coding standards for detailed documentation of this pattern.

The following attributes are read from the RootDSE:

- `namingContexts` — the list of all naming contexts hosted by the server
- `schemaNamingContext` — the DN of the Schema partition
- `configurationNamingContext` — the DN of the Configuration partition
- `rootDomainNamingContext` — the DN of the forest root domain

When targeting a specific server, the path format is `"LDAP://serverName/RootDSE"`:

```powershell
$rootDSE = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://serverName/RootDSE"
```

The `supportedControl` attribute is not required, as .NET Framework 2.0's `DirectorySearcher.SecurityMasks` property handles SD flags control transparently.

### Known Domain NC Definition

A naming context is classified as a "known domain NC" if it appears as the `nCName` attribute of a `crossRef` object in `CN=Partitions,<configurationNamingContext>` that also has a `nETBIOSName` attribute. This distinguishes domain naming contexts from application partitions and other non-domain NCs.

**Authoritative source**: The known-domain-NC set is built from the `Domains` property of the `Forest` object (see Step 1 in Section 9), which returns all domain NCs in the forest. The `crossRef` query against `CN=Partitions` is used only to retrieve `nETBIOSName` values (since the `Domain` class does not expose NetBIOS names), and the results are matched back to the `Forest.Domains` set by `nCName` ↔ DN. Both sources should produce the same domain set; the `crossRef` definition above provides the formal classification criteria, while `Forest.Domains` is the runtime enumeration mechanism. This same set is used consistently for AdminSDHolder selection, deleted-trustee detection, per-domain SDDL expansion, and all other domain-scoped operations.

### Recursive Traversal

- **Schema partition**: Enumerated via `[System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetCurrentSchema().FindAllClasses()` and `.FindAllProperties()` for class GUIDs, attribute GUIDs, and default security descriptors. When `-Server` is specified, use `[System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetSchema($context)` instead, where `$context` is a `DirectoryContext` targeting the specified server.
- **Configuration partition**: Queried with `DirectorySearcher` using `[System.DirectoryServices.SearchScope]::Subtree` to enumerate `controlAccessRight` objects for property sets, validated writes, and control access rights.
- **Each naming context** (including schema, configuration, domain, and application partitions): Queried with `DirectorySearcher` using `Filter = "(objectClass=*)"` and `SearchScope = [System.DirectoryServices.SearchScope]::Subtree`, which returns every object in the partition recursively.
- **AdminSDHolder**: Accessed via `New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://CN=AdminSDHolder,CN=System,<domainDN>"` when the naming context is a known domain NC; otherwise `New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://CN=AdminSDHolder,CN=System,<rootDomainNamingContext>"`. When `-Server` is specified, the server prefix is included: `"LDAP://serverName/CN=AdminSDHolder,..."`.
- **Individual SID lookups**: Performed via `New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://<SID=S-1-5-...>"`. When `-Server` is specified, the server prefix is included: `"LDAP://serverName/<SID=...>"`.

---

## 2. Directory Query Mechanics

### Domain Controller Discovery and Connection

The tool uses .NET Framework `System.DirectoryServices.ActiveDirectory` managed APIs for DC discovery:

| Behavior | Implementation |
| --- | --- |
| Auto-discover a DC for the current domain | `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()` returns a `Domain` object with an auto-selected DC |
| Auto-discover forest-level topology | `[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()` returns the forest with all domains and sites |
| Connect to a specific server | `New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://serverName"` — connection is established lazily on first property access |
| Specify a port number | Encoded in the LDAP path: `"LDAP://serverName:636"` for LDAPS. **Note:** the port number alone does not enable TLS — `[System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer` must also be set (see LDAPS section below) |
| Failure on non-domain-joined machine | `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()` throws `ActiveDirectoryObjectNotFoundException`; the tool must handle this error by wrapping the call in a function that follows the `trap`-based error handling pattern (use `reference-code/_RobustCloudServiceFunctionTemplate.ps1` since this contacts a domain controller and may benefit from retry logic) and report a clear error message |

The tool should default to using `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()` for DC discovery (which uses the Windows DC locator, i.e., AD sites and services native functionality, to select an optimal DC). An optional `-Server` CLI parameter allows targeting a specific DC. When `-Server` is specified, all directory operations must be routed through that server for consistency:

- **Managed API context**: Use `New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList ([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::DirectoryServer), $serverName` to construct `[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)`, `[System.DirectoryServices.ActiveDirectory.Forest]::GetForest($context)`, and `[System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetSchema($context)` objects, ensuring DC locator routes through the specified server.
- **DirectoryEntry paths**: All `DirectoryEntry` LDAP paths must include the server prefix, e.g., `"LDAP://serverName/RootDSE"`, `"LDAP://serverName/CN=AdminSDHolder,..."`, `"LDAP://serverName/<SID=...>"`.
- **DirectorySearcher instances**: The `SearchRoot` `DirectoryEntry` must include the server prefix when `-Server` is specified.

**General principle**: Prefer .NET Framework managed classes (`Domain`, `Forest`, `ActiveDirectorySchema`, `DirectoryContext` from the `System.DirectoryServices.ActiveDirectory` namespace) over raw LDAP paths wherever possible. These managed classes use the Windows DC locator for site-aware DC selection automatically, and respect `DirectoryContext` for explicit server targeting. Raw LDAP paths (via `DirectoryEntry`) should only be used when no managed equivalent exists (e.g., AdminSDHolder access, SID-based lookups, reading specific object attributes not exposed by managed classes).

### Authentication

| Behavior | Implementation |
| --- | --- |
| Use current Windows SSO (Negotiate/SSPI) | `New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $path` — uses the process identity automatically |
| Explicit credentials | `New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $path, $username, $password, ([System.DirectoryServices.AuthenticationTypes]::Secure)` |
| Interactive password entry (`-Password *`) | Version-conditional: on PS 2.0+ use `Read-Host -AsSecureString` with conversion to plain text; on PS 1.0 use `[System.Console]::ReadKey($true)` in a loop. Pass result to `DirectoryEntry` constructor (see below) |

#### Interactive Password Entry

When the user specifies `-Password *` (interactive prompt), the tool must read the password without echoing it to the console. The implementation MUST use version-conditional logic to select the appropriate approach based on the running PowerShell version (detected via `Get-PSVersion` — see `reference-code/Get-PSVersion.ps1`):

**PowerShell 1.0: `[System.Console]::ReadKey($true)` (plain text directly)**

On PowerShell 1.0, the tool MUST build the password string character-by-character using `[System.Console]::ReadKey($true)`, which reads a single key without echoing it. This method is available in all PowerShell versions (1.0 through 7.x) and directly produces a plain `[string]` suitable for the `DirectoryEntry` constructor. Implementations SHOULD handle Backspace (to allow correction) and filter non-printing control characters rather than appending every key press directly:

```powershell
$passwordChars = New-Object -TypeName 'System.Collections.Generic.List[char]'
while ($true) {
    $key = [System.Console]::ReadKey($true)
    if ($key.Key -eq [System.ConsoleKey]::Enter) {
        break
    } elseif ($key.Key -eq [System.ConsoleKey]::Backspace) {
        if ($passwordChars.Count -gt 0) {
            [void]($passwordChars.RemoveAt($passwordChars.Count - 1))
        }
    } elseif (-not [System.Char]::IsControl($key.KeyChar)) {
        [void]($passwordChars.Add($key.KeyChar))
    }
}
$password = New-Object -TypeName System.String -ArgumentList (, $passwordChars.ToArray())
```

**PowerShell 2.0+: `Read-Host -AsSecureString` (with SecureString conversion)**

On PowerShell 2.0 and later, the tool SHOULD use `Read-Host -AsSecureString`, which provides built-in input masking and produces a `SecureString`. However, the `DirectoryEntry` constructor requires a plain `[string]` for the password parameter. The `SecureString` must be converted to plain text before use. Since `try/finally` MUST NOT be used (see the resource cleanup note in Section 1), the BSTR allocation is freed using the `trap`-based pattern to ensure `ZeroFreeBSTR` is reached even if `PtrToStringBSTR` fails:

```powershell
trap { }

$securePassword = Read-Host -Prompt "Password" -AsSecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$password = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
```

The `trap { }` statement ensures that if `PtrToStringBSTR` throws a terminating error, execution continues to `ZeroFreeBSTR`, preventing an unmanaged BSTR memory leak. This provides equivalent cleanup semantics to the `try/finally` pattern without causing parser errors on PowerShell 1.0.

**Version-conditional selection:**

The tool MUST detect the PowerShell version at runtime and select the appropriate approach:

- **PowerShell 1.0:** Use the `[System.Console]::ReadKey($true)` approach (Approach 1), which produces a plain `[string]` directly.
- **PowerShell 2.0+:** Use the `Read-Host -AsSecureString` approach (Approach 2), which provides brief encrypted in-memory storage during the input phase before conversion to plain text for the `DirectoryEntry` constructor.

**Trade-offs:**

| Consideration | `[System.Console]::ReadKey($true)` | `Read-Host -AsSecureString` |
| --- | --- | --- |
| PowerShell version | 1.0+ | 2.0+ |
| Produces | Plain `[string]` directly | `SecureString` (requires conversion) |
| Echo suppression | Manual (per-character) | Built-in |
| Memory safety | Password in plain text from the start | Password encrypted until conversion |
| Complexity | More code (loop, key handling) | Less code, but conversion step required |

In both cases, the password ultimately exists as a plain `[string]` in memory because `DirectoryEntry` requires it. The `SecureString` approach provides a brief window of encrypted in-memory storage during the input phase, but the plain text conversion is required immediately afterward for the `DirectoryEntry` constructor, limiting the practical security benefit.

### LDAP Filters Used

| Query Target | Filter | Attributes Requested |
| --- | --- | --- |
| Property sets | `(&(objectClass=controlAccessRight)(validAccesses=48)(rightsGuid=*))` | `rightsGuid`, `displayName` |
| Validated writes | `(&(objectClass=controlAccessRight)(validAccesses=8)(rightsGuid=*))` | `rightsGuid`, `displayName` |
| Control access rights | `(&(objectClass=controlAccessRight)(validAccesses=256)(rightsGuid=*))` | `rightsGuid`, `displayName` |
| All naming contexts (main scan) | `(objectClass=*)` | `nTSecurityDescriptor`, `objectClass`, `objectSid`, `adminCount`, `msDS-KrbTgtLinkBl`, `serverReference`, `distinguishedName` |
| AdminSDHolder | `(objectClass=*)` | `nTSecurityDescriptor` |
| Domain enumeration (partitions) | `(&(objectClass=crossRef)(nCName=*)(nETBIOSName=*))` | `nCName`, `nETBIOSName` |

Schema classes and attributes are enumerated via `[System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetCurrentSchema().FindAllClasses()` and `.FindAllProperties()` respectively, rather than via direct LDAP queries. Each `ActiveDirectorySchemaClass` provides `.SchemaGuid`, `.Name` (the `lDAPDisplayName`), and `.DefaultObjectSecurityDescriptor` (SDDL string). Each `ActiveDirectorySchemaProperty` provides `.SchemaGuid` and `.Name`.

Extended rights, property sets, and validated writes are not directly exposed by `ActiveDirectorySchema` and must be queried via `DirectorySearcher` on the Configuration NC using the LDAP filters listed above.

### Referral Handling

LDAP referrals are disabled:

```powershell
$searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
```

**Rationale:** Disabling referrals prevents hanging when running the tool from outside the domain or when DNS cannot resolve referral targets.

**Cross-domain implication:** With referrals disabled, the tool will not automatically follow cross-domain references within the same forest. Objects referenced from other domains will not be resolved via referral chasing. Unfollowed referrals may surface as missing results or errors depending on the specific operation. This is an acceptable trade-off for connection reliability.

### LDAPS and Encrypted Transport

The tool uses `[System.DirectoryServices.AuthenticationTypes]::Secure` by default, which provides SSPI-negotiated authentication (typically Kerberos or NTLM). `Secure` guarantees authenticated binding but does **not** guarantee encryption or integrity protection — signing and sealing are negotiated separately and depend on domain controller and client policies. In most Active Directory environments, Kerberos with signing and sealing is the negotiated result, but this is not guaranteed by the flag alone. For environments that require guaranteed TLS-based transport encryption:

- LDAPS is supported via path syntax: `"LDAP://server:636"` with `[System.DirectoryServices.AuthenticationTypes]::Secure -bor [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer` (combining both flags ensures SSPI/Kerberos/NTLM authentication is preserved over the TLS channel; using `SecureSocketsLayer` alone may fall back to simple bind depending on how credentials are supplied)
- Certificate validation is handled automatically by the Windows trusted CA certificate store
- No custom certificate validation code or P/Invoke is needed

### Connection Endpoints

DC discovery is handled by `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()` and `[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()`, which use the Windows DC locator (AD sites and services) for site-aware DC selection. The `-Server` CLI parameter allows explicit server targeting via `New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList ([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::DirectoryServer), $serverName`. Global Catalog access uses the `GC://` provider (e.g., `"GC://serverName"`), though the tool's operations primarily use the standard LDAP provider.

---

## 3. Paging, Performance, and Query Configuration

### Paged Search

All LDAP searches use paged results via the `PageSize` property of `DirectorySearcher`:

```powershell
$searcher.PageSize = 1000
```

Setting `PageSize` to a nonzero value enables transparent paging — `DirectorySearcher.FindAll()` handles page control creation, cookie management, and continuation automatically. The value 1000 is the default AD `MaxPageSize` policy limit. Environments with custom `MaxPageSize` policies may require a different value.

### Security Descriptor Retrieval Control

The `SecurityMasks` property of `DirectorySearcher` controls which parts of the security descriptor are retrieved:

- **Main scan**: `[System.DirectoryServices.SecurityMasks]::Owner -bor [System.DirectoryServices.SecurityMasks]::Dacl` — retrieves only the owner and DACL
- **AdminSDHolder**: `[System.DirectoryServices.SecurityMasks]::Dacl` — retrieves only the DACL

Example:

```powershell
$searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Owner -bor [System.DirectoryServices.SecurityMasks]::Dacl
```

This replaces the manual `LDAP_SERVER_SD_FLAGS_OID` control and reduces data transfer by excluding the SACL and the security descriptor's Group SID field (not to be confused with the separate `primaryGroupID` attribute).

> **Version note:** `System.DirectoryServices.SecurityMasks` is available in .NET Framework 2.0 and all later versions. No version-conditional logic is needed for this property.

### Timeouts

- `$searcher.ClientTimeout` — maximum time the client waits for search results
- `$searcher.ServerTimeLimit` — maximum time the server spends processing a query

The tool should set reasonable timeout values and report a clear error message if a timeout occurs.

### Attribute Selection

Only the specific attributes needed are requested via the `PropertiesToLoad` property of `DirectorySearcher`:

```powershell
$searcher.PropertiesToLoad.AddRange(@(
    "nTSecurityDescriptor", "objectClass", "objectSid",
    "adminCount", "msDS-KrbTgtLinkBl", "serverReference",
    "distinguishedName"
))
```

> **PowerShell 1.0 compatibility note:** The `AddRange` method is available on `System.Collections.Specialized.StringCollection` in .NET Framework 2.0 and works in all PowerShell versions. As an alternative, individual attributes can be added in a loop using `[void]$searcher.PropertiesToLoad.Add("attributeName")`.

This reduces network traffic compared to retrieving all attributes. The `distinguishedName` attribute is included because it is needed for CSV Resource values (the object's DN), SID → DN cache population, and progress reporting. While .NET's `SearchResult.Path` (ADsPath) also encodes the DN, it includes the LDAP URI prefix and server name, requiring parsing to extract the bare DN — explicitly requesting `distinguishedName` via `PropertiesToLoad` provides the DN directly and avoids ambiguity.

---

## 4. Security Descriptor Retrieval and ACE Processing

<!-- TODO: To be completed in a future work effort -->

---

## 5. Detection of Inherited vs. Explicit Permissions

<!-- TODO: To be completed in a future work effort -->

---

## 6. Filtering of Default or Built-in Permissions

<!-- TODO: To be completed in a future work effort -->

---

## 7. Security Identifier (SID) Resolution

<!-- TODO: To be completed in a future work effort -->

---

## 8. Permission and Rights Interpretation

<!-- TODO: To be completed in a future work effort -->

---

## 9. Data Processing and Transformation Pipeline

<!-- TODO: To be completed in a future work effort -->

---

## 10. CSV Export Structure

<!-- TODO: To be completed in a future work effort -->

---

## 11. Delegation and Template System

<!-- TODO: To be completed in a future work effort -->

---

## 12. Handling of Special or Edge Cases

<!-- TODO: To be completed in a future work effort -->

---

## 13. Usability and Operational Concerns

<!-- TODO: To be completed in a future work effort -->

---

## 14. Security Considerations

<!-- TODO: To be completed in a future work effort -->

---

## 15. Assumptions and Limitations

<!-- TODO: To be completed in a future work effort -->

---

## 16. Risk Classification and Insecure Delegation Detection

<!-- TODO: To be completed in a future work effort -->

---

## 17. Dangerous Delegation Type Detection

<!-- TODO: To be completed in a future work effort -->

---

## 18. Risk Classification Rules

<!-- TODO: To be completed in a future work effort -->

---

## 19. Current User Context Reporting

<!-- TODO: To be completed in a future work effort -->

---

## 20. Risk Output and Console Feedback

<!-- TODO: To be completed in a future work effort -->
