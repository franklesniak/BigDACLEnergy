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

> **Important:** The `try`, `catch`, and `finally` constructs MUST NOT be used anywhere in this tool. These constructs were introduced in PowerShell 2.0 and cause a **parser error** on PowerShell 1.0 — the script will fail to parse entirely, even if the `try/catch/finally` code is inside a conditional branch that would never execute on v1.0. Since this tool targets Windows PowerShell 1.0 through 5.1 and PowerShell 7.x on Windows from a single script, no `try/catch/finally` may appear in the source code.

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

### Security Descriptor Access

Security descriptors are accessed through managed .NET APIs exclusively. No raw Windows API calls (`IsValidSecurityDescriptor`, `GetSecurityDescriptorOwner`, `GetAce`, etc.) are used.

For objects retrieved via `DirectorySearcher`:

- **Primary approach**: Read `nTSecurityDescriptor` as `byte[]` from `$result.Properties["nTSecurityDescriptor"]` and parse with `New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $sdBytes, 0`. This leverages the `PropertiesToLoad` and `SecurityMasks` optimizations already configured on the `DirectorySearcher`, avoiding additional LDAP round-trips. To obtain an `ActiveDirectorySecurity` object (needed for `GetAccessRules()`), construct one from the binary data:

```powershell
$sdBytes = [byte[]]$result.Properties["nTSecurityDescriptor"][0]
$security = New-Object -TypeName System.DirectoryServices.ActiveDirectorySecurity
$security.SetSecurityDescriptorBinaryForm($sdBytes)
```

- **Fallback**: Access `$result.GetDirectoryEntry().ObjectSecurity` to obtain an `ActiveDirectorySecurity` object directly. **Note:** This forces an additional LDAP bind/read per result, negating `PropertiesToLoad`/`SecurityMasks` optimizations. Use only when the binary SD is unavailable from the search result. **Important:** `GetDirectoryEntry()` returns a new `DirectoryEntry` that implements `IDisposable`. When using this fallback, the returned `DirectoryEntry` MUST be disposed (via explicit `.Dispose()`) to release unmanaged ADSI handles, especially inside loops processing many results. Since `try/finally` MUST NOT be used (see Section 1), disposal MUST be performed using the `trap`-based error handling pattern to ensure `.Dispose()` is reached even if an error occurs.

### ACE Extraction

ACEs are retrieved from the `ActiveDirectorySecurity` instance constructed from the binary `nTSecurityDescriptor` (see "Security Descriptor Access" above):

```powershell
# '$security' is the ActiveDirectorySecurity built from nTSecurityDescriptor bytes
$rules = $security.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
```

Passing `$false` for `includeInherited` retrieves only explicit ACEs directly, replacing the manual `INHERITED_ACE` flag check. The `$security` variable here refers to the `ActiveDirectorySecurity` object populated via `SetSecurityDescriptorBinaryForm()` from the `nTSecurityDescriptor` byte array — **not** from `$entry.ObjectSecurity`, which would force an additional LDAP round-trip per result.

Each `ActiveDirectoryAccessRule` exposes:

| Property | Description |
| --- | --- |
| `AccessControlType` | `Allow` or `Deny` |
| `ActiveDirectoryRights` | Flags enum of access rights granted/denied |
| `ObjectType` | GUID identifying the specific property, property set, extended right, or child class |
| `InheritedObjectType` | GUID identifying which child object type the ACE applies to |
| `IdentityReference` | Trustee SID (castable to `SecurityIdentifier`) |
| `InheritanceFlags` | `ContainerInherit`, `ObjectInherit` |
| `PropagationFlags` | `InheritOnly`, `NoPropagateInherit` |
| `IsInherited` | Whether the ACE is inherited (always `$false` when retrieved with `includeInherited = $false`) |

> **Version note:** `ActiveDirectoryRights` is a `[Flags]` enum in `System.DirectoryServices`, available in .NET Framework 2.0 and all later versions. All properties listed above are accessed natively in PowerShell — no special syntax is required beyond standard `.Property` access on the `ActiveDirectoryAccessRule` object.

### SDDL Parsing for Schema Defaults

Schema `defaultSecurityDescriptor` SDDL strings are parsed using:

```powershell
$sd = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddlString
```

The `RawSecurityDescriptor` constructor accepts SDDL directly. The resulting `$sd.DiscretionaryAcl` provides ACE enumeration through `CommonAce` and `ObjectAce` types in `System.Security.AccessControl`.

**Important**: SDDL domain-relative aliases (e.g., `DA` for Domain Admins, `DU` for Domain Users) resolve to different SIDs in each domain, while forest-root-only aliases (`EA` for Enterprise Admins, `SA` for Schema Admins) always resolve to the forest root domain's SID. Since `New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddlString` resolves aliases using only the calling process's security context (i.e., the current domain), schema default SDDL strings must be parsed **once per known domain NC** with manual alias substitution.

**Per-domain SDDL alias expansion mechanism:** For each `ActiveDirectorySchemaClass` with a `DefaultObjectSecurityDescriptor`, the tool MUST manually substitute domain-relative SDDL abbreviations with the appropriate domain's SIDs before parsing. Specifically, for each known domain NC, the tool MUST substitute the following per-domain aliases in the SDDL string (where `<domainSid>` is the full SID string of the domain being processed, e.g., `S-1-5-21-3623811015-3361044348-30300820`):

| Alias | Description | Target SID |
| --- | --- | --- |
| `LA` | Administrator | `<domainSid>-500` |
| `LG` | Guest | `<domainSid>-501` |
| `DA` | Domain Admins | `<domainSid>-512` |
| `DU` | Domain Users | `<domainSid>-513` |
| `DG` | Domain Guests | `<domainSid>-514` |
| `DC` | Domain Computers | `<domainSid>-515` |
| `DD` | Domain Controllers | `<domainSid>-516` |
| `CA` | Cert Publishers | `<domainSid>-517` |
| `PA` | Group Policy Creator Owners | `<domainSid>-520` |
| `CN` | Cloneable Domain Controllers | `<domainSid>-522` |
| `AP` | Protected Users | `<domainSid>-525` |
| `KA` | Key Admins | `<domainSid>-526` |
| `RS` | RAS and IAS Servers | `<domainSid>-553` |

Forest-root-only aliases — these MUST always resolve to the **forest root domain** SID regardless of which domain is being processed:

| Alias | Description | Target SID |
| --- | --- | --- |
| `SA` | Schema Admins | `<forestRootSid>-518` |
| `EA` | Enterprise Admins | `<forestRootSid>-519` |

All other SDDL abbreviations (e.g., `BA`, `AU`, `SY`, `CO`, `WD`) correspond to well-known SIDs that are identical across all domains and MUST be passed unchanged to `System.Security.AccessControl.RawSecurityDescriptor` for resolution. After substitution, parse the expanded string:

```powershell
$sd = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $expandedSddl
```

The set of known domain NCs and their SIDs is collected during domain enumeration (see Section 1, "Known Domain NC Definition"): the tool MUST enumerate all writable domain naming contexts in the current forest and cache each domain NC's SID before performing SDDL alias expansion.

### Owner Retrieval

The object owner is retrieved via:

```powershell
$owner = $security.GetOwner([System.Security.Principal.SecurityIdentifier])
```

> **Note:** `GetOwner()` requires that the security descriptor was retrieved with `SecurityMasks.Owner` included (as in the main scan's `[System.DirectoryServices.SecurityMasks]::Owner -bor [System.DirectoryServices.SecurityMasks]::Dacl`). When only `[System.DirectoryServices.SecurityMasks]::Dacl` was requested (e.g., for AdminSDHolder), the Owner field is not present in the retrieved bytes and `GetOwner()` should not be called.

### Callback ACE Handling

**Documented limitation:** Callback ACE types (`ACCESS_ALLOWED_CALLBACK_ACE_TYPE`, `ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE`, etc.) are returned by `GetAccessRules()` as `ActiveDirectoryAccessRule` objects, but the conditional expression data embedded in the ACE is not exposed by the .NET Framework. Callback ACEs are reported as-is, treated identically to their non-callback counterparts, without evaluation of their conditional expressions. The reported permissions may not reflect the effective conditional access.

### ACE Type Coverage

ACE type coverage is determined by the .NET Framework's `GetAccessRules()` implementation, which parses all supported ACE types and exposes them through `ActiveDirectoryAccessRule`. The tool does not need to enumerate ACE types manually. ACE types that the framework does not expose would appear as `CustomAce` objects in the raw `$sd.DiscretionaryAcl` collection (from `RawSecurityDescriptor`); these are not processed by the tool.

### Objects Inspected

Every object in every naming context is inspected. The tool does not filter by object class during the LDAP query — it retrieves all objects via `(objectClass=*)` and processes each one's security descriptor.

---

## 5. Detection of Inherited vs. Explicit Permissions

### Inherited ACE Filtering

Only explicitly assigned (non-inherited) ACEs are included in the output. This is achieved by passing `$false` for `includeInherited` to `GetAccessRules()`:

```powershell
$rules = $security.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
```

This eliminates the need for manual `INHERITED_ACE` flag checking. The tool's goal is to report delegations that were explicitly configured, not those that flow down from parent containers through inheritance.

---

## 6. Filtering of Default or Built-in Permissions

### Schema Default Security Descriptors

Each AD class can have a `defaultSecurityDescriptor` attribute in SDDL form, accessed via `ActiveDirectorySchemaClass.DefaultObjectSecurityDescriptor`. The tool parses these for every class and computes the ACEs that would be derived by inheritance from the schema defaults for each object's class. An ACE that matches a schema default is excluded from the output.

The ACE comparison function compares two ACEs while ignoring:

- **Read-only access rights**: `[System.DirectoryServices.ActiveDirectoryRights]::ReadProperty`, `[System.DirectoryServices.ActiveDirectoryRights]::ListChildren`, `[System.DirectoryServices.ActiveDirectoryRights]::ReadControl`, `[System.DirectoryServices.ActiveDirectoryRights]::ListObject`
- **Object inherit flag**: `[System.Security.AccessControl.InheritanceFlags]::ObjectInherit`. The `OBJECT_INHERIT_ACE` flag causes an ACE to be inherited by non-container (leaf) child objects, while `ContainerInherit` causes inheritance to container child objects. The tool masks out this flag before comparing ACEs. **This is an intentional design simplification**, not a claim about AD's object model. Leaf objects do exist in AD (e.g., individual DNS records in AD-integrated DNS zones, certain system objects), and ignoring `OBJECT_INHERIT_ACE` may produce incorrect results for ACEs that target these objects. This trade-off is accepted because the flag has no effect on container objects (which represent the tool's primary analysis targets), and preserving it would introduce false positives in schema default ACE comparison. This is documented as a known limitation.

**False-negative risk:** An administrator may intentionally set an explicit ACE that happens to match a schema default. Excluding these ACEs means the tool will not report them. This trade-off is documented as a known limitation. A future enhancement could provide a flag to expose these matches, similar to `-ShowBuiltin`.

### Default SD Computation for Multiple Classes

The tool computes default security descriptors based on the object's most-specific class (the last value in the multi-valued `objectClass` attribute). Active Directory uses the union of inherited ACEs from all structural classes in the hierarchy. If a parent class has a `defaultSecurityDescriptor` that introduces ACEs not present in the most-specific class's default, those ACEs may not be correctly filtered. This is documented as a known limitation.

### Creator Owner Handling in Schema Defaults

When computing inherited ACEs from schema defaults, if the parent ACE's trustee is the `Creator Owner` SID (`S-1-3-0`), it is replaced by the actual owner SID of the child object (mirroring AD behavior). Both the replaced and original ACEs are produced as defaults, so an explicit ACE matching either version is filtered.

**Note:** If the object's owner has changed since creation, the ACE with the original creator's SID would no longer match the owner-replaced version. The tool uses the current owner SID for this comparison.

### Ignored Trustee SIDs

ACEs for the following well-known SIDs are suppressed by default. These are highly-privileged or default trustees whose ACEs are usually not actionable for delegation review. They can be re-enabled via `-ShowIgnoredTrustees`:

| SID | Identity |
| --- | --- |
| `S-1-5-10` | SELF |
| `S-1-5-18` | Local System |
| `S-1-5-20` | Network Service |
| `S-1-5-32-544` | BUILTIN\Administrators |
| `S-1-5-9` | Enterprise Domain Controllers |
| `<domain SID>-512` | Domain Admins (per domain) |
| `<domain SID>-516` | Domain Controllers (per domain) |
| `<forest root domain SID>-518` | Schema Admins (forest root domain only) |
| `<forest root domain SID>-519` | Enterprise Admins (forest root domain only) |

**Note:** Account Operators (`S-1-5-32-548`), Server Operators (`S-1-5-32-549`), Print Operators (`S-1-5-32-550`), and Backup Operators (`S-1-5-32-551`) are **reported by default** and are NOT in the suppressed list. These groups are well-known attack vectors in Active Directory, and suppressing their ACEs by default could give a false sense of security. Security auditors specifically need visibility into what these groups can do.

### Configurable Ignored Trustee List

The `-ShowIgnoredTrustees` CLI option causes the tool to report ACEs for all trustees, including those in the default suppressed list. This allows auditors to see the full picture when needed.

### Read-Only Access Rights

ACEs whose access mask, after masking out read-only rights, results in zero are discarded. The ignored (read-only) access rights are defined using the `ActiveDirectoryRights` enum:

```powershell
$ignoredRights = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor
    [System.DirectoryServices.ActiveDirectoryRights]::ListChildren -bor
    [System.DirectoryServices.ActiveDirectoryRights]::ReadControl -bor
    [System.DirectoryServices.ActiveDirectoryRights]::ListObject

if (([int]$rule.ActiveDirectoryRights -band (-bnot [int]$ignoredRights)) -eq 0) {
    # ACE grants only read-only rights; discard
}
```

> **Version note — bitwise operations on enums:** `ActiveDirectoryRights` is a `[Flags]` enum in `System.DirectoryServices`, available in .NET Framework 2.0 and all later versions. The `-bnot` operator on an enum value may not produce the expected result without first casting to `[int]`, because `-bnot` on an enum returns the result as the enum type, which can cause issues in subsequent bitwise operations. The `[int]` cast shown above ensures correct bitwise NOT behavior and is recommended across all supported PowerShell versions for reliability.
>
> For flag checks, `-band` is the primary approach and works across all supported versions. On PowerShell 3.0+ (.NET 4.0+), `$rule.ActiveDirectoryRights.HasFlag($flagValue)` can be used as an alternative for single-flag checks, but `-band` is preferred for simplicity and cross-version consistency.
>
> When converting string representations of rights to enum values (e.g., when parsing delegation definition files), use `[System.Enum]::Parse([System.DirectoryServices.ActiveDirectoryRights], $rightsName)` for PowerShell 1.0 compatibility. On PowerShell 2.0+, direct casting via `[System.DirectoryServices.ActiveDirectoryRights]$rightsName` also works.

The output reflects the full (unmasked) access rights of an ACE. The masking is used only for the "is this ACE interesting?" decision. In `-ShowRaw` mode, the complete access mask is displayed.

### Delete Protection ACEs

Deny ACEs for `Everyone` (`S-1-1-0`) are suppressed only when the ACE **exclusively** denies delete-related rights (`Delete`, `DeleteChild`, and/or `DeleteTree`). If the ACE also denies other rights beyond these, it is NOT suppressed. This tightened check prevents hiding deny ACEs that restrict more than just deletion.

```powershell
$deleteRights = [System.DirectoryServices.ActiveDirectoryRights]::Delete -bor
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild -bor
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree

# Suppress only if the ACE denies exclusively delete rights
if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and $trusteeSid.Equals($everyoneSid) -and (([int]$rule.ActiveDirectoryRights -band (-bnot [int]$deleteRights)) -eq 0)) {
    # Suppress this standard delete-protection entry
}
```

### Change Password Deny ACEs

Deny ACEs for `Everyone` that deny the `Change Password` control access right are suppressed, as these are set by tools like `dsa.msc` for the "Cannot change password" option.

### AdminSDHolder ACEs

For objects where `adminCount != 0` **and** `$security.AreAccessRulesProtected` is `$true`, ACEs that appear in the AdminSDHolder DACL are suppressed. This is because objects marked as protected (commonly indicated by `adminCount != 0`) have their security descriptors — including inheritance blocking — periodically stamped (copied) from AdminSDHolder by SDProp. Both conditions are required: `adminCount` alone is unreliable because it is notoriously stale — it is typically present on objects that are or were members of protected groups, but it is not always cleared when an object is removed from such a group. If `adminCount != 0` but `$security.AreAccessRulesProtected` is `$false`, the object is likely no longer in the population of objects whose security descriptors are stamped from AdminSDHolder by SDProp, and its explicit ACEs represent real delegations that should be reported (not filtered).

> **Note:** This tool determines AdminSDHolder-related suppression based on per-object state (`adminCount` and `AreAccessRulesProtected`) rather than inferring protection from membership in a list of "protected groups." This avoids brittle heuristics based on group names (which can be localized or renamed) or static protected-group lists (which can be impacted by environment customizations).

The `adminCount` attribute is parsed as an integer, not a string:

```powershell
$adminCount = 0
if ($result.Properties.Contains("adminCount")) {
    $adminCount = [int]$result.Properties["adminCount"][0]
}
```

Any nonzero integer value indicates that the object is or has been treated as protected; however, effective AdminSDHolder ACE suppression still relies on the combined check described above (`adminCount != 0` and `$security.AreAccessRulesProtected -eq $true`).

**Stale adminCount caveat:** The `adminCount` attribute is notoriously stale in AD — it is typically present on objects that are or were members of protected groups, but it is not always cleared when an object is removed from such a group. Additionally, `adminCount` can be manually modified. Formerly-protected objects may have `adminCount=1` but are no longer in the population of objects whose security descriptors are stamped from AdminSDHolder by SDProp. Because AdminSDHolder ACE filtering requires both `adminCount != 0` and `$security.AreAccessRulesProtected -eq $true` (see above), stale `adminCount` objects whose inheritance has been restored will correctly have their ACEs reported rather than suppressed. If `adminCount != 0` but `$security.AreAccessRulesProtected` is `$false`, the tool logs a warning noting the inconsistency, as this may indicate a stale `adminCount`.

### Ignored Control Access Rights

ACEs granting only `ExtendedRight` for specific control access rights that do not grant meaningful control over a resource are suppressed:

- `Apply Group Policy` — applying a GPO does not mean controlling it
- `Allow a DC to create a clone of itself` — if an attacker can impersonate a DC, cloning is not the primary concern

### Ignored DACL Protected Flags

DACL inheritance blocking (detected via `$security.AreAccessRulesProtected`) is not reported as a warning for:

- Objects of class `groupPolicyContainer` (GPOs block inheritance by design)
- Objects with `adminCount != 0` (expected to have inheritance blocked as part of AdminSDHolder protection)
- Specific well-known containers: `CN=AdminSDHolder,CN=System`, `CN=VolumeTable,CN=FileLinks,CN=System`, `CN=Keys`, `CN=WMIPolicy,CN=System`, `CN=SOM,CN=WMIPolicy,CN=System`

### Built-in Delegation Definitions

A set of built-in delegation definitions is shipped with the tool, either embedded within the script (e.g., as a here-string or data section) or as an external XML file distributed alongside the script. These define expected ACEs for well-known delegations (e.g., DnsAdmins on DNS zones, Group Policy Creator Owners on WMI policies). By default, matched built-in delegations are excluded from CSV output unless `-ShowBuiltin` is specified.

### RODC-Specific Filtering

The tool suppresses several ACE patterns specific to Read-Only Domain Controllers (RODCs):

- Change Password / Reset Password control access by an RODC on its secondary KrbTgt account
- `CreateChild` on `nTDSDSA` objects by the RODC referenced from the server object, and `Delete` on `nTDSDSA` objects only when the ACE has the `InheritOnly` propagation flag set
- `WriteProperty` for `schedule` and `fromServer` attributes on `nTDSConnection` objects by the owning RODC
- Validated write for `dnsHostName` on `server` objects by the referenced RODC

---

## 7. Security Identifier (SID) Resolution

### Resolution Strategy

SID resolution uses a clear 4-step priority:

1. **Cache lookup**: Check a SID resolution cache (a key-value mapping from SID string to resolved result) for a previously resolved display name and principal type.
2. **Local resolution via `SecurityIdentifier.Translate()`**: Call `$sid.Translate([System.Security.Principal.NTAccount])`. If successful, the resulting `NTAccount` object's `.Value` property returns the name in `DOMAIN\Username` format. This replaces the previous `LookupAccountSidLocalW` approach entirely — no P/Invoke or dynamic library loading is needed. The `Translate()` method is a .NET instance method on `System.Security.Principal.SecurityIdentifier` and works identically across all supported PowerShell versions.
3. **LDAP SID-based lookup**: Perform a lookup via `New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://<SID=$($sid.Value)>"` and retrieve `distinguishedName` and `objectClass` attributes. When `-Server` is specified, include the server prefix: `"LDAP://$serverName/<SID=$($sid.Value)>"`. If successful, the DN is used as the display name and `objectClass` determines the principal type. The `DirectoryEntry` MUST be disposed after use (see resource cleanup note below).
4. **Raw SID string fallback**: If all resolution methods fail, the raw SID string (e.g., `S-1-5-21-...`) is used as the display name, with type `External`.

**Resource cleanup for LDAP SID lookups:** The `DirectoryEntry` created for each SID lookup implements `IDisposable` and MUST be disposed to release unmanaged ADSI handles. Since `try/finally` MUST NOT be used (see Section 1), disposal MUST be performed using the `trap`-based error handling pattern to ensure `.Dispose()` is reached even if an error occurs during attribute retrieval. The LDAP lookup operation MUST be wrapped in a function following the `trap`-based pattern from `reference-code/_RobustCloudServiceFunctionTemplate.ps1` (since it contacts a domain controller and may benefit from retry logic). The `.Dispose()` call is placed after the error-prone attribute access, within the same scope as the `trap { }` statement, so that it executes regardless of whether the access succeeded or failed.

### Cache Semantics

The SID resolution cache uses **"first write wins"** semantics: once a SID's mapping is stored, it is not overwritten for the duration of the run. This ensures stable, predictable resolution results.

The cache is implemented as a `Dictionary<string, object>`:

```powershell
$sidCache = New-Object 'System.Collections.Generic.Dictionary[string,object]'
```

> **Version note — generic dictionary instantiation:** `New-Object 'System.Collections.Generic.Dictionary[string,object]'` is the way to create a `Dictionary<TKey,TValue>` across all supported PowerShell versions, including PowerShell 1.0. On PowerShell 3.0+, the alternative syntax `[System.Collections.Generic.Dictionary[string,object]]::new()` also works, but `New-Object` is preferred for cross-version consistency. The value type `object` is used here because the cache stores a composite resolution result. Implementations MAY narrow the value type when they also constrain the minimum supported PowerShell version (for example, using `Dictionary[string,psobject]` or `Dictionary[string,IDictionary]` for PowerShell 1.0/2.0 compatibility). In the baseline implementation, `PSObject` with `Add-Member` is the recommended composite type because it is available in all PowerShell versions including 1.0 and provides named-property semantics without requiring `Add-Type` or PowerShell 5.0+ class definitions.

The cache stores a typed resolution result with:

- **Display name**: Either a `DOMAIN\Username` string (from `Translate()`) or a DN (from LDAP lookup) or a raw SID string (fallback)
- **Principal type**: The resolved principal type classification
- **Resolution source**: Which resolution path populated the entry (for diagnostic purposes)

> **Version note — HashSet for SID sets (Tier 2 / PowerShell 3.0+):** For auxiliary data structures that require set-membership semantics (e.g., tracking which SIDs have already been processed, or maintaining a set of known domain SIDs), `[System.Collections.Generic.HashSet[string]]` provides cleaner semantics than `Dictionary<string, bool>` on PowerShell 3.0+ (where the underlying .NET runtime exposes `System.Collections.Generic.HashSet<T>`; this type is available starting in .NET 3.5 and is also present in the .NET 4.0 runtime used by PowerShell 3.0+). On PowerShell 1.0/2.0 (.NET Framework 2.0, where `HashSet<T>` is not available), fall back to `New-Object 'System.Collections.Generic.Dictionary[string,bool]'` and use `.ContainsKey($sidString)` for membership checks. The SID resolution cache itself uses `Dictionary<string, object>` (not `HashSet`) because it stores key-value mappings, not just membership. **Important:** Because this is a version-conditional choice, every location in the code that creates or interacts with a set-membership data structure MUST include a runtime version check (e.g., via `Get-PSVersion`) to select between `HashSet<T>` and `Dictionary<string, bool>`. This conditional pattern MUST be applied consistently wherever set-membership structures are instantiated or consumed.

### Cache Population

The cache is populated from multiple sources during operation:

- **During the main scan**: When an object has an `objectSid` attribute, for domain-specific SIDs (starting with `S-1-5-21-...`), the mapping from SID → DN is inserted directly. For non-domain-specific SIDs (e.g., well-known SIDs found in `CN=ForeignSecurityPrincipals`), `Translate()` is attempted first; only if it throws `IdentityNotMappedException` is the SID → DN mapping inserted as a fallback. Existing cache entries are never overwritten.
- **During `Translate()` resolution**: A successful translation stores the SID → `DOMAIN\Username` mapping.
- **During LDAP SID lookup**: A successful lookup stores the SID → DN mapping.

### Principal Type Resolution

Each resolved SID is mapped to one of four principal type classifications. The mapping depends on the resolution path:

**From LDAP (objectClass-based):** The most specific class (last value of the multi-valued `objectClass` attribute) is compared via case-insensitive exact match. In PowerShell, `-eq` on strings is case-insensitive by default, which aligns well with this requirement:

| Most Specific Class | Principal Type | Notes |
| --- | --- | --- |
| `computer` | `Computer` | Includes machine accounts |
| `user` | `User` | Includes `inetOrgPerson` (which inherits from `user` and appears as most-specific class `inetOrgPerson` — see below) |
| `group` | `Group` | |
| `msDS-GroupManagedServiceAccount` | `User` | gMSA accounts (inherits from `computer` in AD but logically represents a service identity) |
| `msDS-ManagedServiceAccount` | `User` | sMSA accounts |
| `inetOrgPerson` | `User` | Inherits from `user`; the `objectClass` ordering (most-specific-last) ensures this is the last value |
| `foreignSecurityPrincipal` | `External` | Represents a principal from a trusted domain |
| Any other class | `External` | |

**From `SecurityIdentifier.Translate()` resolution:** The `Translate()` method returns an `NTAccount` but does not directly provide a `SID_NAME_USE` equivalent. The principal type is set to `External` for `Translate()`-resolved SIDs. Because the cache uses "first write wins" semantics and the resolution steps are sequential (cache → `Translate()` → LDAP), a SID successfully resolved by `Translate()` is cached immediately and the LDAP step is never attempted for that SID — so the `External` type is not subsequently refined. SIDs that are pre-populated during the main scan (from objects with `objectSid`) already have `objectClass`-based types before `Translate()` is ever tried, so they are unaffected.

**Unresolved SIDs:** If resolution fails entirely (cache miss, `Translate()` throws `IdentityNotMappedException`, and LDAP lookup fails), the raw SID string is used as the trustee name with type `External`.

### Foreign Security Principals

`$sid.Translate([System.Security.Principal.NTAccount])` automatically resolves trusted-domain and well-known SIDs, regardless of where they appear in the directory. Foreign security principal objects in `CN=ForeignSecurityPrincipals` do not require special handling — `Translate()` does the right thing for cross-domain and cross-forest SIDs. Truly unresolvable SIDs (e.g., from unreachable forests) fall back to the raw SID string.

### Deleted Trustee Detection

During post-processing, for each naming context, ACEs whose trustee SID cannot be resolved are evaluated for deleted trustee classification:

```powershell
# $knownDomainSids is the in-memory set/dictionary of known domain SIDs.
# It MAY be implemented as either:
#   - [System.Collections.Generic.Dictionary[string,bool]] (Tier 1 / PowerShell 1.0+)
#   - [System.Collections.Generic.HashSet[string]]        (Tier 2 / PowerShell 3.0+)
# This helper abstracts the membership check so callers do not need to know
# which backing type is in use.
#
# IMPORTANT: The HashSet<T> type does not exist on PowerShell 1.0/2.0 (.NET 2.0).
# Referencing [System.Collections.Generic.HashSet[string]] directly would throw
# a runtime error on those versions. The version check via Get-PSVersion gates
# the HashSet branch so the type is never referenced on Tier 1.
function Test-KnownDomainSid {
    param (
        [string]$SidValue
    )

    $versionPS = Get-PSVersion
    if ($versionPS.Major -ge 3) {
        # Tier 2+: HashSet<T> is available (.NET 3.5+)
        if ($knownDomainSids -is [System.Collections.Generic.HashSet[string]]) {
            return $knownDomainSids.Contains($SidValue)
        }
    }

    # Tier 1 / fallback: Dictionary<string,bool>
    if ($knownDomainSids -is [System.Collections.Generic.Dictionary[string,bool]]) {
        return $knownDomainSids.ContainsKey($SidValue)
    }

    # Final fallback: treat $knownDomainSids as an enumerable of SID strings
    foreach ($sid in $knownDomainSids) {
        if ($sid -eq $SidValue) { return $true }
    }
    return $false
}

$domainSid = $trusteeSid.AccountDomainSid

if (($null -ne $domainSid) -and (Test-KnownDomainSid -SidValue $domainSid.Value)) {
    # Flag as deleted trustee
}
```

`$trusteeSid.AccountDomainSid` returns the domain portion of a SID (strips the RID), or `$null` for well-known SIDs with no domain component. If the domain portion matches **any** known domain SID (not just the root domain), the ACE is flagged as a deleted trustee. Unresolvable SIDs from unknown domains or forests remain as orphan ACEs with raw SID trustee strings.

> **Version note — LINQ for filtering (Tier 3 / PowerShell 4.0+):** Where the implementation uses explicit loops to filter or search through the set of known domain SIDs (e.g., iterating through a dictionary or list to find a matching domain SID), on PowerShell 4.0+ (.NET 4.5+), `[System.Linq.Enumerable]::Any(...)` or similar LINQ methods could be used for conciseness. On PowerShell 1.0–3.0, explicit `foreach` loops with early-exit (`break`) MUST be used instead. The `-band` and `-eq` operators used in the examples above work identically across all supported versions.

---

## 8. Permission and Rights Interpretation

### Access Mask Mapping

The tool maps `ActiveDirectoryRights` enum values to human-readable descriptions. When in resolved-name mode (the default), the following mappings apply:

| `ActiveDirectoryRights` Value | Human-Readable Description |
| --- | --- |
| `WriteProperty` | "Write attribute {name}" (attribute GUID match), "Write attributes of category {name}" (property set GUID match), or "Write all properties" (no match/no GUID) |
| `ExtendedRight` | "{Control access name}" or "Perform all application-specific operations" |
| `CreateChild` | "Create child {class} objects" or "Create child objects of any type" |
| `DeleteChild` | "Delete child {class} objects" or "Delete child objects of any type" |
| `WriteOwner` | "Change the owner" |
| `WriteDacl` | "Add/delete delegations" |
| `Delete` | "Delete" |
| `DeleteTree` | "Delete along with all children" |
| `Self` | "{Validated write name}" or "Perform all validated writes" |
| `AccessSystemSecurity` | "Add/delete auditing rules" |

Rights checks use bitwise operations compatible with .NET Framework 2.0:

```powershell
if (($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -ne 0) {
    # WriteProperty is set
}
```

> **Version note — `Enum.HasFlag()` is NOT used in the baseline spec** because it requires .NET 4.0+ (Tier 2). On PowerShell 3.0+ (where .NET 4.0+ is available), `$rule.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)` may be used as an alternative for single-flag checks, but the `-band` approach is preferred for code simplicity and cross-version consistency.

### Object Type GUID Resolution

In **resolved-name mode** (the default), the `ObjectType` GUID resolution is **conditional on which access right is set**:

| Access Right | GUID Resolution Order |
| --- | --- |
| `WriteProperty` | attribute GUID → property set GUID → (fallback: "Write all properties") |
| `ExtendedRight` | control access right GUID → (fallback: "Perform all application-specific operations") |
| `CreateChild` | class GUID → (fallback: "Create child objects of any type") |
| `DeleteChild` | class GUID → (fallback: "Delete child objects of any type") |
| `Self` | validated write GUID → (fallback: "Perform all validated writes") |

The `ObjectType` GUID is checked for the empty GUID to determine whether a specific schema object is targeted:

```powershell
if ($rule.ObjectType -eq [System.Guid]::Empty) {
    # No specific ObjectType — use the generic fallback description
} else {
    # Look up $rule.ObjectType against the appropriate schema dictionary
}
```

GUID lookups are performed against dictionaries populated from schema data (see the schema enumeration and GUID mapping details in Section 2, "LDAP Filters Used"). Each dictionary maps a `[System.Guid]` to a schema object name (e.g., attribute name, class name, control access right name). The lookup uses the dictionary's `.ContainsKey()` method and indexer to resolve the GUID to a human-readable name.

> **Version note — LINQ for schema dictionary filtering (Tier 3 / PowerShell 4.0+):** Where the implementation uses explicit loops to iterate through schema maps for GUID resolution (e.g., searching multiple dictionaries sequentially), on PowerShell 4.0+ (.NET 4.5+), `[System.Linq.Enumerable]::Where(...)` or `[System.Linq.Enumerable]::FirstOrDefault(...)` could be used for more concise filtering. On PowerShell 1.0–3.0, explicit `foreach` loops MUST be used. Since the baseline spec uses keyed dictionary lookups (not linear scans), LINQ provides minimal benefit for the primary resolution path but may be useful for diagnostic or raw-mode enumeration scenarios.

In **raw mode** (`-ShowRaw`), the GUID is resolved sequentially across all schema categories:

1. Class GUID → class name
2. Attribute GUID → attribute name
3. Control access right GUID → control access name
4. Property set GUID → property set name
5. Validated write GUID → validated write name

Raw mode displays hex values and symbolic names for the access rights:

```powershell
$hexRights = ([int]$rule.ActiveDirectoryRights).ToString("X8")
$symbolicRights = $rule.ActiveDirectoryRights.ToString()
```

The `.ToString("X8")` format specifier produces an 8-character zero-padded uppercase hexadecimal string (e.g., `"00000020"` for `WriteProperty`). The parameterless `.ToString()` on a `[Flags]` enum produces the symbolic name(s) (e.g., `"WriteProperty"` or `"ReadProperty, WriteProperty"`). Both `.ToString()` calls are .NET instance methods that work identically across all supported PowerShell versions.

### Inherited Object Type Resolution and Inheritance Scope

When in resolved-name mode and `ContainerInherit` is set in `InheritanceFlags`, the `InheritedObjectType` GUID is resolved against class GUIDs to determine which child object type the ACE applies to:

```powershell
if (($rule.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) -ne 0) {
    if ($rule.InheritedObjectType -ne [System.Guid]::Empty) {
        # Resolve InheritedObjectType against class GUIDs
        # → "on all {class_name} child objects"
    } else {
        # → "on all child objects"
    }

    if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0) {
        # Append "and the container itself"
    }
}
```

- "on all {class_name} child objects" if `InheritedObjectType` resolves to a class
- "on all child objects" otherwise
- "and the container itself" is appended if `InheritOnly` is NOT set in `PropagationFlags`

When `ContainerInherit` is not set, no inheritance scope text is included.

---

## 9. Data Processing and Transformation Pipeline

### Step 1: Connection and Bootstrap

- Establish connection via managed .NET APIs: by default, `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()` and `[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()` use the Windows DC locator (AD sites and services) for site-aware DC discovery. When `-Server` is specified, use `New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList ([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::DirectoryServer), $serverName` with `[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)` and `[System.DirectoryServices.ActiveDirectory.Forest]::GetForest($context)` to route through the specified DC.
- Read RootDSE for naming contexts and schema/configuration DNs
- **Domain enumeration and SID collection**: Use `[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Domains` (or `[System.DirectoryServices.ActiveDirectory.Forest]::GetForest($context).Domains` with `-Server`) to enumerate all domains in the forest — this is the authoritative runtime source for the known-domain-NC set (see Section 1, "Known Domain NC Definition"). For each `Domain` object, obtain a `DirectoryEntry` via `$entry = $domain.GetDirectoryEntry()`. The returned `DirectoryEntry` implements `IDisposable` and holds unmanaged ADSI handles, so it MUST be disposed after use. Since `try/finally` MUST NOT be used (see Section 1), disposal MUST be performed using the `trap`-based error handling pattern: place `$entry.Dispose()` after the error-prone property accesses within the same scope as a `trap { }` statement, so that `.Dispose()` is reached during normal control flow.

    Read `Properties["objectSid"]` — note that `Properties["objectSid"]` returns a `PropertyValueCollection`, so the value must be indexed and cast:

    ```powershell
    $sidBytes = [byte[]]$entry.Properties["objectSid"][0]
    $domainSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $sidBytes, 0
    ```

    The domain's DN can be read from `$entry.Properties["distinguishedName"][0]` within the same scope. This collects SIDs for **all** known domain NCs — not just the current domain — which is required for deleted-trustee detection (Section 7) and per-domain SDDL alias expansion (Step 4). The `Domain.Name` property provides the DNS name.

- **NetBIOS name mapping**: Since `Domain` objects do not expose NetBIOS names directly, query `CN=Partitions,<configurationNamingContext>` via `DirectorySearcher` with filter `(&(objectClass=crossRef)(nCName=*)(nETBIOSName=*))` to retrieve the `nETBIOSName` for each domain NC, and map them to the `Forest.Domains` set collected above by matching each `crossRef` object's `nCName` to the corresponding domain's distinguished name. This reconciles the `crossRef`-based definition from Section 1 with the managed API enumeration — both should produce the same set of domain NCs.

- **Progress output**: Report connection status using `[System.Console]::Error.WriteLine()`:

    ```powershell
    [System.Console]::Error.WriteLine(
        [string]::Format("[*] Connected to {0}", $targetServer)
    )
    ```

    where `$targetServer` is the `-Server` value if specified, or the domain controller hostname obtained via `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name` when using the default DC locator path.

> **Progress and diagnostic output — stream selection:** All progress and diagnostic messages MUST go to stderr, not stdout, to ensure clean stdout separation for CSV data. The following approaches are available in PowerShell:
>
> | Approach | Availability | Behavior |
> | --- | --- | --- |
> | `[System.Console]::Error.WriteLine()` | All PS versions | Writes to stderr in all versions; most consistent with the original specification's `Console.Error` behavior |
> | `Write-Warning` | PS 2.0+ | Writes to the warning stream (stream 3 in PS 3.0+); visible by default but suppressible via `$WarningPreference` |
> | `Write-Host` | All PS versions | In PS 5.0+ writes to the information stream (stream 6); in PS 1.0–4.0 writes directly to the host and cannot be redirected |
> | `Write-Verbose` / `Write-Debug` | PS 2.0+ | Available for optional verbosity levels; require `-Verbose` / `-Debug` to display |
>
> **Recommendation:** Use `[System.Console]::Error.WriteLine()` for all progress and diagnostic output (e.g., `[*]` status lines, periodic scan progress). This writes to stderr in all PowerShell versions, maintaining clean stdout for CSV data — matching the original specification's design where CSV goes to stdout and diagnostics go to stderr. `Write-Verbose` and `Write-Debug` (PS 2.0+) are appropriate for optional verbosity levels but are not suitable for default progress output because they are suppressed by default.

### Step 2: Schema Loading

- Enumerate all schema classes via `[System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetCurrentSchema().FindAllClasses()` (or `[System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetSchema($context).FindAllClasses()` with `-Server`) for class GUIDs (`SchemaGuid`) and `DefaultObjectSecurityDescriptor` SDDL strings
- Enumerate all schema attributes via `[System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetCurrentSchema().FindAllProperties()` (or `.GetSchema($context).FindAllProperties()` with `-Server`) for attribute GUIDs (`SchemaGuid`)
- Query `controlAccessRight` objects via `DirectorySearcher` on the Configuration NC for property sets (`validAccesses=48`), validated writes (`validAccesses=8`), and control access rights (`validAccesses=256`)
- Report progress:

    ```powershell
    [System.Console]::Error.WriteLine(
        [string]::Format("[*] Schema loaded: {0} classes, {1} attributes, {2} extended rights",
            $classCount, $attrCount, $rightCount)
    )
    ```

### Step 3: Delegation and Template Loading

- **Load built-in delegation definitions.** In the archived C# specification, built-in definitions were loaded from embedded assembly resources via `Assembly.GetManifestResourceStream()`. In PowerShell, embedded assembly resources are not available. Instead, the tool MUST use one of the following approaches to load built-in delegation definitions:

    1. **Separate XML file distributed with the script (recommended):** Store built-in definitions in an XML file (e.g., `delegations-builtin.xml`) alongside the script. Load using:

        ```powershell
        $xml = New-Object -TypeName System.Xml.XmlDocument
        $xml.Load($builtinXmlPath)
        ```

        This approach provides the best maintainability: delegation definitions can be reviewed, edited, and version-controlled independently of the script logic.

    2. **Inline here-string in the script itself (fallback for single-file deployment):** Embed the XML content as a string literal in the script and parse it directly:

        ```powershell
        $xmlString = @"
        <adeleg>
          <delegation name="..." builtin="true" trustee="...">
            <location>...</location>
            <ace type="Allow" rights="..." objectType="..." />
          </delegation>
        </adeleg>
        "@
        $xml = New-Object -TypeName System.Xml.XmlDocument
        $xml.LoadXml($xmlString)
        ```

        This enables single-file deployment without external dependencies but makes editing delegation definitions harder.

    3. **`DATA` section (PS 2.0+):** PowerShell 2.0 and later support `DATA` sections for embedding static data. However, `DATA` sections are not available in PowerShell 1.0 and provide limited benefit over here-strings for XML content. This approach is NOT RECOMMENDED for cross-version compatibility.

    > **Recommendation:** Use approach (1) — a separate XML file — as the primary mechanism. This aligns with the tool's existing support for user-provided XML files (`-Delegations`, `-Templates`) and enables the same XSD validation path for both built-in and user-provided definitions. Approach (2) may be used as a fallback when single-file distribution is required.

- **Reading XML file content across PowerShell versions:** The `[System.Xml.XmlDocument].Load($path)` method works in all PowerShell versions and is the recommended approach for loading XML from files. For scenarios where XML content must be read as a string first (e.g., for preprocessing), use version-conditional logic:

    > **Version note — `Get-Content -Raw` (PS 3.0+):** `Get-Content -Raw` reads an entire file as a single string. On PowerShell 1.0/2.0, use `[System.IO.File]::ReadAllText($path)` instead:
    >
    > ```powershell
    > $versionPS = Get-PSVersion
    > if ($versionPS.Major -ge 3) {
    >     $xmlContent = Get-Content -Path $xmlPath -Raw
    > } else {
    >     $xmlContent = [System.IO.File]::ReadAllText($xmlPath)
    > }
    > ```

- Optionally load user-provided templates (`-Templates`) and delegations (`-Delegations`) from external XML files, validated against XSD schema (see Section 11 for the validation mechanism)
- For each delegation, derive expected ACEs by resolving trustees and locations, and index them by SID → Location

### Step 4: Schema ACE Analysis

- For each `ActiveDirectorySchemaClass` with a `DefaultObjectSecurityDescriptor`:
  - Parse the SDDL string **once per known domain NC** (all domain NCs collected in Step 1). SDDL domain-relative aliases (e.g., `DA` for Domain Admins, `DU` for Domain Users, `PA` for Group Policy Creator Owners) resolve to different SIDs in each domain. Since `New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddlString` resolves aliases using only the calling process's security context (i.e., the current domain), the tool must manually substitute SDDL abbreviations with the appropriate domain's SIDs before parsing. Specifically, for each domain, replace per-domain aliases like `DA` → `S-1-5-21-<domain SID>-512`, `DU` → `S-1-5-21-<domain SID>-513`, etc. Forest-root-only aliases — `EA` (Enterprise Admins, RID 519) and `SA` (Schema Admins, RID 518) — must always resolve to the **forest root domain** SID regardless of which domain is being processed. Parse the substituted string via `New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $expandedSddl`. See Section 4 ("SDDL Parsing for Schema Defaults") for the complete alias substitution table.
  - Filter the DACL ACEs through the interest check logic
  - Store remaining ACEs as orphan ACEs in the result set

### Step 5: Explicit ACE Analysis

- For each naming context, perform a subtree search via `DirectorySearcher` with `Filter = "(objectClass=*)"`, `SearchScope = [System.DirectoryServices.SearchScope]::Subtree`, `PageSize = 1000`, `SecurityMasks = [System.DirectoryServices.SecurityMasks]::Owner -bor [System.DirectoryServices.SecurityMasks]::Dacl`

- **Critical: `SearchResultCollection` disposal.** `SearchResultCollection` returned by `$searcher.FindAll()` implements `IDisposable`. It MUST be disposed (via explicit `.Dispose()`) to release unmanaged LDAP result handles and prevent memory leaks during long scans. Since `try/finally` MUST NOT be used (see Section 1), the `SearchResultCollection` disposal MUST be handled using the `trap`-based error handling pattern: wrap the `FindAll()` call and its result iteration in a function following the `trap`-based pattern, with `$results.Dispose()` placed after the iteration loop within the same scope as the `trap { }` statement. This ensures `.Dispose()` is reached even if an error occurs during result processing. Additionally, `DirectorySearcher` and its `SearchRoot` `DirectoryEntry` both implement `IDisposable` and MUST also be disposed when no longer needed to avoid leaking ADSI/LDAP handles across multiple naming context iterations.

- For each object:
  - Parse the security descriptor via `ActiveDirectorySecurity` (see Section 4, "Security Descriptor Access")
  - Compute expected default ACEs from the schema class's `DefaultObjectSecurityDescriptor`
  - Filter each DACL ACE through the interest check, which excludes: inherited ACEs, read-only ACEs, schema default ACEs, AdminSDHolder ACEs, ignored trustee ACEs, and special-case ACEs
  - Record: owner, DACL protection status (via `AreAccessRulesProtected`), ACL canonicality, and orphan ACEs

- Report progress periodically using carriage-return-based overwrite:

    ```powershell
    [System.Console]::Error.Write(
        [string]::Format("`r[{0}] {1} objects processed...", $ncDN, $count)
    )
    ```

    > **Note:** The backtick-r (`` `r ``) is PowerShell's escape sequence for the carriage return character (`\r` in C#). `[System.Console]::Error.Write()` (not `WriteLine`) is used to overwrite the current line in-place, providing a continuously updating progress indicator without scrolling.

### Step 6: Post-Processing

1. **Memory optimization**: Remove records with no findings (no orphan ACEs, no owner issues, no warnings), but retain parent container records needed for CREATE_CHILD analysis.
2. **Deleted trustee detection**: For each unresolvable orphan ACE trustee across all naming contexts, check `$trusteeSid.AccountDomainSid` — if it matches **any** known domain SID (collected from all known domain NCs), move the ACE to the deleted trustee list. See Section 7 ("Deleted Trustee Detection") for the full algorithm.
3. **KDS root key handling**: Suppress DACL protection warnings for KDS root key objects in the Configuration partition.
4. **Owner analysis via CREATE_CHILD**: For each object with a non-ignored owner, walk up the container hierarchy checking if the owner has `CreateChild` permissions — if so, suppress the owner finding (the owner created the object). Group membership for this check uses the `tokenGroups` constructed attribute via `$entry.RefreshCache(@("tokenGroups"))`, which resolves transitive/nested group memberships. The `DirectoryEntry` used for the `RefreshCache` call MUST be disposed after use (see the resource cleanup pattern in Section 1).
5. **Parent object ACE suppression**: Remove ACEs whose trustees are parent objects (e.g., computers controlling their own BitLocker recovery objects).

### Step 7: Delegation Matching

1. For each expected delegation (built-in + user-defined), create or update a result entry, initially marking all expected ACEs as "missing".
2. For each location, match orphan ACEs against expected delegation ACEs using the ACE comparison function:
   - If a match is found, the ACE moves from orphan ACEs to found ACEs for that delegation
   - The corresponding expected ACE is removed from the missing list
   - One ACE can match multiple delegations
3. For built-in delegations, clear all missing ACEs (do not flag missing built-in ACEs).

### Step 8: CSV Generation

- Iterate over all results, sorted deterministically (see Section 10)
- For each entry, write CSV records for: errors/warnings, owner, DACL protection, non-canonical ACL, deleted trustees, orphan ACEs, and matched delegations
- Report final summary to stderr (and log file if `-Log` is active) using the format defined in Section 13.3 — `[i]` prefix, object/ACE/SD counts, and elapsed time formatted as `hh:mm:ss` (or `mm:ss` for scans under one hour):

    ```powershell
    [System.Console]::Error.WriteLine(
        [string]::Format("[i] Scan complete: {0} objects, {1} ACEs, {2} SDs in {3}",
            $objectCount, $aceCount, $sdCount, $elapsed)
    )
    ```

---

## 10. CSV Export Structure

### CSV Output Destination

The `-Csv <path>` command-line argument selects the destination for CSV output. If the path is `-`, output goes to stdout. Otherwise, a file is created (or truncated if it exists). If neither `-Csv` nor `-RiskCsv` (see Section 20.2) is specified, the tool writes CSV to stdout by default (equivalent to `-Csv -`). This ensures the tool always produces usable output, even when run without explicit output arguments.

### CSV Header Row

The CSV output includes a mandatory header row as the first line:

```text
Resource,Trustee,Trustee type,Category,Details,Risk Level,Current User Can Exploit
```

### CSV Schema

The CSV output has **7 columns**:

| Column | Name | Description |
| --- | --- | --- |
| 1 | **Resource** | The location where the delegation or finding applies. Either a DN (e.g., `OU=Users,DC=example,DC=com`), a schema reference (e.g., `Schema: default security descriptor of class 'user'`), or `Global` for non-location-specific findings |
| 2 | **Trustee** | The resolved name of the security principal (DN or `DOMAIN\Username`), or the raw SID string if unresolvable, or `Global` for non-trustee-specific `Warning` rows |
| 3 | **Trustee type** | One of: `User`, `Group`, `Computer`, `External`, or empty for non-trustee-specific rows (e.g., `Warning` rows where `Trustee` is `Global`) |
| 4 | **Category** | Classification of the finding (see below) |
| 5 | **Details** | Human-readable description of the permission or finding |
| 6 | **Risk Level** | A risk classification for the row. One of: `Critical`, `High`, `Medium`, `Informational`, or empty (blank) for rows that do not match any risk rule. See Section 18 for the classification matrix. |
| 7 | **Current User Can Exploit** | `Yes` if the ACE trustee SID matches the current user's SID or any of the current user's transitive group SIDs (see Section 19); empty (blank) otherwise. |

### Category Values

| Category | Meaning |
| --- | --- |
| `Owner` | The trustee owns the object, granting implicit full control |
| `Warning` | A structural issue (unreadable SD, blocked DACL inheritance, non-canonical ACL), a deleted trustee finding, or an AdminSDHolder anomaly |
| `Allow ACE` | An explicit allow ACE not explained by any known delegation |
| `Deny ACE` | An explicit deny ACE not explained by any known delegation |
| `Built-in` | A delegation matching a built-in definition (only shown with `-ShowBuiltin`) |
| `Delegation` | A delegation matching a user-defined definition |
| `Expected allow ACE found` | An individual allow ACE that was expected and found in place |
| `Expected deny ACE found` | An individual deny ACE that was expected and found in place |
| `Expected allow ACE missing` | An individual allow ACE that was expected but not found |
| `Expected deny ACE missing` | An individual deny ACE that was expected but not found |

### Deterministic Row Ordering

CSV rows are sorted deterministically using the following order:

1. **Primary sort**: Resource column, lexicographic string sort (includes DNs like `OU=Users,DC=example,DC=com`, schema references like `Schema: default security descriptor of class 'user'`, and `Global` for non-location-specific findings)
2. **Secondary sort**: Category column, by priority order: `Warning` → `Owner` → `Deny ACE` → `Allow ACE` → `Built-in` → `Delegation` → `Expected deny ACE found` → `Expected allow ACE found` → `Expected deny ACE missing` → `Expected allow ACE missing`
3. **Tertiary sort**: Trustee column, alphabetically

This deterministic ordering enables diff-based change tracking between runs.

> **Version note — sorting implementation:** `Sort-Object` is available in PowerShell 1.0+ and is the cross-version approach for implementing the deterministic sort. On PowerShell 4.0+ (.NET 4.5+), `[System.Linq.Enumerable]::OrderBy(...)` and `.ThenBy(...)` could be used as an alternative with custom comparers, but `Sort-Object` with multiple `-Property` expressions is sufficient and more idiomatic. The category priority ordering requires a custom sort expression that maps category strings to their numeric priority (e.g., `Warning` → 0, `Owner` → 1, `Deny ACE` → 2, etc.).

### Record Generation Logic

For each location/result pair in the scan results, the following record types are generated in this per-location output sequence:

1. **Per-location processing errors** (if `-ShowWarningUnreadable` is enabled; see Section 13 for CLI flag definitions): One `Warning` record with the error message. This covers any error entry in the results, including unreadable security descriptors, missing/unreadable `objectClass` attributes, and unparseable schema `defaultSecurityDescriptor` SDDL strings. The `Trustee` column is set to `Global` and the `Trustee type` column is empty.
2. **Owner**: One `Owner` record if the object's owner is not in the ignored trustee set and was not filtered by CREATE_CHILD analysis.
3. **DACL protection**: One `Warning` record if `AreAccessRulesProtected` is `$true` and the object is not in an excluded category. The `Trustee` column is set to `Global` and the `Trustee type` column is empty.
4. **Non-canonical ACL**: One `Warning` record if the ACL is not in canonical order. The offending ACE is described. The `Trustee` column is set to `Global` and the `Trustee type` column is empty.
5. **Deleted trustees**: One `Warning` record per ACE whose trustee no longer exists.
6. **AdminSDHolder anomalies**: One `Warning` record per AdminSDHolder-related anomaly detected for the location.
7. **Orphan ACEs**: One `Allow ACE` or `Deny ACE` record per unmatched ACE, with access rights described.
8. **Delegations**: For each matched delegation (built-in only if `-ShowBuiltin`):
   - One `Built-in` or `Delegation` record with the delegation description
   - One `Expected allow/deny ACE found` record per matched ACE, prefixed with "In delegation: "
   - One `Expected allow/deny ACE missing` record per unmatched expected ACE, prefixed with "In delegation: "

### Formatting and Encoding

- **Encoding**: UTF-8 without BOM. This MUST be specified explicitly because PowerShell's default encoding varies by version and is NOT UTF-8:

    | PowerShell Version | `Out-File` / `Set-Content` Default | Notes |
    | --- | --- | --- |
    | PS 1.0–5.1 | System locale encoding or UTF-16LE | NOT suitable for cross-platform CSV |
    | PS 7.x | UTF-8 (no BOM) | `Set-Content -Encoding UTF8NoBOM` is available |

    The `StreamWriter` approach described below is mandatory for consistent UTF-8 (no BOM) output across all supported PowerShell versions.

- **UTF-8 without BOM encoding object**:

    ```powershell
    $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    ```

- **File output** (when `-Csv` specifies a file path):

    ```powershell
    $stream = New-Object -TypeName System.IO.FileStream -ArgumentList $csvPath,
        ([System.IO.FileMode]::Create),
        ([System.IO.FileAccess]::Write),
        ([System.IO.FileShare]::Read)
    $writer = New-Object -TypeName System.IO.StreamWriter -ArgumentList $stream, $utf8NoBom
    ```

    The `FileStream` and `StreamWriter` MUST be disposed after all CSV rows are written. Since `try/finally` MUST NOT be used (see Section 1), use the `trap`-based error handling pattern to ensure `.Close()` is reached. `StreamWriter.Close()` flushes buffered output and disposes the underlying stream — omitting this risks truncating the final bytes:

    ```powershell
    trap {
        if ($null -ne $writer) { $writer.Close() }
        elseif ($null -ne $stream) { $stream.Close() }
    }

    # ... write CSV rows via $writer.WriteLine(...) ...

    $writer.Close()
    ```

- **Stdout output** (when `-Csv -` or default): Wrap `[System.Console]::OpenStandardOutput()` in a `StreamWriter`:

    ```powershell
    $stdoutStream = [System.Console]::OpenStandardOutput()
    $writer = New-Object -TypeName System.IO.StreamWriter -ArgumentList $stdoutStream, $utf8NoBom
    ```

    **Do NOT use `[System.Console]::Out` directly** for CSV output, as `[System.Console]::OutputEncoding` defaults to the system's OEM code page on Windows. The `StreamWriter` must be disposed (or at minimum flushed) after all CSV rows are written — `StreamWriter` buffers output internally, so omitting `.Flush()` / `.Close()` risks truncating the final bytes. The `trap`-based pattern above handles this.

    > **Important:** Do NOT use `Out-File`, `Set-Content`, or `Export-Csv` for CSV output. `Out-File` and `Set-Content` in PS 1.0–5.1 default to system locale encoding or UTF-16LE, NOT UTF-8. `Export-Csv` is NOT suitable because: (1) its output format varies by PowerShell version, (2) it adds `#TYPE` information headers by default in PS 2.0–5.1 (suppressible via `-NoTypeInformation` in PS 3.0+, but that parameter is unavailable in PS 1.0/2.0), and (3) it does not guarantee RFC 4180 compliance with CRLF line endings across all PS versions. The `StreamWriter` approach is the only reliable cross-version method for producing consistent UTF-8 (no BOM) CSV output.

- **RFC 4180 quoting rules**: CSV field quoting MUST be implemented manually. Fields containing commas, double-quotes, or newlines are enclosed in double-quotes. Embedded double-quotes are escaped as `""`. The line terminator is CRLF (`"`r`n"` in PowerShell). A minimal quoting function:

    ```powershell
    # Quotes a single CSV field value per RFC 4180.
    # Returns the field with appropriate quoting applied.
    function ConvertTo-CsvField {
        param (
            $Value
        )

        if ($null -eq $Value) {
            $text = ""
        } else {
            $text = [string]$Value
        }

        # Escape embedded double-quotes by doubling them
        $text = $text -replace '"', '""'

        # Always quote the field for consistency and safety
        return ('"' + $text + '"')
    }
    ```

    > **Note:** The function above unconditionally quotes all fields. While RFC 4180 only requires quoting for fields that contain commas, double-quotes, or CRLF, unconditional quoting is safe, simpler, and avoids edge-case bugs. This approach is consistent across all PowerShell versions.

    Row assembly joins quoted fields with the delimiter and writes via `$writer.WriteLine()`:

    ```powershell
    $fields = @()
    $fields += (ConvertTo-CsvField $resource)
    $fields += (ConvertTo-CsvField $trustee)
    # ... remaining fields ...
    $writer.WriteLine([string]::Join(",", $fields))
    ```

    > **Version note — `[PSCustomObject]` (Tier 2 / PS 3.0+):** When building structured result objects for sorting before CSV output, use `[PSCustomObject]@{...}` on PS 3.0+. On PS 1.0/2.0, use `New-Object -TypeName PSObject` with `Add-Member`:
    >
    > ```powershell
    > $record = New-Object -TypeName PSObject
    > $record | Add-Member -MemberType NoteProperty -Name "Resource" -Value $resource
    > $record | Add-Member -MemberType NoteProperty -Name "Trustee" -Value $trustee
    > # ... remaining properties ...
    > ```

### DN String Encoding

Distinguished Names in Active Directory can contain special characters (commas, plus signs, semicolons, angle brackets, equals signs, hash marks, backslashes). These characters appear as-is in the DN string within the CSV field. The RFC 4180 quoting rules handle the CSV-level escaping (DNs containing commas will be enclosed in double-quotes by the `ConvertTo-CsvField` function).

### Stdout and Stderr Separation

When `-Csv -` is used (or by default), CSV data goes to stdout via the `StreamWriter` wrapping `[System.Console]::OpenStandardOutput()`. All diagnostic and progress messages go to stderr via `[System.Console]::Error.WriteLine()` (see the progress output guidance in Section 9, Step 1). This ensures clean separation when using pipe redirection:

```text
powershell -File BigDACLEnergy.ps1 > output.csv 2> progress.log
```

---

## 11. Delegation and Template System

### Delegation and Template Format

Delegation and template definitions use **XML format** (not JSON), taking advantage of the `System.Xml` namespace available in .NET Framework 2.0 and all later versions.

### XML Parsing

In PowerShell, XML parsing uses the `System.Xml.XmlDocument` class with XPath-based navigation, which is more idiomatic than the `XmlSerializer` deserialization approach used in C#. The following approaches are available:

- **DOM-based access (recommended):** Create an `XmlDocument` explicitly and load from a file path or stream:

    ```powershell
    $xml = New-Object -TypeName System.Xml.XmlDocument
    $xml.Load($xmlPath)
    ```

    This approach works in all PowerShell versions (1.0+) and provides full XPath query support via `$xml.SelectNodes()` and `$xml.SelectSingleNode()`.

- **`[xml]` type accelerator (PS 2.0+):** Parse XML content from a string:

    ```powershell
    $xmlContent = [System.IO.File]::ReadAllText($xmlPath)
    $xml = [xml]$xmlContent
    ```

    The `[xml]` type accelerator is a shorthand for `[System.Xml.XmlDocument]` and is available in PowerShell 2.0 and later. On PowerShell 1.0, use the explicit `New-Object` approach above.

    > **Version note — `Get-Content -Raw` (PS 3.0+):** When reading XML content as a string, `Get-Content -Raw` is available on PS 3.0+ to read the entire file in one operation. On PS 1.0/2.0, use `[System.IO.File]::ReadAllText($path)` instead.

- **XPath navigation:** After loading, delegation and template elements are accessed via XPath queries rather than deserialization:

    ```powershell
    $delegations = $xml.SelectNodes("//delegation")
    foreach ($delegation in $delegations) {
        $name = $delegation.GetAttribute("name")
        $builtin = $delegation.GetAttribute("builtin")
        $trustee = $delegation.GetAttribute("trustee")

        $locations = $delegation.SelectNodes("location")
        $aces = $delegation.SelectNodes("ace")
        # ... process each delegation ...
    }
    ```

    This XPath-based approach replaces the `XmlSerializer` deserialization pattern from the C# specification and is the recommended approach for PowerShell.

### XSD Schema Validation

All XML files loaded by the tool — whether they contain delegation definitions, template definitions, risk classification configuration, or any combination thereof — are validated against the same `<adeleg>` XSD schema at load time. This includes standalone risk-configuration files that contain only `<unsafeTrustees>`, `<tier0Resources>`, or `<dangerousDelegations>` elements. Validation is performed by creating an `XmlReader` with validation settings and reading the document through it. The load-and-validate operation MUST be wrapped in a function following the `trap`-based error handling pattern (see Section 1) to both ensure resource cleanup AND detect validation failures:

```powershell
$settings = New-Object -TypeName System.Xml.XmlReaderSettings
[void]($settings.Schemas.Add($null, $xsdPath))
$settings.ValidationType = [System.Xml.ValidationType]::Schema

# Register a validation event handler that throws on schema violations.
# The scriptblock receives $sender and $eventArgs (ValidationEventArgs).
$settings.add_ValidationEventHandler({
    param ($sender, $eventArgs)
    throw $eventArgs.Exception
})

$reader = [System.Xml.XmlReader]::Create($xmlPath, $settings)
$doc = New-Object -TypeName System.Xml.XmlDocument

# Wrap the Load() call in a function that uses the trap-based error
# detection pattern. The function's trap { } suppresses the terminating
# error thrown by the validation handler, and Get-ReferenceToLastError /
# Test-ErrorOccurred detect whether the Load() failed.
$refLastKnownError = Get-ReferenceToLastError

$actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
$global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

trap { }
$doc.Load($reader)  # Validation occurs during Load

$global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

# Close/dispose the reader regardless of whether Load() succeeded or failed
$reader.Close()

$refNewestCurrentError = Get-ReferenceToLastError
if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
    # Validation failed — report the error and abort processing of this XML file.
    # $Error[0] contains the XmlSchemaValidationException with line number,
    # position, and inner exception context for precise error reporting.
}
```

> **Resource cleanup and error detection:** The `XmlReader` implements `IDisposable` and MUST be closed/disposed after use. Since `try/finally` MUST NOT be used (see Section 1), the `trap`-based error handling pattern serves dual purposes: (1) the empty `trap { }` suppresses the terminating error thrown by the validation event handler, allowing execution to continue to `$reader.Close()`, and (2) the `Get-ReferenceToLastError` / `Test-ErrorOccurred` helper functions (see Section 1, "Error handling via function wrappers") detect whether `$doc.Load($reader)` failed by comparing `$Error` stack references before and after the operation. This ensures both reliable resource cleanup AND reliable error detection — the load failure is not silently swallowed.

If the XML does not conform to the XSD schema, the `ValidationEventHandler` fires and throws the `XmlSchemaValidationException`, which preserves line number, position, and inner exception context for precise error reporting. The `Test-ErrorOccurred` check after `$reader.Close()` detects this failure and prevents invalid definitions from being processed. This provides formal structural validation without third-party libraries.

### Access Mask Representation

Delegation definitions use symbolic `ActiveDirectoryRights` enum names (e.g., `WriteProperty`, `ExtendedRight`, `CreateChild`) rather than raw numeric values. These are resolved at load time using `[System.Enum]::Parse()`:

```powershell
$rights = [System.Enum]::Parse(
    [System.DirectoryServices.ActiveDirectoryRights],
    $rightsName
)
```

> **Version note:** `[System.Enum]::Parse()` is a .NET static method available in all PowerShell versions (1.0+). It throws an `ArgumentException` if `$rightsName` is not a valid member of the `ActiveDirectoryRights` enum, which serves as input validation for delegation definitions.

### XML Schema Elements

The delegation XML schema defines:

- **`<delegation>`**: A delegation definition with attributes for `name`, `builtin` (boolean), `trustee` (SID or samAccountName), and child elements for locations and expected ACEs
- **`<location>`**: A location pattern (DN or wildcard) where the delegation applies
- **`<ace>`**: An expected ACE with attributes for `type` (Allow/Deny), `rights` (symbolic `ActiveDirectoryRights` names), `objectType` (GUID), `inheritedObjectType` (GUID)
- **`<template>`**: A template definition with `name`, `appliesTo` filters, and `rights` arrays

### Document-Level Structure

All XML files — whether containing delegation definitions, risk classification configuration, or both — must use a single root element: **`<adeleg>`**. This root element serves as the container for all top-level elements:

```xml
<adeleg>
  <!-- Delegation and template definitions -->
  <delegation name="..." builtin="true" trustee="...">
    <location>...</location>
    <ace type="Allow" rights="..." objectType="..." />
  </delegation>
  <template name="..." appliesTo="...">
    ...
  </template>

  <!-- Risk classification configuration (optional) -->
  <unsafeTrustees>
    <add sid="{domainSID}-513" />
  </unsafeTrustees>
  <tier0Resources>
    <add sid="{domainSID}-500" />
  </tier0Resources>
  <dangerousDelegations>
    <add rights="GenericAll" objectType="" category="A" description="Full control" />
  </dangerousDelegations>
</adeleg>
```

The `<adeleg>` root element may contain any combination of `<delegation>`, `<template>`, `<unsafeTrustees>`, `<tier0Resources>`, and `<dangerousDelegations>` child elements. All are optional — a file may contain only delegation definitions, only risk configuration, or both. The XSD schema (see XSD Schema Validation above) validates this structure: a file missing the `<adeleg>` root element, or containing unrecognized child elements, will fail validation.

### Risk Classification Configuration Schema

The XML schema defines elements for configuring risk classification rules (referenced by Sections 16.3.2, 16.4.3, and 17.4). These elements appear as children of the `<adeleg>` root element, either in the same XML files as delegation definitions or in separate configuration XML files:

- **`<unsafeTrustees>`**: Container for unsafe trustee definitions. Contains `<add>` and `<remove>` child elements.
  - **`<add sid="...">`**: Adds a SID to the unsafe trustee set. The `sid` attribute may contain a literal SID (e.g., `S-1-5-7`) or a pattern with a placeholder (e.g., `{domainSID}-513`). Patterns are expanded at runtime for each known domain.
  - **`<remove sid="...">`**: Removes a SID from the baseline unsafe trustee set. Uses the same SID/pattern syntax as `<add>`.

- **`<tier0Resources>`**: Container for Tier 0 resource definitions. Contains `<add>` and `<remove>` child elements.
  - **`<add>`**: Adds a resource to the Tier 0 set. Supports the following attributes (at least one of `sid`, `dn`, or `objectClass` is required):
    - `sid="..."` — Match by SID or SID pattern (e.g., `{domainSID}-500`)
    - `dn="..."` — Match by DN pattern (e.g., `CN=AdminSDHolder,CN=System,{domainDN}`)
    - `objectClass="..."` — Match by object class (e.g., `trustedDomain`)
    - `tier="..."` — Optional sub-tier label (e.g., `Tier0-Critical`, `Tier0-High`; defaults to `Tier0`)

    **Note:** XSD 1.0 (used by `XmlReader` schema validation on .NET Framework 2.0) cannot express the "at least one of `sid`/`dn`/`objectClass` must be present" constraint. In the XSD, all three attributes are declared `use="optional"`. The tool enforces this requirement via **runtime validation** after XSD validation: if an `<add>` element has none of `sid`, `dn`, or `objectClass`, the tool emits a clear error to stderr and exits with a nonzero code.
  - **`<remove>`**: Removes a resource from the baseline Tier 0 set. Uses the same attribute syntax as `<add>`.

- **`<dangerousDelegations>`**: Container for dangerous delegation type definitions. Contains `<add>` and `<remove>` child elements.
  - **`<add>`**: Adds a dangerous delegation type. Attributes:
    - `rights="..."` — Symbolic `ActiveDirectoryRights` name (e.g., `WriteProperty`, `ExtendedRight`)
    - `objectType="..."` — Object type GUID (or empty for `Guid.Empty`)
    - `category="..."` — Risk category: `A` (Full-Control), `B` (Dangerous Write), `C` (Control Access), `D` (Create/Delete), `E` (Validated Write)
    - `description="..."` — Human-readable description of the attack vector
    - `riskLevel="..."` — Optional custom risk level override (`Critical`, `High`, `Medium`, `Informational`)
  - **`<remove>`**: Removes a delegation type from the baseline dangerous set. Uses `rights` and `objectType` attributes to identify the entry to remove.

### Placeholder Expansion

Placeholders in SID and DN patterns use curly-brace syntax (`{domainSID}`, `{forestRootDomainSID}`, `{domainDN}`, `{forestRootDN}`) rather than angle brackets, avoiding the need for XML entity escaping. At runtime, these placeholders are expanded using string replacement:

```powershell
# Per-domain expansion — executed for each known domain NC
$expandedSid = $sidPattern -replace '\{domainSID\}', $domainSidString
$expandedDn = $dnPattern -replace '\{domainDN\}', $domainDN

# Forest-root expansion — executed once
$expandedSid = $expandedSid -replace '\{forestRootDomainSID\}', $forestRootSidString
$expandedDn = $expandedDn -replace '\{forestRootDN\}', $forestRootDN
```

> **Version note:** The `-replace` operator is available in all PowerShell versions (1.0+). Because `-replace` uses regular expressions, the curly braces in the placeholder patterns MUST be escaped with backslashes (`\{`, `\}`). Alternatively, `[string]::Replace()` can be used for literal string replacement without regex escaping:
>
> ```powershell
> $expandedSid = $sidPattern.Replace('{domainSID}', $domainSidString)
> ```
>
> Both approaches produce identical results. `[string]::Replace()` is slightly more readable for literal replacements; `-replace` is more flexible for pattern-based substitutions.

`{domainSID}` and `{domainDN}` are expanded for each known domain, `{forestRootDomainSID}` is expanded once using the forest root domain's SID (used for forest-root-only groups such as Schema Admins, Enterprise Admins, and Enterprise Key Admins), and `{forestRootDN}` is expanded using the forest root domain's DN. This is analogous to how delegation location wildcards (`DC=*`) are expanded (see Location Wildcards below).

### Location Wildcards

Delegation definitions support the following wildcard patterns for locations, which are expanded at load time:

| Pattern | Expansion |
| --- | --- |
| `DC=*` | Each domain's DN in the forest |
| `CN=Configuration,DC=*` | The Configuration naming context |
| `CN=Schema,DC=*` | The Schema naming context |
| `DC=DomainDnsZones,DC=*` | Expanded using each domain's DN |
| `DC=ForestDnsZones,DC=*` | Expanded using the root domain NC |

These are a closed set of supported patterns, not true glob-style wildcards.

### Resource Representation

Resources in the CSV `Resource` column are represented as:

- **Distinguished Names (DNs)**: Full LDAP DNs like `CN=Users,DC=example,DC=com`
- **Schema references**: Formatted as `Schema: default security descriptor of class '{className}'`
- **`Global`**: Used for non-location-specific findings

### Multi-Valued Attribute Handling

For multi-valued attributes:

- `objectClass`: The last value (most-specific class) is used for class determination. The ordering (most-specific-last) is relied upon as a standard AD behavior.
- `namingContexts`: All values are used (each represents a naming context to scan).
- Other multi-valued attributes: The specific handling depends on the attribute's purpose and is defined per-attribute where relevant.

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
