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

For objects that are determined to be **AdminSDHolder-protected (SDProp in-scope)**, ACEs that appear in the AdminSDHolder DACL are suppressed. This is because SDProp periodically stamps (copies) the AdminSDHolder security descriptor onto protected principals.

#### Determining "AdminSDHolder-protected (SDProp in-scope)"

This tool MUST NOT use `adminCount` as the authoritative signal for AdminSDHolder/SDProp protection. The `adminCount` attribute is diagnostic — it is only set when SDProp actually modifies the security descriptor; it can be cleared or set arbitrarily, and it may remain null/0 even for SDProp-protected principals when the security descriptor already matches the AdminSDHolder template.

Instead, this tool MUST determine SDProp in-scope status using **SID-based** evaluation (not name-based), because names can be renamed or localized while SIDs remain stable.

An object is treated as AdminSDHolder-protected (SDProp in-scope) if and only if:

1. The object is a **security principal**, AND
2. The object is either:
   - one of the protected groups/accounts itself (by `objectSid`), OR
   - a direct or transitive member of a protected group (nested membership).

SDProp in-scope evaluation is conceptually **tri-state**:

1. **In-scope** — the tool has positively determined that the object is SDProp-protected per the rules above.
2. **Not in-scope** — the tool has positively determined that the object is *not* SDProp-protected per the rules above.
3. **Undetermined** — the tool cannot reliably determine SDProp status (for example, due to permissions errors, data gaps, or other failures).

For **suppression behavior only**, if SDProp in-scope status is **Undetermined** the tool MUST **fail-safe** and treat the object as **not protected for suppression purposes** (i.e., it MUST NOT suppress ACEs based on SDProp, and MUST report those ACEs).

For **AdminSDHolder anomaly detection**, the tool:

- MUST emit `AdminSDHolder anomaly: stale adminCount` or corresponding "cleared" anomalies **only** when SDProp status is explicitly **In-scope** or **Not in-scope**, and
- MUST NOT emit any AdminSDHolder stale/cleared anomaly rows when SDProp status is **Undetermined**.

**Operator-configured additional suppression:** Separately from the authoritative SDProp in-scope definition above, the tool MUST support an operator-configurable list of additional SIDs whose ACEs should also be suppressed against the AdminSDHolder template, via the suppression-override SID list, as further described in the *Protected Set Data* section below. This override mechanism does not change the tool's SDProp in-scope determination, but only adds additional SIDs to the suppression set. Objects matched only by this override list are not treated or reported as SDProp in-scope in any SDProp-related reporting/telemetry described in this specification (including AdminSDHolder anomaly `Warning` rows).

##### Security principal scope

Only evaluate SDProp in-scope status for security principals. At minimum include:

- `user`
- `group`
- `computer`
- `msDS-ManagedServiceAccount`
- `msDS-GroupManagedServiceAccount`
- `foreignSecurityPrincipal` (cross-domain members)

Do NOT use `objectCategory=person` as a shortcut without explicit exclusion of non-security principals (e.g., `contact`). Prefer explicit object classes and presence of `objectSid`.

##### Protected Set Data (authoritative baseline)

The tool MUST define the **authoritative protected set** by **SID**, not by name, in a versioned data artifact (e.g., JSON/YAML/XML) shipped with the tool. This authoritative protected-set data is the **only** source used to determine whether an object is SDProp in-scope.

The tool MUST also support a **separate operator-configurable suppression-override SID list** for customized environments. This override list MAY be used to adjust or extend suppression/filtering behavior but MUST NOT be treated as part of the SDProp protected set and MUST NOT affect SDProp in-scope determination.

Baseline protected set (minimum):

| SID | Identity |
| --- | --- |
| `S-1-5-32-544` | BUILTIN\Administrators |
| `S-1-5-32-548` | BUILTIN\Account Operators |
| `S-1-5-32-549` | BUILTIN\Server Operators |
| `S-1-5-32-550` | BUILTIN\Print Operators |
| `S-1-5-32-551` | BUILTIN\Backup Operators |
| `<domain SID>-512` | Domain Admins |
| `<forest root domain SID>-518` | Schema Admins (forest root domain) |
| `<forest root domain SID>-519` | Enterprise Admins (forest root domain) |

Optional explicit protected accounts (enabled by default; configurable):

| SID | Identity |
| --- | --- |
| `<domain SID>-500` | Administrator |
| `<domain SID>-502` | KRBTGT |

> **Forest scope requirement:** In multi-domain forests, `<domain SID>` and `<forest root domain SID>` may differ. The tool MUST determine the forest root domain SID (i.e., `<forest root domain SID>`) to correctly evaluate `…-518` (Schema Admins) and `…-519` (Enterprise Admins). The forest root domain DN is available via RootDSE's `rootDomainNamingContext` attribute (see Section 1); its SID is obtained by resolving that DN to a domain object and reading its `objectSid`. If the forest root domain SID cannot be determined, the tool MUST fail-safe — the SDProp evaluation status for Schema Admins and Enterprise Admins MUST be treated as **Undetermined** (their SIDs cannot be evaluated). Objects that would only be protected via those groups therefore inherit an **Undetermined** SDProp status: this Undetermined state MUST be used only to disable suppression based on those groups and MUST NOT cause AdminSDHolder anomalies (including `stale adminCount`) to be emitted solely due to this condition.

##### Protected set candidates (future authoritative baseline; non-authoritative via configuration)

Some environments track additional SIDs as *candidate* SDProp-relevant identities (e.g., Domain Controllers `…-516`, RODCs `…-521`, Cert Publishers `…-517`, BUILTIN\Replicator `S-1-5-32-552`). These candidates are **not** part of the authoritative protected set unless and until they are shipped in a new versioned protected-set artifact. Operator configuration MUST NOT promote these candidates (or any other SIDs) into the authoritative protected set or otherwise affect SDProp in-scope determination. Operators MAY reference candidate SIDs in the suppression-override list to extend AdminSDHolder-template ACE suppression to members of those groups. Objects matched only by the suppression-override list (and not by the authoritative protected set) receive AdminSDHolder-template ACE suppression but are NOT treated as SDProp in-scope — they do not participate in AdminSDHolder anomaly detection or any other SDProp-related reporting.

##### Anti-pattern: never protect entire domain

Do NOT include Domain Users (`…-513`), Domain Guests (`…-514`), or Domain Computers (`…-515`) in the protected set; doing so would classify most/all principals as protected and suppress meaningful findings.

##### Membership evaluation requirements

Membership evaluation MUST:

- Be transitive (nested groups).
- Handle primary group semantics (`memberOf` does not include the primary group; `primaryGroupID` must be evaluated separately).
- Handle cross-domain/foreign security principals as feasible.
- Fail-safe (undetermined → no suppression).

##### Allowed membership evaluation approaches

**1) Token-based (preferred):**

- Read `tokenGroups` and evaluate presence of protected SIDs.
- `tokenGroupsGlobalAndUniversal` MAY be used only as a supplement; it MUST NOT be the sole source because it can omit domain-local memberships.
- Do not rely on filtering/searching using `tokenGroups` in LDAP queries; treat it as a per-object read.

**2) Directory expansion:**

- Resolve protected group SIDs to group DNs first (SID → object → DN), then evaluate transitive membership (e.g., chain rule) using the DN.
- Do not embed raw SIDs into `memberOf` chain matching; `memberOf` compares DNs.
- If using `memberOf` traversal, explicitly compute and include the principal's primary group via `primaryGroupID`.

##### Performance guidance

For scale, prefer:

- Precompute transitive membership for protected groups once (per domain/forest), produce a set-membership structure of protected principal SIDs that supports O(1) membership checks (e.g., `HashSet[string]` on PowerShell 3.0+ where `HashSet<T>` is available, or `Dictionary[string,bool]` on PowerShell 1.0/2.0), then do per-object checks against this structure.
- Cache: domain SID, forest-root domain SID, protected group SID → group DN (if doing DN-based chain matching).
- Fail-safe rule still applies: incomplete precompute → no suppression for affected objects.

##### `adminCount` treated as diagnostic only

The `adminCount` attribute is parsed as an integer:

```powershell
$adminCount = 0
if ($result.Properties.Contains("adminCount")) {
    $adminCount = [int]$result.Properties["adminCount"][0]
}
```

However, `adminCount` MUST NOT be used for ACE suppression decisions. It is retained in the data collection solely for the anomaly findings described below.

##### AdminSDHolder anomaly findings

The tool MUST emit AdminSDHolder anomaly findings as `Warning`-category CSV rows (see Section 10, Category Values). Each anomaly row uses the following format:

| Column | Value |
| --- | --- |
| **Resource** | The DN of the affected principal |
| **Trustee** | `Global` (these are object-level findings, not trustee-specific) |
| **Trustee type** | empty |
| **Category** | `Warning` |
| **Details** | Prefixed with `AdminSDHolder anomaly:` followed by a short description (see below) |
| **Risk Level** | empty (consistent with all other Warning-category rows — see Section 18.4) |
| **Current User Can Exploit** | empty |

Two anomaly conditions are defined:

- **`AdminSDHolder anomaly: stale adminCount`** — `adminCount != 0` but the principal is explicitly Not in-scope for SDProp by SID/membership evaluation. This may indicate a formerly-protected principal whose `adminCount` was never cleared.
- **`AdminSDHolder anomaly: cleared adminCount`** — The principal is explicitly In-scope for SDProp by SID/membership evaluation but `adminCount` is null/0. This may indicate that the security descriptor already matched the AdminSDHolder template when SDProp last ran, so `adminCount` was not set.

These anomaly conditions MUST be evaluated only for principals whose SDProp in-scope status has been successfully determined by SID/membership evaluation. If SDProp in-scope evaluation is incomplete or indeterminate for a principal (for example, due to missing membership data or permission errors), the implementation MUST NOT emit any AdminSDHolder anomaly CSV row for that principal.

Emission of these CSV rows MUST NOT depend on the `-Verbose` setting. Implementations MAY additionally log a summary count of AdminSDHolder anomalies to stderr when verbose output is enabled (for example, via the `-Verbose` common parameter).

These findings help operations/security teams identify AdminSDHolder hygiene issues, but MUST NOT affect ACE suppression decisions.

##### Offline/CSV prerequisites

If suppression depends on comparing ACEs to the AdminSDHolder template DACL, the data collection MUST include:

- `CN=AdminSDHolder,CN=System,<domainDN>` with its full `nTSecurityDescriptor` (or equivalent export fields).
- Sufficient attributes to evaluate protected status: `objectSid`, group membership inputs (`tokenGroups` if used, or enough membership data to expand group nesting), `primaryGroupID` (if using `memberOf`-based expansion).
- `computer` objects (needed if DC/RODC-related candidates are later enabled).
- Disabled accounts (e.g., KRBTGT should not be filtered out).

**Fail-safe:** If the AdminSDHolder template security descriptor cannot be retrieved, do not suppress "template ACEs" — report them instead.

### Ignored Control Access Rights

ACEs granting only `ExtendedRight` for specific control access rights that do not grant meaningful control over a resource are suppressed:

- `Apply Group Policy` — applying a GPO does not mean controlling it
- `Allow a DC to create a clone of itself` — if an attacker can impersonate a DC, cloning is not the primary concern

### Ignored DACL Protected Flags

DACL inheritance blocking (detected via `$security.AreAccessRulesProtected`) is not reported as a warning for:

- Objects of class `groupPolicyContainer` (GPOs block inheritance by design)
- Objects that are determined to be **AdminSDHolder-protected (SDProp in-scope)** (expected to have inheritance blocked as part of AdminSDHolder protection; see [Determining "AdminSDHolder-protected (SDProp in-scope)"](#determining-adminsdholder-protected-sdprop-in-scope) above)
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

### Foreign Security Principals (SID Resolution)

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
