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

**Important**: SDDL domain-relative aliases (e.g., `DA` for Domain Admins, `DU` for Domain Users) resolve to different SIDs in each domain, while forest-root-only aliases (`EA` for Enterprise Admins, `SA` for Schema Admins) always resolve to the forest root domain's SID. Since `New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddlString` resolves aliases using only the calling process's security context (i.e., the current domain), schema default SDDL strings must be parsed **once per known domain NC** with manual alias substitution. See Step 4 in Section 9 for the full per-domain expansion mechanism.

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
