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

<!-- TODO: To be completed in a future work effort -->

---

## 2. Directory Query Mechanics

<!-- TODO: To be completed in a future work effort -->

---

## 3. Paging, Performance, and Query Configuration

<!-- TODO: To be completed in a future work effort -->

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
