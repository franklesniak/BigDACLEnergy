# Active Directory Delegation Analysis Tool — Technical Specification

## Table of Contents

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

## 1. Active Directory Scope and Query Locations

### Naming Contexts Queried

The tool queries the following Active Directory partitions, discovered dynamically at runtime from the RootDSE:

| Partition | RootDSE Attribute | Purpose |
|---|---|---|
| Schema | `schemaNamingContext` | Retrieve class definitions, attribute definitions, default security descriptors |
| Configuration | `configurationNamingContext` | Retrieve extended rights, control access rights, validated writes, property sets |
| All naming contexts | `namingContexts` | Scan every object in each naming context (including schema, configuration, domain, and application partitions) for explicit (non-inherited) ACEs |
| Root domain | `rootDomainNamingContext` | Used as a fallback domain reference |

### RootDSE Bootstrap

On startup, the tool reads the RootDSE to retrieve essential directory metadata:

```csharp
using (DirectoryEntry rootDSE = new DirectoryEntry("LDAP://RootDSE"))
{
    // Read attributes and use rootDSE within this scope
}
```

`DirectoryEntry` implements `IDisposable` and must be disposed after use (e.g., via `using`) to avoid leaking unmanaged ADSI handles. This applies to all `DirectoryEntry` instances throughout the tool.

The following attributes are read from the RootDSE:

- `namingContexts` — the list of all naming contexts hosted by the server
- `schemaNamingContext` — the DN of the Schema partition
- `configurationNamingContext` — the DN of the Configuration partition
- `rootDomainNamingContext` — the DN of the forest root domain

When targeting a specific server, the path format is `"LDAP://serverName/RootDSE"`.

The `supportedControl` attribute is not required, as .NET Framework 2.0's `DirectorySearcher.SecurityMasks` handles SD flags control transparently.

### Known Domain NC Definition

A naming context is classified as a "known domain NC" if it appears as the `nCName` attribute of a `crossRef` object in `CN=Partitions,<configurationNamingContext>` that also has a `nETBIOSName` attribute. This distinguishes domain naming contexts from application partitions and other non-domain NCs.

**Authoritative source**: The known-domain-NC set is built from `Forest.Domains` (see Step 1 in Section 9), which returns all domain NCs in the forest. The `crossRef` query against `CN=Partitions` is used only to retrieve `nETBIOSName` values (since the `Domain` class does not expose NetBIOS names), and the results are matched back to the `Forest.Domains` set by `nCName` ↔ DN. Both sources should produce the same domain set; the `crossRef` definition above provides the formal classification criteria, while `Forest.Domains` is the runtime enumeration mechanism. This same set is used consistently for AdminSDHolder selection, deleted-trustee detection, per-domain SDDL expansion, and all other domain-scoped operations.

### Recursive Traversal

- **Schema partition**: Enumerated via `ActiveDirectorySchema.GetCurrentSchema().FindAllClasses()` and `FindAllProperties()` for class GUIDs, attribute GUIDs, and default security descriptors.
- **Configuration partition**: Queried with `DirectorySearcher` using `SearchScope.Subtree` to enumerate `controlAccessRight` objects for property sets, validated writes, and control access rights.
- **Each naming context** (including schema, configuration, domain, and application partitions): Queried with `DirectorySearcher` using `Filter = "(objectClass=*)"` and `SearchScope = SearchScope.Subtree`, which returns every object in the partition recursively.
- **AdminSDHolder**: Accessed via `new DirectoryEntry("LDAP://CN=AdminSDHolder,CN=System,<domainDN>")` when the naming context is a known domain NC; otherwise `new DirectoryEntry("LDAP://CN=AdminSDHolder,CN=System,<rootDomainNamingContext>")`. When `--server` is specified, the server prefix is included: `"LDAP://serverName/CN=AdminSDHolder,..."`.
- **Individual SID lookups**: Performed via `new DirectoryEntry("LDAP://<SID=S-1-5-...>")`. When `--server` is specified, the server prefix is included: `"LDAP://serverName/<SID=...>"`.

---

## 2. Directory Query Mechanics

### Domain Controller Discovery and Connection

The tool uses .NET Framework 2.0 managed APIs for DC discovery:

| Behavior | Implementation |
|---|---|
| Auto-discover a DC for the current domain | `Domain.GetCurrentDomain()` returns a `Domain` object with an auto-selected DC |
| Auto-discover forest-level topology | `Forest.GetCurrentForest()` returns the forest with all domains and sites |
| Connect to a specific server | `new DirectoryEntry("LDAP://serverName")` — connection is established lazily on first property access |
| Specify a port number | Encoded in the LDAP path: `"LDAP://serverName:636"` for LDAPS. **Note:** the port number alone does not enable TLS — `AuthenticationTypes.SecureSocketsLayer` must also be set (see LDAPS section below) |
| Failure on non-domain-joined machine | `Domain.GetCurrentDomain()` throws `ActiveDirectoryObjectNotFoundException`; the tool must catch this and report a clear error message |

The tool should default to using `Domain.GetCurrentDomain()` for DC discovery (which uses the Windows DC locator, i.e., AD sites and services native functionality, to select an optimal DC). An optional `--server` CLI argument allows targeting a specific DC. When `--server` is specified, all directory operations must be routed through that server for consistency:

- **Managed API context**: Use `new DirectoryContext(DirectoryContextType.DirectoryServer, serverName)` to construct `Domain.GetDomain(ctx)`, `Forest.GetForest(ctx)`, and `ActiveDirectorySchema.GetSchema(ctx)` objects, ensuring DC locator routes through the specified server.
- **DirectoryEntry paths**: All `DirectoryEntry` LDAP paths must include the server prefix, e.g., `"LDAP://serverName/RootDSE"`, `"LDAP://serverName/CN=AdminSDHolder,..."`, `"LDAP://serverName/<SID=...>"`.
- **DirectorySearcher instances**: The `SearchRoot` `DirectoryEntry` must include the server prefix when `--server` is specified.

**General principle**: Prefer .NET Framework 2.0 managed classes (`Domain`, `Forest`, `ActiveDirectorySchema`, `DirectoryContext`) over raw LDAP paths wherever possible. These managed classes use the Windows DC locator for site-aware DC selection automatically, and respect `DirectoryContext` for explicit server targeting. Raw LDAP paths (via `DirectoryEntry`) should only be used when no managed equivalent exists (e.g., AdminSDHolder access, SID-based lookups, reading specific object attributes not exposed by managed classes).

### Authentication

| Behavior | Implementation |
|---|---|
| Use current Windows SSO (Negotiate/SSPI) | `new DirectoryEntry(path)` — uses the process identity automatically |
| Explicit credentials | `new DirectoryEntry(path, username, password, AuthenticationTypes.Secure)` |
| Interactive password entry (`--password *`) | Read password via `Console.ReadKey(true)` in a loop, pass to `DirectoryEntry` constructor |

### LDAP Filters Used

| Query Target | Filter | Attributes Requested |
|---|---|---|
| Property sets | `(&(objectClass=controlAccessRight)(validAccesses=48)(rightsGuid=*))` | `rightsGuid`, `displayName` |
| Validated writes | `(&(objectClass=controlAccessRight)(validAccesses=8)(rightsGuid=*))` | `rightsGuid`, `displayName` |
| Control access rights | `(&(objectClass=controlAccessRight)(validAccesses=256)(rightsGuid=*))` | `rightsGuid`, `displayName` |
| All naming contexts (main scan) | `(objectClass=*)` | `nTSecurityDescriptor`, `objectClass`, `objectSid`, `adminCount`, `msDS-KrbTgtLinkBl`, `serverReference`, `distinguishedName` |
| AdminSDHolder | `(objectClass=*)` | `nTSecurityDescriptor` |
| Domain enumeration (partitions) | `(&(objectClass=crossRef)(nCName=*)(nETBIOSName=*))` | `nCName`, `nETBIOSName` |

Schema classes and attributes are enumerated via `ActiveDirectorySchema.GetCurrentSchema().FindAllClasses()` and `FindAllProperties()` respectively, rather than via direct LDAP queries. Each `ActiveDirectorySchemaClass` provides `.SchemaGuid`, `.Name` (the `lDAPDisplayName`), and `.DefaultObjectSecurityDescriptor` (SDDL string). Each `ActiveDirectorySchemaProperty` provides `.SchemaGuid` and `.Name`.

Extended rights, property sets, and validated writes are not directly exposed by `ActiveDirectorySchema` and must be queried via `DirectorySearcher` on the Configuration NC using the LDAP filters listed above.

### Referral Handling

LDAP referrals are disabled:

```csharp
searcher.ReferralChasing = ReferralChasingOption.None;
```

**Rationale:** Disabling referrals prevents hanging when running the tool from outside the domain or when DNS cannot resolve referral targets.

**Cross-domain implication:** With referrals disabled, the tool will not automatically follow cross-domain references within the same forest. Objects referenced from other domains will not be resolved via referral chasing. Unfollowed referrals may surface as missing results or errors depending on the specific operation. This is an acceptable trade-off for connection reliability.

### LDAPS and Encrypted Transport

The tool uses `AuthenticationTypes.Secure` by default, which provides SSPI-negotiated authentication (typically Kerberos or NTLM). `Secure` guarantees authenticated binding but does **not** guarantee encryption or integrity protection — signing and sealing are negotiated separately and depend on domain controller and client policies. In most Active Directory environments, Kerberos with signing and sealing is the negotiated result, but this is not guaranteed by the flag alone. For environments that require guaranteed TLS-based transport encryption:

- LDAPS is supported via path syntax: `"LDAP://server:636"` with `AuthenticationTypes.Secure | AuthenticationTypes.SecureSocketsLayer` (combining both flags ensures SSPI/Kerberos/NTLM authentication is preserved over the TLS channel; using `SecureSocketsLayer` alone may fall back to simple bind depending on how credentials are supplied)
- Certificate validation is handled automatically by the Windows trusted CA certificate store
- No custom certificate validation code or P/Invoke is needed

### Connection Endpoints

DC discovery is handled by `Domain.GetCurrentDomain()` and `Forest.GetCurrentForest()`, which use the Windows DC locator (AD sites and services) for site-aware DC selection. The `--server` CLI option allows explicit server targeting via `DirectoryContext(DirectoryContextType.DirectoryServer, serverName)`. Global Catalog access uses the `GC://` provider (`"GC://server"`), though the tool's operations primarily use the standard LDAP provider.

---

## 3. Paging, Performance, and Query Configuration

### Paged Search

All LDAP searches use paged results via `DirectorySearcher.PageSize`:

```csharp
searcher.PageSize = 1000;
```

Setting `PageSize` to a nonzero value enables transparent paging — `DirectorySearcher.FindAll()` handles page control creation, cookie management, and continuation automatically. The value 1000 is the default AD `MaxPageSize` policy limit. Environments with custom `MaxPageSize` policies may require a different value.

### Security Descriptor Retrieval Control

The `DirectorySearcher.SecurityMasks` property controls which parts of the security descriptor are retrieved:

- **Main scan**: `SecurityMasks.Owner | SecurityMasks.Dacl` — retrieves only the owner and DACL
- **AdminSDHolder**: `SecurityMasks.Dacl` — retrieves only the DACL

This replaces the manual `LDAP_SERVER_SD_FLAGS_OID` control and reduces data transfer by excluding the SACL and the security descriptor's Group SID field (not to be confused with the separate `primaryGroupID` attribute).

### Timeouts

- `DirectorySearcher.ClientTimeout` — maximum time the client waits for search results
- `DirectorySearcher.ServerTimeLimit` — maximum time the server spends processing a query

The tool should set reasonable timeout values and report a clear error message if a timeout occurs.

### Attribute Selection

Only the specific attributes needed are requested via `DirectorySearcher.PropertiesToLoad`:

```csharp
searcher.PropertiesToLoad.AddRange(new string[] {
    "nTSecurityDescriptor", "objectClass", "objectSid",
    "adminCount", "msDS-KrbTgtLinkBl", "serverReference",
    "distinguishedName"
});
```

This reduces network traffic compared to retrieving all attributes. The `distinguishedName` attribute is included because it is needed for CSV Resource values (the object's DN), SID → DN cache population, and progress reporting. While .NET's `SearchResult.Path` (ADsPath) also encodes the DN, it includes the LDAP URI prefix and server name, requiring parsing to extract the bare DN — explicitly requesting `distinguishedName` via `PropertiesToLoad` provides the DN directly and avoids ambiguity.

---

## 4. Security Descriptor Retrieval and ACE Processing

### Security Descriptor Access

Security descriptors are accessed through .NET Framework 2.0 managed APIs exclusively. No raw Windows API calls (`IsValidSecurityDescriptor`, `GetSecurityDescriptorOwner`, `GetAce`, etc.) are used.

For objects retrieved via `DirectorySearcher`:

- **Primary approach**: Read `nTSecurityDescriptor` as `byte[]` from `SearchResult.Properties["nTSecurityDescriptor"]` and parse with `new RawSecurityDescriptor(bytes, 0)`. This leverages the `PropertiesToLoad` and `SecurityMasks` optimizations already configured on the `DirectorySearcher`, avoiding additional LDAP round-trips. To obtain an `ActiveDirectorySecurity` object (needed for `GetAccessRules()`), construct one from the binary data:

```csharp
byte[] sdBytes = (byte[])result.Properties["nTSecurityDescriptor"][0];
ActiveDirectorySecurity security = new ActiveDirectorySecurity();
security.SetSecurityDescriptorBinaryForm(sdBytes);
```

- **Fallback**: Access `SearchResult.GetDirectoryEntry().ObjectSecurity` to obtain an `ActiveDirectorySecurity` object directly. **Note:** This forces an additional LDAP bind/read per result, negating `PropertiesToLoad`/`SecurityMasks` optimizations. Use only when the binary SD is unavailable from the search result. **Important:** `GetDirectoryEntry()` returns a new `DirectoryEntry` that implements `IDisposable`. When using this fallback, the returned `DirectoryEntry` MUST be disposed (via `using` statement or explicit `.Dispose()`) to release unmanaged ADSI handles, especially inside loops processing many results.

### ACE Extraction

ACEs are retrieved from the `ActiveDirectorySecurity` instance constructed from the binary `nTSecurityDescriptor` (see "Security Descriptor Retrieval" above):

```csharp
// 'security' is the ActiveDirectorySecurity built from nTSecurityDescriptor bytes
AuthorizationRuleCollection rules = security.GetAccessRules(
    true,   // includeExplicit
    false,  // includeInherited
    typeof(SecurityIdentifier)
);
```

Passing `false` for `includeInherited` retrieves only explicit ACEs directly, replacing the manual `INHERITED_ACE` flag check. The `security` variable here refers to the `ActiveDirectorySecurity` object populated via `SetSecurityDescriptorBinaryForm()` from the `nTSecurityDescriptor` byte array — **not** from `entry.ObjectSecurity`, which would force an additional LDAP round-trip per result.

Each `ActiveDirectoryAccessRule` exposes:

| Property | Description |
|---|---|
| `AccessControlType` | `Allow` or `Deny` |
| `ActiveDirectoryRights` | Flags enum of access rights granted/denied |
| `ObjectType` | GUID identifying the specific property, property set, extended right, or child class |
| `InheritedObjectType` | GUID identifying which child object type the ACE applies to |
| `IdentityReference` | Trustee SID (castable to `SecurityIdentifier`) |
| `InheritanceFlags` | `ContainerInherit`, `ObjectInherit` |
| `PropagationFlags` | `InheritOnly`, `NoPropagateInherit` |
| `IsInherited` | Whether the ACE is inherited (always `false` when retrieved with `includeInherited = false`) |

### SDDL Parsing for Schema Defaults

Schema `defaultSecurityDescriptor` SDDL strings are parsed using:

```csharp
RawSecurityDescriptor sd = new RawSecurityDescriptor(sddlString);
```

The `RawSecurityDescriptor(string)` constructor accepts SDDL directly. The resulting `.DiscretionaryAcl` provides ACE enumeration through `CommonAce` and `ObjectAce` types in `System.Security.AccessControl`.

**Important**: SDDL domain-relative aliases (e.g., `DA` for Domain Admins, `DU` for Domain Users) resolve to different SIDs in each domain, while forest-root-only aliases (`EA` for Enterprise Admins, `SA` for Schema Admins) always resolve to the forest root domain's SID. Since `RawSecurityDescriptor(string)` resolves aliases using only the calling process's security context (i.e., the current domain), schema default SDDL strings must be parsed **once per known domain NC** with manual alias substitution. See Step 4 in Section 9 for the full per-domain expansion mechanism.

### Owner Retrieval

The object owner is retrieved via:

```csharp
SecurityIdentifier owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
```

> **Note:** `GetOwner()` requires that the security descriptor was retrieved with `SecurityMasks.Owner` included (as in the main scan's `SecurityMasks.Owner | SecurityMasks.Dacl`). When only `SecurityMasks.Dacl` was requested (e.g., for AdminSDHolder), the Owner field is not present in the retrieved bytes and `GetOwner()` should not be called.

### Callback ACE Handling

**Documented limitation:** Callback ACE types (`ACCESS_ALLOWED_CALLBACK_ACE_TYPE`, `ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE`, etc.) are returned by `GetAccessRules()` as `ActiveDirectoryAccessRule` objects, but the conditional expression data embedded in the ACE is not exposed by the .NET Framework. Callback ACEs are reported as-is, treated identically to their non-callback counterparts, without evaluation of their conditional expressions. The reported permissions may not reflect the effective conditional access.

### ACE Type Coverage

ACE type coverage is determined by the .NET Framework's `GetAccessRules()` implementation, which parses all supported ACE types and exposes them through `ActiveDirectoryAccessRule`. The tool does not need to enumerate ACE types manually. ACE types that the framework does not expose would appear as `CustomAce` objects in the raw `RawSecurityDescriptor.DiscretionaryAcl` collection; these are not processed by the tool.

### Objects Inspected

Every object in every naming context is inspected. The tool does not filter by object class during the LDAP query — it retrieves all objects via `(objectClass=*)` and processes each one's security descriptor.

---

## 5. Detection of Inherited vs. Explicit Permissions

### Inherited ACE Filtering

Only explicitly assigned (non-inherited) ACEs are included in the output. This is achieved by passing `includeInherited = false` to `GetAccessRules()`:

```csharp
security.GetAccessRules(true, false, typeof(SecurityIdentifier));
```

This eliminates the need for manual `INHERITED_ACE` flag checking. The tool's goal is to report delegations that were explicitly configured, not those that flow down from parent containers through inheritance.

---

## 6. Filtering of Default or Built-in Permissions

### Schema Default Security Descriptors

Each AD class can have a `defaultSecurityDescriptor` attribute in SDDL form, accessed via `ActiveDirectorySchemaClass.DefaultObjectSecurityDescriptor`. The tool parses these for every class and computes the ACEs that would be derived by inheritance from the schema defaults for each object's class. An ACE that matches a schema default is excluded from the output.

The ACE comparison function compares two ACEs while ignoring:

- **Read-only access rights**: `ActiveDirectoryRights.ReadProperty | ActiveDirectoryRights.ListChildren | ActiveDirectoryRights.ReadControl | ActiveDirectoryRights.ListObject`
- **Object inherit flag**: `InheritanceFlags.ObjectInherit`. The `OBJECT_INHERIT_ACE` flag causes an ACE to be inherited by non-container (leaf) child objects, while `ContainerInherit` causes inheritance to container child objects. The tool masks out this flag before comparing ACEs. **This is an intentional design simplification**, not a claim about AD's object model. Leaf objects do exist in AD (e.g., individual DNS records in AD-integrated DNS zones, certain system objects), and ignoring `OBJECT_INHERIT_ACE` may produce incorrect results for ACEs that target these objects. This trade-off is accepted because the flag has no effect on container objects (which represent the tool's primary analysis targets), and preserving it would introduce false positives in schema default ACE comparison. This is documented as a known limitation.

**False-negative risk:** An administrator may intentionally set an explicit ACE that happens to match a schema default. Excluding these ACEs means the tool will not report them. This trade-off is documented as a known limitation. A future enhancement could provide a flag to expose these matches, similar to `--show-builtin`.

### Default SD Computation for Multiple Classes

The tool computes default security descriptors based on the object's most-specific class (the last value in the multi-valued `objectClass` attribute). Active Directory uses the union of inherited ACEs from all structural classes in the hierarchy. If a parent class has a `defaultSecurityDescriptor` that introduces ACEs not present in the most-specific class's default, those ACEs may not be correctly filtered. This is documented as a known limitation.

### Creator Owner Handling in Schema Defaults

When computing inherited ACEs from schema defaults, if the parent ACE's trustee is the `Creator Owner` SID (`S-1-3-0`), it is replaced by the actual owner SID of the child object (mirroring AD behavior). Both the replaced and original ACEs are produced as defaults, so an explicit ACE matching either version is filtered.

**Note:** If the object's owner has changed since creation, the ACE with the original creator's SID would no longer match the owner-replaced version. The tool uses the current owner SID for this comparison.

### Ignored Trustee SIDs

ACEs for the following well-known SIDs are suppressed by default. These are highly-privileged or default trustees whose ACEs are usually not actionable for delegation review. They can be re-enabled via `--show-ignored-trustees`:

| SID | Identity |
|---|---|
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

The `--show-ignored-trustees` CLI option causes the tool to report ACEs for all trustees, including those in the default suppressed list. This allows auditors to see the full picture when needed.

### Read-Only Access Rights

ACEs whose access mask, after masking out read-only rights, results in zero are discarded. The ignored (read-only) access rights are defined using the `ActiveDirectoryRights` enum:

```csharp
ActiveDirectoryRights ignoredRights =
    ActiveDirectoryRights.ReadProperty |
    ActiveDirectoryRights.ListChildren |
    ActiveDirectoryRights.ReadControl |
    ActiveDirectoryRights.ListObject;

if ((rule.ActiveDirectoryRights & ~ignoredRights) == 0)
{
    // ACE grants only read-only rights; discard
}
```

The output reflects the full (unmasked) access rights of an ACE. The masking is used only for the "is this ACE interesting?" decision. In `--show-raw` mode, the complete access mask is displayed.

### Delete Protection ACEs

Deny ACEs for `Everyone` (`S-1-1-0`) are suppressed only when the ACE **exclusively** denies delete-related rights (`Delete`, `DeleteChild`, and/or `DeleteTree`). If the ACE also denies other rights beyond these, it is NOT suppressed. This tightened check prevents hiding deny ACEs that restrict more than just deletion.

```csharp
ActiveDirectoryRights deleteRights =
    ActiveDirectoryRights.Delete |
    ActiveDirectoryRights.DeleteChild |
    ActiveDirectoryRights.DeleteTree;

// Suppress only if the ACE denies exclusively delete rights
if (rule.AccessControlType == AccessControlType.Deny
    && trusteeSid.Equals(everyoneSid)
    && (rule.ActiveDirectoryRights & ~deleteRights) == 0)
{
    // Suppress this standard delete-protection entry
}
```

### Change Password Deny ACEs

Deny ACEs for `Everyone` that deny the `Change Password` control access right are suppressed, as these are set by tools like `dsa.msc` for the "Cannot change password" option.

### AdminSDHolder ACEs

For objects where `adminCount != 0` **and** `AreAccessRulesProtected` is `true`, ACEs that appear in the AdminSDHolder DACL are suppressed. This is because the SDProp process copies the AdminSDHolder's DACL onto protected objects and blocks inheritance. Both conditions are required: `adminCount` alone is unreliable because it is notoriously stale — it is set when an object is added to a protected group but not always cleared when removed. If `adminCount != 0` but `AreAccessRulesProtected` is `false`, the object is likely no longer SDProp-managed, and its explicit ACEs represent real delegations that should be reported (not filtered).

The `adminCount` attribute is parsed as an integer, not a string:

```csharp
int adminCount = result.Properties.Contains("adminCount")
    ? (int)result.Properties["adminCount"][0]
    : 0;
```

Any nonzero integer value indicates a protected object.

**Stale adminCount caveat:** The `adminCount` attribute is notoriously stale in AD — it is set when an object is added to a protected group but not always cleared when removed. Formerly-protected objects may have `adminCount=1` but are no longer managed by SDProp. Because AdminSDHolder ACE filtering requires both `adminCount != 0` and `AreAccessRulesProtected == true` (see above), stale `adminCount` objects whose inheritance has been restored will correctly have their ACEs reported rather than suppressed. If `adminCount != 0` but `AreAccessRulesProtected` is `false`, the tool logs a warning to stderr noting the inconsistency, as this may indicate a stale `adminCount`.

### Ignored Control Access Rights

ACEs granting only `ExtendedRight` for specific control access rights that do not grant meaningful control over a resource are suppressed:

- `Apply Group Policy` — applying a GPO does not mean controlling it
- `Allow a DC to create a clone of itself` — if an attacker can impersonate a DC, cloning is not the primary concern

### Ignored DACL Protected Flags

DACL inheritance blocking (detected via `ActiveDirectorySecurity.AreAccessRulesProtected`) is not reported as a warning for:

- Objects of class `groupPolicyContainer` (GPOs block inheritance by design)
- Objects with `adminCount != 0` (expected to block inheritance via SDProp)
- Specific well-known containers: `CN=AdminSDHolder,CN=System`, `CN=VolumeTable,CN=FileLinks,CN=System`, `CN=Keys`, `CN=WMIPolicy,CN=System`, `CN=SOM,CN=WMIPolicy,CN=System`

### Built-in Delegation Definitions

A set of built-in delegation definitions is shipped with the tool, either as an embedded XML resource (loaded via `Assembly.GetManifestResourceStream()`) or as an external XML file distributed alongside the executable. These define expected ACEs for well-known delegations (e.g., DnsAdmins on DNS zones, Group Policy Creator Owners on WMI policies). By default, matched built-in delegations are excluded from CSV output unless `--show-builtin` is specified.

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
2. **Local resolution via `SecurityIdentifier.Translate()`**: Call `SecurityIdentifier.Translate(typeof(NTAccount))`. If successful, the `NTAccount.Value` property returns the name in `DOMAIN\Username` format. This replaces the previous `LookupAccountSidLocalW` approach entirely — no P/Invoke or dynamic library loading is needed.
3. **LDAP SID-based lookup**: Perform a lookup via `new DirectoryEntry("LDAP://<SID=" + sid.Value + ">")` and retrieve `distinguishedName` and `objectClass` attributes. When `--server` is specified, include the server prefix: `"LDAP://serverName/<SID=" + sid.Value + ">"`. If successful, the DN is used as the display name and `objectClass` determines the principal type.
4. **Raw SID string fallback**: If all resolution methods fail, the raw SID string (e.g., `S-1-5-21-...`) is used as the display name, with type `External`.

### Cache Semantics

The SID resolution cache uses **"first write wins"** semantics: once a SID's mapping is stored, it is not overwritten for the duration of the run. This ensures stable, predictable resolution results.

The cache stores a typed resolution result with:
- **Display name**: Either a `DOMAIN\Username` string (from `Translate()`) or a DN (from LDAP lookup) or a raw SID string (fallback)
- **Principal type**: The resolved principal type classification
- **Resolution source**: Which resolution path populated the entry (for diagnostic purposes)

### Cache Population

The cache is populated from multiple sources during operation:

- **During the main scan**: When an object has an `objectSid` attribute, for domain-specific SIDs (starting with `S-1-5-21-...`), the mapping from SID → DN is inserted directly. For non-domain-specific SIDs (e.g., well-known SIDs found in `CN=ForeignSecurityPrincipals`), `Translate()` is attempted first; only if it throws `IdentityNotMappedException` is the SID → DN mapping inserted as a fallback. Existing cache entries are never overwritten.
- **During `Translate()` resolution**: A successful translation stores the SID → `DOMAIN\Username` mapping.
- **During LDAP SID lookup**: A successful lookup stores the SID → DN mapping.

### Principal Type Resolution

Each resolved SID is mapped to one of four principal type classifications. The mapping depends on the resolution path:

**From LDAP (objectClass-based):** The most specific class (last value of the multi-valued `objectClass` attribute) is compared via case-insensitive exact match:

| Most Specific Class | Principal Type | Notes |
|---|---|---|
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

`SecurityIdentifier.Translate(typeof(NTAccount))` automatically resolves trusted-domain and well-known SIDs, regardless of where they appear in the directory. Foreign security principal objects in `CN=ForeignSecurityPrincipals` do not require special handling — `Translate()` does the right thing for cross-domain and cross-forest SIDs. Truly unresolvable SIDs (e.g., from unreachable forests) fall back to the raw SID string.

### Deleted Trustee Detection

During post-processing, for each naming context, ACEs whose trustee SID cannot be resolved are evaluated for deleted trustee classification:

```csharp
SecurityIdentifier trusteeSid = /* unresolvable trustee */;
SecurityIdentifier domainSid = trusteeSid.AccountDomainSid;

if (domainSid != null && IsKnownDomainSid(domainSid))
{
    // Flag as deleted trustee
}
```

`SecurityIdentifier.AccountDomainSid` returns the domain portion of a SID (strips the RID), or `null` for well-known SIDs with no domain component. If the domain portion matches **any** known domain SID (not just the root domain), the ACE is flagged as a deleted trustee. Unresolvable SIDs from unknown domains or forests remain as orphan ACEs with raw SID trustee strings.

---

## 8. Permission and Rights Interpretation

### Access Mask Mapping

The tool maps `ActiveDirectoryRights` enum values to human-readable descriptions. When in resolved-name mode (the default), the following mappings apply:

| `ActiveDirectoryRights` Value | Human-Readable Description |
|---|---|
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

```csharp
if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) != 0)
{
    // WriteProperty is set
}
```

**Note:** `Enum.HasFlag()` is NOT used, as it was introduced in .NET Framework 4.0.

### Object Type GUID Resolution

In **resolved-name mode** (the default), the `ObjectType` GUID resolution is **conditional on which access right is set**:

| Access Right | GUID Resolution Order |
|---|---|
| `WriteProperty` | attribute GUID → property set GUID → (fallback: "Write all properties") |
| `ExtendedRight` | control access right GUID → (fallback: "Perform all application-specific operations") |
| `CreateChild` | class GUID → (fallback: "Create child objects of any type") |
| `DeleteChild` | class GUID → (fallback: "Delete child objects of any type") |
| `Self` | validated write GUID → (fallback: "Perform all validated writes") |

In **raw mode** (`--show-raw`), the GUID is resolved sequentially across all schema categories:
1. Class GUID → class name
2. Attribute GUID → attribute name
3. Control access right GUID → control access name
4. Property set GUID → property set name
5. Validated write GUID → validated write name

Raw mode displays hex values via `((int)rule.ActiveDirectoryRights).ToString("X8")` and symbolic names via `rule.ActiveDirectoryRights.ToString()`.

### Inherited Object Type Resolution and Inheritance Scope

When in resolved-name mode and `ContainerInherit` is set in `InheritanceFlags`, the `InheritedObjectType` GUID is resolved against class GUIDs to determine which child object type the ACE applies to:

- "on all {class_name} child objects" if `InheritedObjectType` resolves to a class
- "on all child objects" otherwise
- "and the container itself" is appended if `InheritOnly` is NOT set in `PropagationFlags`

When `ContainerInherit` is not set, no inheritance scope text is included.

---

## 9. Data Processing and Transformation Pipeline

### Step 1: Connection and Bootstrap

- Establish connection via managed .NET APIs: by default, `Domain.GetCurrentDomain()` and `Forest.GetCurrentForest()` use the Windows DC locator (AD sites and services) for site-aware DC discovery. When `--server` is specified, use `new DirectoryContext(DirectoryContextType.DirectoryServer, serverName)` with `Domain.GetDomain(ctx)` and `Forest.GetForest(ctx)` to route through the specified DC.
- Read RootDSE for naming contexts and schema/configuration DNs
- **Domain enumeration and SID collection**: Use `Forest.GetCurrentForest().Domains` (or `Forest.GetForest(ctx).Domains` with `--server`) to enumerate all domains in the forest — this is the authoritative runtime source for the known-domain-NC set (see Section 1, "Known Domain NC Definition"). For each `Domain` object, obtain a single `DirectoryEntry` via `using (DirectoryEntry entry = domain.GetDirectoryEntry())` (since the returned `DirectoryEntry` implements `IDisposable` and holds unmanaged ADSI handles), then read `Properties["objectSid"]` — note that `Properties["objectSid"]` returns a `PropertyValueCollection`, so the value must be indexed and cast: `(byte[])entry.Properties["objectSid"][0]`, then parsed with `new SecurityIdentifier(bytes, 0)`. The domain's DN can be read from `entry.Properties["distinguishedName"][0]` within the same `using` scope. This collects SIDs for **all** known domain NCs — not just the current domain — which is required for deleted-trustee detection (Section 7) and per-domain SDDL alias expansion (Step 4). The `Domain.Name` property provides the DNS name.
- **NetBIOS name mapping**: Since `Domain` objects do not expose NetBIOS names directly, query `CN=Partitions,<configurationNC>` via `DirectorySearcher` with filter `(&(objectClass=crossRef)(nCName=*)(nETBIOSName=*))` to retrieve the `nETBIOSName` for each domain NC, and map them to the `Forest.Domains` set collected above by matching each `crossRef` object's `nCName` to the corresponding domain's distinguished name. This reconciles the `crossRef`-based definition from Section 1 with the managed API enumeration — both should produce the same set of domain NCs.
- Report progress: `Console.Error.WriteLine(String.Format("[*] Connected to {0}", targetServer))` where `targetServer` is the `--server` value if specified, or the domain controller hostname obtained via `Domain.GetCurrentDomain().FindDomainController().Name` when using the default DC locator path

### Step 2: Schema Loading

- Enumerate all schema classes via `ActiveDirectorySchema.GetCurrentSchema().FindAllClasses()` (or `ActiveDirectorySchema.GetSchema(ctx).FindAllClasses()` with `--server`) for class GUIDs (`SchemaGuid`) and `DefaultObjectSecurityDescriptor` SDDL strings
- Enumerate all schema attributes via `ActiveDirectorySchema.GetCurrentSchema().FindAllProperties()` (or `.GetSchema(ctx).FindAllProperties()` with `--server`) for attribute GUIDs (`SchemaGuid`)
- Query `controlAccessRight` objects via `DirectorySearcher` on the Configuration NC for property sets (`validAccesses=48`), validated writes (`validAccesses=8`), and control access rights (`validAccesses=256`)
- Report progress: `Console.Error.WriteLine(String.Format("[*] Schema loaded: {0} classes, {1} attributes, {2} extended rights", classCount, attrCount, rightCount))`

### Step 3: Delegation and Template Loading

- Load built-in delegations from the embedded XML resource via `Assembly.GetManifestResourceStream()`, wrapping the returned `Stream` in a `using` block (since it implements `IDisposable`), then calling `XmlDocument.Load(stream)` within that scope
- Optionally load user-provided templates (`--templates`) and delegations (`--delegations`) from external XML files, validated against XSD schema
- For each delegation, derive expected ACEs by resolving trustees and locations, and index them by SID → Location

### Step 4: Schema ACE Analysis

- For each `ActiveDirectorySchemaClass` with a `DefaultObjectSecurityDescriptor`:
  - Parse the SDDL string **once per known domain NC** (all domain NCs collected in Step 1). SDDL domain-relative aliases (e.g., `DA` for Domain Admins, `DU` for Domain Users, `PA` for Group Policy Creator Owners) resolve to different SIDs in each domain. Since `RawSecurityDescriptor(string)` resolves aliases using only the calling process's security context (i.e., the current domain), the tool must manually substitute SDDL abbreviations with the appropriate domain's SIDs before parsing. Specifically, for each domain, replace per-domain aliases like `DA` → `S-1-5-21-<domainSid>-512`, `DU` → `S-1-5-21-<domainSid>-513`, etc. Forest-root-only aliases — `EA` (Enterprise Admins, RID 519) and `SA` (Schema Admins, RID 518) — must always resolve to the **forest root domain** SID regardless of which domain is being processed. Parse the substituted string via `new RawSecurityDescriptor(expandedSddl)`.
  - Filter the DACL ACEs through the interest check logic
  - Store remaining ACEs as orphan ACEs in the result set

### Step 5: Explicit ACE Analysis

- For each naming context, perform a subtree search via `DirectorySearcher` with `Filter = "(objectClass=*)"`, `SearchScope = SearchScope.Subtree`, `PageSize = 1000`, `SecurityMasks = SecurityMasks.Owner | SecurityMasks.Dacl`
- **Important:** `SearchResultCollection` returned by `FindAll()` implements `IDisposable`. It MUST be disposed (via `using` statement or explicit `.Dispose()`) to release unmanaged LDAP result handles and prevent memory leaks during long scans. Additionally, `DirectorySearcher` and its `SearchRoot` `DirectoryEntry` both implement `IDisposable` and MUST also be disposed when no longer needed (typically by scoping them in `using` blocks) to avoid leaking ADSI/LDAP handles across multiple naming context iterations.
- For each object:
  - Parse the security descriptor via `ActiveDirectorySecurity`
  - Compute expected default ACEs from the schema class's `DefaultObjectSecurityDescriptor`
  - Filter each DACL ACE through the interest check, which excludes: inherited ACEs, read-only ACEs, schema default ACEs, AdminSDHolder ACEs, ignored trustee ACEs, and special-case ACEs
  - Record: owner, DACL protection status (via `AreAccessRulesProtected`), ACL canonicality, and orphan ACEs
- Report progress periodically: `Console.Error.Write(String.Format("\r[{0}] {1} objects processed...", ncDN, count))`

### Step 6: Post-Processing

1. **Memory optimization**: Remove records with no findings (no orphan ACEs, no owner issues, no warnings), but retain parent container records needed for CREATE_CHILD analysis.
2. **Deleted trustee detection**: For each unresolvable orphan ACE trustee across all naming contexts, check `SecurityIdentifier.AccountDomainSid` — if it matches **any** known domain SID (collected from all known domain NCs), move the ACE to the deleted trustee list. See Section 7 ("Deleted Trustee Detection") for the full algorithm.
3. **KDS root key handling**: Suppress DACL protection warnings for KDS root key objects in the Configuration partition.
4. **Owner analysis via CREATE_CHILD**: For each object with a non-ignored owner, walk up the container hierarchy checking if the owner has `CreateChild` permissions — if so, suppress the owner finding (the owner created the object). Group membership for this check uses the `tokenGroups` constructed attribute via `DirectoryEntry.RefreshCache(new string[] { "tokenGroups" })`, which resolves transitive/nested group memberships.
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
- Report final summary to stderr (and log file if `--log` is active) using the format defined in Section 13.3 — `[i]` prefix, object/ACE/SD counts, and elapsed time formatted as `hh:mm:ss` (or `mm:ss` for scans under one hour)

---

## 10. CSV Export Structure

### CSV Output Destination

The `--csv <path>` command-line argument selects the destination for CSV output. If the path is `-`, output goes to stdout. Otherwise, a file is created (or truncated if it exists). If neither `--csv` nor `--risk-csv` (see Section 20.2) is specified, the tool writes CSV to stdout by default (equivalent to `--csv -`). This ensures the tool always produces usable output, even when run without explicit output arguments.

### CSV Header Row

The CSV output includes a mandatory header row as the first line:

```
Resource,Trustee,Trustee type,Category,Details,Risk Level,Current User Can Exploit
```

### CSV Schema

The CSV output has **7 columns**:

| Column | Name | Description |
|---|---|---|
| 1 | **Resource** | The location where the delegation or finding applies. Either a DN (e.g., `OU=Users,DC=example,DC=com`), a schema reference (e.g., `Schema: default security descriptor of class 'user'`), or `Global` for non-location-specific findings |
| 2 | **Trustee** | The resolved name of the security principal (DN or `DOMAIN\Username`), or the raw SID string if unresolvable, or `Global` for location-level warnings |
| 3 | **Trustee type** | One of: `User`, `Group`, `Computer`, `External` |
| 4 | **Category** | Classification of the finding (see below) |
| 5 | **Details** | Human-readable description of the permission or finding |
| 6 | **Risk Level** | A risk classification for the row. One of: `Critical`, `High`, `Medium`, `Informational`, or empty (blank) for rows that do not match any risk rule. See Section 18 for the classification matrix. |
| 7 | **Current User Can Exploit** | `Yes` if the ACE trustee SID matches the current user's SID or any of the current user's transitive group SIDs (see Section 19); empty (blank) otherwise. |

### Category Values

| Category | Meaning |
|---|---|
| `Owner` | The trustee owns the object, granting implicit full control |
| `Warning` | A structural issue (unreadable SD, blocked DACL inheritance, non-canonical ACL) or a deleted trustee finding |
| `Allow ACE` | An explicit allow ACE not explained by any known delegation |
| `Deny ACE` | An explicit deny ACE not explained by any known delegation |
| `Built-in` | A delegation matching a built-in definition (only shown with `--show-builtin`) |
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

### Record Generation Logic

For each location/result pair in the scan results:

1. **Per-location processing errors** (if `--show-warning-unreadable`): One `Warning` record with the error message. This covers any error entry in the results, including unreadable security descriptors, missing/unreadable `objectClass` attributes, and unparseable schema `defaultSecurityDescriptor` SDDL strings.
2. **Owner**: One `Owner` record if the object's owner is not in the ignored trustee set and was not filtered by CREATE_CHILD analysis.
3. **DACL protection**: One `Warning` record if `AreAccessRulesProtected` is `true` and the object is not in an excluded category.
4. **Non-canonical ACL**: One `Warning` record if the ACL is not in canonical order. The offending ACE is described.
5. **Deleted trustees**: One `Warning` record per ACE whose trustee no longer exists.
6. **Orphan ACEs**: One `Allow ACE` or `Deny ACE` record per unmatched ACE, with access rights described.
7. **Delegations**: For each matched delegation (built-in only if `--show-builtin`):
   - One `Built-in` or `Delegation` record with the delegation description
   - One `Expected allow/deny ACE found` record per matched ACE, prefixed with "In delegation: "
   - One `Expected allow/deny ACE missing` record per unmatched expected ACE, prefixed with "In delegation: "

### Formatting and Encoding

- **Encoding**: UTF-8 without BOM. Use `new UTF8Encoding(false)` explicitly.
- **File output**: `new StreamWriter(path, false, new UTF8Encoding(false))`
- **Stdout output**: Wrap `Console.OpenStandardOutput()` in a `StreamWriter`:

```csharp
using (StreamWriter writer = new StreamWriter(
    Console.OpenStandardOutput(),
    new UTF8Encoding(false)))
{
    // Write CSV rows via writer.WriteLine(...)
    // The using block ensures Flush() and Dispose() are called,
    // preventing truncation of buffered output.
}
```

**Do NOT use `Console.Out` directly** for CSV output, as `Console.OutputEncoding` defaults to the system's OEM code page on Windows. The `StreamWriter` must be disposed (or at minimum flushed) after all CSV rows are written — `StreamWriter` buffers output internally, so omitting `Flush()`/`Dispose()` risks truncating the final bytes. The `using` block above handles this automatically.

- **RFC 4180 quoting rules**: Fields containing commas, double-quotes, or newlines are enclosed in double-quotes. Embedded double-quotes are escaped as `""`. The line terminator is CRLF. This is implemented manually (~20 lines of code), as .NET Framework 2.0 has no built-in CSV library.

### DN String Encoding

Distinguished Names in Active Directory can contain special characters (commas, plus signs, semicolons, angle brackets, equals signs, hash marks, backslashes). These characters appear as-is in the DN string within the CSV field. The RFC 4180 quoting rules handle the CSV-level escaping (DNs containing commas will be enclosed in double-quotes).

### Stdout and Stderr Separation

When `--csv -` is used, CSV data goes to stdout. All diagnostic and progress messages go to stderr via `Console.Error`. This ensures clean separation when using pipe redirection.

---

## 11. Delegation and Template System

### Delegation and Template Format

Delegation and template definitions use **XML format** (not JSON), taking advantage of .NET Framework 2.0's native XML support.

### XML Parsing

- **DOM-based access**: `XmlDocument.Load(path)` with `SelectNodes()` for XPath queries
- **Deserialization**: `XmlSerializer` can deserialize XML directly into typed C# objects
- **Embedded resources**: Built-in definitions loaded via `Assembly.GetManifestResourceStream()` and parsed with `XmlDocument.Load(stream)`

### XSD Schema Validation

All XML files loaded by the tool — whether they contain delegation definitions, template definitions, risk classification configuration, or any combination thereof — are validated against the same `<adeleg>` XSD schema at load time. This includes standalone risk-configuration files that contain only `<unsafeTrustees>`, `<tier0Resources>`, or `<dangerousDelegations>` elements. Validation is performed by creating an `XmlReader` with validation settings and reading the document through it:

```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.Schemas.Add(null, xsdPath);
settings.ValidationType = ValidationType.Schema;
settings.ValidationEventHandler += delegate(object sender, ValidationEventArgs e) {
    throw e.Exception;
};
using (XmlReader reader = XmlReader.Create(xmlPath, settings))
{
    XmlDocument doc = new XmlDocument();
    doc.Load(reader); // Validation occurs during Load
}
```

If the XML does not conform to the XSD schema, the `ValidationEventHandler` fires and throws `e.Exception` (the `XmlSchemaValidationException` from `ValidationEventArgs`), which preserves line number, position, and inner exception context for precise error reporting. This prevents invalid definitions from being processed and provides formal structural validation without third-party libraries.

### Access Mask Representation

Delegation definitions use symbolic `ActiveDirectoryRights` enum names (e.g., `WriteProperty`, `ExtendedRight`, `CreateChild`) rather than raw numeric values. These are resolved at load time:

```csharp
ActiveDirectoryRights rights = (ActiveDirectoryRights)Enum.Parse(
    typeof(ActiveDirectoryRights), rightsName
);
```

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

**Placeholder syntax:** Placeholders in SID and DN patterns use curly-brace syntax (`{domainSID}`, `{forestRootDomainSID}`, `{domainDN}`, `{forestRootDN}`) rather than angle brackets, avoiding the need for XML entity escaping. At runtime, `{domainSID}` and `{domainDN}` are expanded for each known domain, `{forestRootDomainSID}` is expanded once using the forest root domain's SID (used for forest-root-only groups such as Schema Admins, Enterprise Admins, and Enterprise Key Admins), and `{forestRootDN}` is expanded using the forest root domain's DN. This is analogous to how delegation location wildcards (`DC=*`) are expanded (see Location Wildcards above).

### Location Wildcards

Delegation definitions support the following wildcard patterns for locations, which are expanded at load time:

| Pattern | Expansion |
|---|---|
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

### Deleted Objects and Tombstones

- The tool does not explicitly query the Deleted Objects container or tombstones.
- ACEs referencing SIDs that belong to a known domain (determined via `SecurityIdentifier.AccountDomainSid` comparison against all known domain SIDs) and cannot be resolved are flagged as deleted trustees and reported with a "Warning" category.
- Unresolvable SIDs from unknown domains or forests remain as orphan ACEs with raw SID trustee strings.

### Foreign Security Principals

- Objects in `CN=ForeignSecurityPrincipals` are encountered during the subtree scan.
- `SecurityIdentifier.Translate(typeof(NTAccount))` automatically resolves well-known and trusted-domain SIDs, regardless of their container. FSP-specific handling is not needed.
- Truly foreign (cross-forest) principals that cannot be resolved locally appear with their raw SID and `External` type.

### Denied Permissions

- Deny ACEs are processed and reported in the CSV with category `Deny ACE`.
- Deny ACEs are considered during delegation matching (expected deny ACEs can be defined in delegation XML files).
- ACL canonicality checks detect deny-after-allow ordering issues.

### Non-Canonical ACLs

Non-canonical ACL detection uses `CommonAcl.IsCanonical` as the primary detection mechanism:

```csharp
RawSecurityDescriptor rawSd = new RawSecurityDescriptor(bytes, 0);
bool isContainer = DetermineIsContainer(mostSpecificObjectClass);
CommonSecurityDescriptor commonSd = new CommonSecurityDescriptor(
    isContainer, true, rawSd  // isContainer derived per-object, isDS=true for AD objects
);
bool isCanonical = commonSd.DiscretionaryAcl.IsCanonical;
```

The `isContainer` parameter must be derived per-object rather than hard-coded. Many AD objects (domains, OUs, objects of class `container`, `builtinDomain`, `organizationalUnit`, etc.) are containers, and `CommonAcl.IsCanonical` may evaluate inheritance-related canonical ordering rules differently for containers vs. leaf objects. To determine `isContainer`:

1. Retrieve the most specific `objectClass` value for the object (already available from the scan's `PropertiesToLoad`).
2. Look up the corresponding `ActiveDirectorySchemaClass` and check whether `PossibleInferiors.Count > 0`. If the class can contain child objects, it is a container.
3. Cache the `isContainer` determination per class name to avoid repeated schema lookups.

If `IsCanonical` returns `false`, the tool iterates the ACEs manually to identify the specific ordering violation for the warning message. A non-canonical ACL is detected when:

1. An explicit ACE follows an inherited ACE, or
2. A deny ACE follows an allow ACE among explicit ACEs

`CommonAcl.IsCanonical` correctly accounts for inheritance scope levels, where ACEs at different inheritance depths may have different canonical ordering rules.

### Callback and Audit ACE Types

- Callback ACE types are returned by `GetAccessRules()` as `ActiveDirectoryAccessRule` objects but without their conditional expression data. They are treated identically to non-callback ACEs. **This is a documented limitation** — the reported permissions may not reflect effective conditional access.
- Audit and mandatory label ACEs are parsed by the framework. `GetAccessRules()` returns only DACL access rules; audit rules would come from `GetAuditRules()`. Since the tool only processes DACLs, audit ACEs are not encountered in normal operation.

### Objects with No DACL

If an object has no DACL (null DACL, meaning unrestricted access), this represents a significant security concern. The tool should report this as a `Warning` with a message indicating that the object has no discretionary access control.

### Empty objectClass

If an object's `objectClass` attribute is present but empty (`SearchResult.Properties["objectClass"].Count == 0`), the tool logs an error to stderr and skips the object, continuing the scan. This replaces the previous behavior of crashing (panicking) on this condition.

If the `objectClass` attribute is missing entirely, the error is recorded for that object and scanning continues.

### `objectClass` Ordering Assumption

The tool assumes the multi-valued `objectClass` attribute is ordered with the most-specific class last. This is standard AD behavior. For `inetOrgPerson` objects, the `objectClass` list would be `top`, `person`, `organizationalPerson`, `user`, `inetOrgPerson` — the last value correctly identifies the most-specific class.

---

## 13. Usability and Operational Concerns

### 13.1. Validation Mode

The tool should support a `--validate` flag that checks configuration and connectivity without performing the full scan. When `--validate` is specified, the tool:

1. Reads and parses all delegation/template XML files (if any are specified via `--delegations` or `--templates`).
2. Connects to the target domain controller (or auto-discovers one) and reads the RootDSE.
3. Enumerates domains and resolves domain SIDs. If `--server` is specified, use `Forest.GetForest(new DirectoryContext(DirectoryContextType.DirectoryServer, serverName)).Domains` (not `Forest.GetCurrentForest().Domains`) so validation is performed against the intended DC rather than the auto-discovered one.
4. Loads the schema (classes, attributes, GUIDs). If `--server` is specified, use `ActiveDirectorySchema.GetSchema(new DirectoryContext(DirectoryContextType.DirectoryServer, serverName))` rather than `ActiveDirectorySchema.GetCurrentSchema()`, consistent with the `--server` routing rule defined in Section 2.
5. Reports the results to stderr and exits with code 0 on success or a nonzero code on failure.

This mode enables troubleshooting deployment issues (connectivity, credential, configuration) without performing the full subtree scan.

### 13.2. File-Based Logging

The tool should support a `--log <path>` option that writes all diagnostic messages (those normally emitted to stderr) to the specified file **in addition to** stderr. The log file should include UTC timestamps in ISO 8601 format (`yyyy-MM-ddTHH:mm:ss.fffZ`) prepended to each line, generated via `DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", System.Globalization.CultureInfo.InvariantCulture)`. The `CultureInfo.InvariantCulture` parameter ensures the timestamp format is consistent regardless of the system's current culture settings (some cultures use different digit shapes or calendar systems that would produce non-ISO output).

**Implementation in .NET Framework 2.0:** Use a `StreamWriter` wrapping a `FileStream` opened with `FileMode.Create` and `FileAccess.Write`. All stderr output — both `Console.Error.Write()` and `Console.Error.WriteLine()` calls — should be routed through a single logging helper. The helper maintains a boolean flag tracking whether the current position is at the start of a new line. Timestamps are prepended **only at the start of a new line** — not on every write call. Critically, the helper must also scan the text passed to each `Write()` or `WriteLine()` call for **embedded newline characters** (`\n`, `\r\n`, or standalone `\r`), because a single call may contain multiple lines (e.g., exception messages with stack traces). When an embedded newline is found within the text, the helper inserts a timestamp after each newline boundary so that every resulting line in the log is timestamped. **Standalone `\r` handling:** A standalone carriage return (`\r` not followed by `\n`) is used by the tool's progress output (see Section 9, Step 5) to overwrite the current console line — a visual effect that has no meaningful equivalent in a sequential log file. When writing to the log file, the helper must treat standalone `\r` as a newline boundary: replace it with `\n` and start a new timestamped line. This ensures progress updates appear as individual timestamped lines in the log file rather than producing untimestamped overwritten content. On stderr (the console), standalone `\r` is passed through unchanged so the overwrite effect is preserved. For `Write()` calls (partial-line output such as progress updates), the helper writes the text without a timestamp prefix unless the current position is at the start of a new line. For `WriteLine()` calls, the helper prepends the timestamp if the current position is at the start of a new line, writes the text (with embedded newline processing), and marks the next position as a new line. This approach ensures every line in the log file has exactly one timestamp, even when a single API call emits multi-line content. The `StreamWriter` must be disposed via a `using` block (or explicit `Close()` in a `finally`) at tool exit to ensure all buffered content is flushed.

### 13.3. Summary Statistics

After the scan completes, the tool should emit a summary to stderr:

```
[i] Scan complete. {totalObjects} objects scanned, {totalACEs} ACEs analyzed, {unreadableSDs} unreadable security descriptors.
[i] Scan duration: {elapsed}.
```

Where `{elapsed}` is formatted as `hh:mm:ss` (or `mm:ss` for scans under one hour). This scan summary is immediately followed by the risk summary defined in Section 20.1, which reports the count of findings at each risk level. Risk classification is an integrated, always-on feature (see Sections 16–20) — no separate flag is needed to enable it.

### 13.4. Subtree Exclusion

The tool should support `--exclude-dn <dn>` options (may be specified multiple times) to exclude specific subtrees from the scan. When evaluating each object's `distinguishedName`, if it ends with any excluded DN suffix (case-insensitive comparison via `String.EndsWith()` with `StringComparison.OrdinalIgnoreCase`), the object is skipped.

**Use case:** Large environments with thousands of workstation computer objects in `OU=Workstations` that have identical delegations. Excluding this subtree can significantly reduce scan time.

**CLI syntax:**

```
tool.exe --csv output.csv --exclude-dn "OU=Workstations,DC=example,DC=com" --exclude-dn "OU=Servers,DC=example,DC=com"
```

### 13.5. Credential Handling

The tool supports the following authentication modes, ordered by preference:

| Priority | Method | CLI Syntax | Implementation |
|---|---|---|---|
| 1 | **Windows SSO (SSPI/Negotiate)** | *(no credential flags)* | `new DirectoryEntry(path)` — uses process identity automatically. This is the recommended default. |
| 2 | **Interactive password entry** | `--username <user> --password *` | Read password character-by-character via `Console.ReadKey(true)` in a loop, building a `string`. Pass to `new DirectoryEntry(path, username, password, AuthenticationTypes.Secure)`. |
| 3 | **Environment variable** | `--username <user> --password-env <VARIABLE_NAME>` | Read password from `Environment.GetEnvironmentVariable(variableName)`, where `variableName` is the value passed to `--password-env`. If the environment variable is unset or empty, the tool must fail immediately with a clear error message to stderr and exit with a nonzero code — it must **not** attempt a bind with a null/empty password (which could lead to unexpected authentication behavior or weaker-than-intended security). Less visible than command-line arguments. Example: `--password-env ADELEG_PASSWORD` reads from the `ADELEG_PASSWORD` environment variable. |

**Deprecation of cleartext command-line password:** The `--password <value>` form (where the password is supplied directly on the command line) is **not supported**. Passwords supplied on the command line are visible via process listings (`tasklist /v`, `Get-Process`, `/proc/*/cmdline`), creating a credential exposure risk. If automation requires non-interactive credential supply, use the `--password-env` option.

### 13.6. Help Text and CLI Argument Design

The tool should support `--help` (or `-h`) to display usage information to stderr. The help text should include:

1. A brief description of the tool's purpose.
2. A list of all CLI options with descriptions and default values.
3. Examples of common usage patterns.

All CLI arguments should use GNU-style long options with double dashes (e.g., `--csv`, `--server`, `--exclude-dn`). Short aliases are optional but may be provided for the most common options.

### 13.7. Verbosity Levels

The tool should support a `--verbose` flag (may be specified multiple times for increased verbosity):

| Level | Flag | Behavior |
|---|---|---|
| 0 (default) | *(none)* | Emit errors, warnings, per-object progress counter (the `\r` overwrite from Section 9 Step 5), end-of-scan summary (Section 13.3), and risk summary (Section 20.1) to stderr. |
| 1 | `--verbose` | Additionally emit per-naming-context completion messages with object counts and risk counts (see Section 20.3). |
| 2 | `--verbose --verbose` | Additionally emit detailed diagnostic messages (e.g., delegation matching decisions, ACE filter decisions, individual object processing details). |

### 13.8. Output Path Defaults

The `--csv` argument selects the CSV output destination (see Section 10). If `--csv <path>` is specified, write to the given file path. If `--csv -` is specified, write to stdout. If neither `--csv` nor `--risk-csv` is specified, the tool writes CSV to stdout by default (equivalent to `--csv -`).

### 13.9. Error Handling and Exit Codes

#### Exit Codes

The tool uses differentiated exit codes to support scripting and automation:

| Exit Code | Meaning |
|---|---|
| 0 | Success — the requested operation completed successfully (scan, validation, or help output) |
| 1 | General or unexpected error |
| 2 | Connection or authentication failure (e.g., `DirectoryServicesCOMException` during bind, or `ActiveDirectoryObjectNotFoundException` from `Domain.GetCurrentDomain()` on a non-domain-joined machine) |
| 3 | Input file parsing error — delegation, template, or risk configuration XML files failed XSD validation or XML parsing (`XmlException`, `XmlSchemaValidationException`, `InvalidOperationException` from `XmlSerializer`) |
| 4 | Output file error — cannot create or write to the specified CSV or log file (`IOException`, `UnauthorizedAccessException`) |

Exit codes are set via `Environment.ExitCode` or the return value from `Main()`.

#### Search-Level Error Handling

If a search-level LDAP error occurs during the main subtree scan of a naming context (e.g., the server drops the connection, returns a size limit exceeded error, or the `SearchResultCollection` enumerator throws `DirectoryServicesCOMException`):

- **The tool does NOT abort the entire run.** The error is logged to stderr (and to the log file if `--log` is active), the affected naming context is marked as failed, and scanning continues with the remaining naming contexts.
- At the end of the scan, the tool reports which naming contexts were successfully scanned and which failed:
  ```
  [!] Failed to scan naming context: {ncDN} — {errorMessage}
  ```
- If any naming contexts failed, the exit code is 1 (general error), even if other naming contexts succeeded. The CSV output includes results from all successfully scanned naming contexts.

#### Per-Object Error Handling

Per-object errors — such as failures to parse a security descriptor, missing or unreadable `objectClass` attributes, and unparseable schema `defaultSecurityDescriptor` SDDL strings — are recorded per-location and reported as `Warning` rows in the CSV output if `--show-warning-unreadable` is enabled. The scan continues for subsequent objects. By default, these errors are counted and summarized in the end-of-scan summary (see Section 13.3).

#### Connection and Authentication Errors

If the initial connection fails (e.g., `Domain.GetCurrentDomain()` throws `ActiveDirectoryObjectNotFoundException` on a non-domain-joined machine, or `DirectoryEntry` construction with `--server` fails), the tool emits a descriptive error to stderr and exits with code 2.

### 13.10. Format Versioning

The CSV output schema (column names, column count, and column semantics) and the XML configuration schema (delegation, template, and risk configuration elements) are defined by this specification. Changes to either schema that alter column count, column names, column ordering, or XML element/attribute structure constitute a breaking change and should be accompanied by a version increment in the tool's version string (reported in the audit trail per Section 14.3). Consumers of the CSV output should parse by header name rather than by column position to maximize forward compatibility.

---

## 14. Security Considerations

### 14.1. Credential Protection

As detailed in Section 13.5, cleartext passwords on the command line are not supported. The tool provides three credential modes:

1. **Windows SSO** (default, no credentials on command line).
2. **Interactive password entry** (`--username <user> --password *`), which reads characters without echo via `Console.ReadKey(true)`.
3. **Environment variable** (`--username <user> --password-env <VARIABLE_NAME>`), which reads from the named environment variable.

For interactive password entry, the tool should:

1. Print `Password: ` to stderr (no newline).
2. Read characters via `Console.ReadKey(true)` in a loop until the user presses Enter.
3. Print a newline to stderr after entry is complete.
4. Use the collected string as the password for `DirectoryEntry` constructors.

**Note on `SecureString`:** .NET Framework 2.0 supports `System.Security.SecureString`, but `DirectoryEntry` constructors accept only `string` for the password parameter. Therefore, `SecureString` provides no additional protection in this context.

### 14.2. LDAPS Certificate Validation

When using `System.DirectoryServices` with `DirectoryEntry`, LDAPS certificate validation is handled automatically by the underlying Windows LDAP subsystem using the machine's trusted CA certificate store. No custom certificate validation code, `ServicePointManager` callbacks, or P/Invoke hooks are needed.

If `AuthenticationTypes.Secure` is used (the recommended default), the connection uses SSPI-negotiated authentication (typically Kerberos or NTLM). `Secure` guarantees authenticated binding but does **not** guarantee encryption or integrity protection — signing and sealing are negotiated separately and depend on the domain controller's and client's policies. In most Active Directory environments, Kerberos with signing and sealing is the negotiated result, but the tool should not assume this. If encryption of LDAP traffic is a hard requirement, use LDAPS (`AuthenticationTypes.Secure | AuthenticationTypes.SecureSocketsLayer`) to ensure TLS-level transport encryption regardless of SSPI negotiation outcomes.

If an explicit LDAPS connection is needed (e.g., `"LDAP://server:636"` with `AuthenticationTypes.Secure | AuthenticationTypes.SecureSocketsLayer`), the Windows trust store evaluation applies automatically. Both flags must be combined: `Secure` preserves SSPI/Kerberos/NTLM authentication, while `SecureSocketsLayer` enables TLS transport. Using `SecureSocketsLayer` alone may fall back to simple bind (see Section 2, "LDAPS and Encrypted Transport").

### 14.3. Audit Trail

The tool should log the following execution metadata to stderr (and to the log file if `--log` is specified):

```
[i] Tool version: {version}
[i] Start time: {UTC timestamp}
[i] Running as: {DOMAIN\username} ({SID})
[i] Target: {server or "auto-discovered DC: hostname"}
[i] Naming contexts: {comma-separated list of NCs}
[i] End time: {UTC timestamp}
```

Where `{UTC timestamp}` is `DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", System.Globalization.CultureInfo.InvariantCulture)` — the same culture-independent UTC format used by the logging helper (Section 13.2).

This provides a basic audit trail of tool execution for compliance purposes. The LDAP queries themselves may also be logged by the domain controller's diagnostic logging.

### 14.4. Output File Permissions

The specification acknowledges that the output CSV may contain sensitive information about the AD delegation structure. On Windows, file permissions are governed by the parent directory's ACL and the process's access token. The tool does not explicitly set restrictive permissions on the output file, but operators should be advised (in the help text and documentation) to write output to a directory with restricted access.

**Rationale for not programmatically restricting file permissions:** .NET Framework 2.0's `System.IO` does not provide a straightforward cross-version API for setting file ACLs. `System.Security.AccessControl.FileSecurity` exists but requires careful use and may not behave consistently across all target Windows versions. Documenting the security consideration is preferred over fragile programmatic enforcement.

---

## 15. Assumptions and Limitations

This section documents the tool's assumptions and known limitations. Each assumption is either carried forward with documentation, modified, or replaced relative to the original design.

### 15.1. Single Forest Scope

**Decision: Carry forward with documentation.**

The tool assumes all naming contexts belong to the same forest. This is the expected scope for delegation analysis, as delegations are forest-internal constructs.

**Cross-forest behavior:** When the tool encounters foreign security principals (FSPs) from trusted forests, it resolves them if possible via `SecurityIdentifier.Translate(typeof(NTAccount))`, which uses Windows trust relationships transparently. Truly unresolvable cross-forest SIDs appear with their raw SID and `External` type. The tool does not follow cross-forest referrals or enumerate delegations in trusted forests.

**Rationale:** Cross-forest delegation analysis would require credentials and connectivity to the remote forest, making it a substantially different operational model. The single-forest assumption is documented as an intentional scope boundary, not an overlooked limitation.

### 15.2. Standard Schema

**Decision: Carry forward with explicit confirmation.**

The tool loads the schema dynamically at runtime via `ActiveDirectorySchema.GetCurrentSchema().FindAllClasses()` and `FindAllProperties()` (or `ActiveDirectorySchema.GetSchema(ctx).FindAllClasses()` and `ActiveDirectorySchema.GetSchema(ctx).FindAllProperties()` when `--server` is specified, as defined in Section 9, Step 2). Custom schema extensions (additional classes and attributes) are fully supported — they appear in the schema enumeration and their GUIDs are loaded into the schema maps used for rights interpretation.

Custom schema attributes referenced in ACE `ObjectType` GUIDs are resolved correctly because the schema maps are built from the live schema, not from a static list.

### 15.3. "All AD Entries Are Containers" Simplification

**Decision: Document as intentional simplification.**

The tool uses `SearchScope.Subtree` on each naming context, which returns all objects regardless of whether they are containers or leaf objects. The `isContainer` parameter used in `CommonSecurityDescriptor` construction is determined per-object by checking `PossibleInferiors.Count > 0` on the object's schema class (see Section 12, Non-Canonical ACLs), not by assuming all objects are containers.

**Known exceptions to container assumption:** DNS records (`dnsNode` class) and some AD LDS-specific objects are leaf objects. These are handled correctly by the per-class `isContainer` determination.

### 15.4. Console and CSV as Primary Output

**Decision: Modified — acknowledge the limitation and define the mitigation.**

With the GUI removed, the console output (stderr) and CSV files (stdout or file) are the only interfaces. The tool compensates for the loss of the GUI's interactive capabilities through:

1. **Rich CSV output** with risk classification columns (Section 16.2) that enable filtering and pivoting in external tools (Excel, PowerBI, etc.).
2. **Filtered risk report** (`--risk-csv`) that provides a focused view of findings (Section 20.2).
3. **Summary statistics** and per-naming-context progress reporting (Sections 13.3 and 13.7).
4. **Current User Can Exploit column** (Section 19.2) that highlights personally actionable findings.

Additional output modes (HTML report, JSON) are not prescribed in this version but may be considered for future enhancements.

### 15.5. .NET Framework 2.0 Backward Compatibility

**Decision: Carry forward with explicit justification.**

The tool targets .NET Framework 2.0 for the following reasons:

1. **Pre-installed availability:** .NET Framework 2.0 is included in Windows Server 2003 SP2+ and is an optional feature in Windows Server 2008 through Windows Server 2022. It requires no additional installation on these systems.
2. **Minimized deployment dependencies:** Security assessment tools are often deployed in environments with strict change-management policies. Using a pre-installed framework avoids the need for framework installation as a prerequisite.
3. **Target environment breadth:** Active Directory environments being assessed may include legacy domain controllers and management workstations running older Windows versions.

**Accepted trade-offs:**

| Trade-off | Mitigation |
|---|---|
| No LINQ | Use explicit loops and `Dictionary`/`List` operations |
| No `HashSet<T>` | Use `Dictionary<string, bool>` with `ContainsKey()` (see Section 20.5) |
| No modern TLS defaults | Rely on `AuthenticationTypes.Secure` for SSPI-negotiated authentication as the default (signing/sealing are typically negotiated but depend on DC/client policies; use LDAPS via `AuthenticationTypes.Secure` &#124; `AuthenticationTypes.SecureSocketsLayer` when guaranteed transport encryption is required) |
| No `async`/`await` | The tool is single-threaded by design; async is not needed |
| No `SecureString` in `DirectoryEntry` | `DirectoryEntry` accepts only `string` for passwords regardless of framework version |

**Alternative consideration:** .NET Framework 4.0+ would provide `HashSet<T>`, LINQ, and improved TLS defaults, but would not be pre-installed on Windows Server 2003/2008 without an update. If the minimum target is raised to Windows Server 2012 in a future version, .NET Framework 4.5 could be considered.

---

## 16. Risk Classification and Insecure Delegation Detection

> **Provenance:** This section integrates the functionality of the ADeleginator companion tool directly into the new tool. The new tool performs all delegation enumeration and risk classification natively — it does not depend on or invoke ADeleg or ADeleginator externally.

### 16.1. Overview: Integrated Risk Classification

ADeleginator is a separate wrapper tool that post-processes ADeleg's CSV output to identify insecure delegations via regex-based pattern matching. This wrapper approach has fundamental limitations:

1. **Loss of structured data:** By the time ADeleginator processes results, SIDs have been resolved to display names, access masks rendered as text, and GUIDs resolved to schema names. Filtering must reverse-engineer these transformations through regex matching, which is fragile and lossy.
2. **Name-based matching is locale-dependent:** ADeleginator matches trustees and resources by name (e.g., `"Domain Users"`, `"Domain Admins"`). In non-English AD environments, these names are localized (e.g., `"Domänen-Benutzer"` in German), causing silent misses.
3. **External dependency:** Requiring a separate ADeleg binary introduces version compatibility concerns and deployment complexity.

The new tool performs risk classification **during** the scan, when raw SIDs, access masks, GUIDs, and object metadata are available as typed values. This eliminates regex fragility, enables SID-based matching (language-independent), and produces richer risk annotations.

### 16.2. CSV Output: New Risk and Exploitability Columns

Two columns are added to the CSV output schema (extending the schema defined in Section 10):

| Column | Name | Description |
|---|---|---|
| 6 | **Risk Level** | A risk classification for the row. One of: `Critical`, `High`, `Medium`, `Informational`, or empty (blank) for rows that do not match any risk rule. |
| 7 | **Current User Can Exploit** | `Yes` if the ACE trustee SID matches the current user's SID or any of the current user's transitive group SIDs; empty (blank) otherwise. |

The `Risk Level` column is populated for every CSV row by evaluating the risk classification rules defined in Section 18. Rows that do not match any risk rule have an empty value. **Note on schema change:** The addition of these two columns changes the CSV header and column count from 5 to 7. The first 5 columns (`Resource`, `Trustee`, `Trustee type`, `Category`, `Details` — as defined in Section 10) retain their original names, positions, and semantics. The two new columns are appended at positions 6 and 7. Consumers that parse by column position (rather than by header name) will need to be updated.

**Rationale for columns rather than separate files only:** Columns in the main CSV enable downstream tools to filter, sort, and pivot on risk level without a separate join operation. Risk classification is visible in context alongside the full delegation details. Separate filtered reports (Section 20.2) are an additional convenience, not a replacement.

### 16.3. Unsafe Trustee Identification

ADeleginator identifies unsafe trustees using a regex pattern of three hardcoded names (`Domain Users`, `Authenticated Users`, `Everyone`) plus the current user's group memberships. The new tool replaces this with SID-based matching using a structured, configurable unsafe trustee list.

#### 16.3.1. Baseline Unsafe Trustee SIDs

The following SIDs are recognized as unsafe trustees by default. SID-based matching is language-independent and unambiguous:

| # | SID | Identity | Rationale |
|---|---|---|---|
| 1 | `S-1-1-0` | Everyone | Universal identity that includes all users; since Windows Server 2003, `Everyone` does **not** include `Anonymous Logon` by default (controlled by the group policy "Network access: Let Everyone permissions apply to anonymous users") |
| 2 | `S-1-5-11` | Authenticated Users | Includes every authenticated identity in the forest |
| 3 | `S-1-5-7` | Anonymous Logon | Unauthenticated access; dangerous if delegations are granted to it |
| 4 | `S-1-5-32-554` | Pre-Windows 2000 Compatible Access | Often includes `Authenticated Users` as a member; delegations to this group are effectively delegations to all users |
| 5 | `{domainSID}-513` | Domain Users (per domain) | Every domain user account is a member |
| 6 | `{domainSID}-515` | Domain Computers (per domain) | Every domain-joined computer is a member; compromise of any workstation grants these permissions |
| 7 | `{domainSID}-514` | Domain Guests (per domain) | Guest accounts; should never hold delegations |

Domain-relative SIDs (those with a `{domainSID}-` prefix) are expanded for each known domain discovered via `Forest.GetCurrentForest().Domains` (or `Forest.GetForest(ctx).Domains` with `--server`). For each domain, the domain SID is retrieved within a `using` block: `using (DirectoryEntry entry = domain.GetDirectoryEntry()) { byte[] sidBytes = (byte[])entry.Properties["objectSid"][0]; SecurityIdentifier domainSid = new SecurityIdentifier(sidBytes, 0); /* use domainSid.Value to construct expanded SID strings, e.g., domainSid.Value + "-513" */ }`. The `[0]` index is required because `Properties["objectSid"]` returns a `PropertyValueCollection`, and the `using` block prevents ADSI handle leaks (as specified in Section 9, Step 1).

**Comparison with ADeleginator:** ADeleginator uses name-based regex matching for `"Domain Users"`, `"Authenticated Users"`, and `"Everyone"`. The new tool uses SID-based matching for all baseline trustees, which is correct in localized environments and immune to naming variations. ADeleginator omits Anonymous Logon, Pre-Windows 2000 Compatible Access, Domain Computers, and Domain Guests — all of which are legitimate unsafe trustee concerns.

#### 16.3.2. Configurable Unsafe Trustee Definitions

The baseline unsafe trustee list is configurable via the XML delegation/template format (see Section 11). The XML schema supports:

- Adding custom unsafe trustee SIDs (e.g., organization-specific broad groups)
- Removing baseline unsafe trustee SIDs (e.g., if an organization has locked down `Pre-Windows 2000 Compatible Access`)
- Specifying trustees by SID pattern (e.g., `{domainSID}-513` for Domain Users across all domains)

At runtime, SID patterns containing `{domainSID}` are expanded for each known domain, similarly to how delegation location wildcards (`DC=*`) are expanded in Section 11.

### 16.4. Tier 0 (Critical) Resource Identification

ADeleginator uses a hardcoded list of 20 resource names matched by regex. The new tool replaces this with a structured, SID-based and DN-pattern-based Tier 0 identification system.

#### 16.4.1. Expanded Tier 0 Resource Definitions

The following resources are classified as Tier 0 by default. Resources are identified by SID (for security principals) or by DN pattern and object class (for non-principal objects):

**Tier 0 Security Principals (identified by SID):**

| # | SID Pattern | Identity | Rationale |
|---|---|---|---|
| 1 | `{domainSID}-500` | Administrator | Built-in administrator account — full domain control |
| 2 | `{domainSID}-502` | krbtgt | Kerberos ticket-granting account — compromise enables Golden Ticket attacks |
| 3 | `{domainSID}-512` | Domain Admins | Full administrative control over the domain |
| 4 | `{domainSID}-516` | Domain Controllers | Machine accounts for all DCs |
| 5 | `{forestRootDomainSID}-518` | Schema Admins | Can modify the AD schema — forest-wide impact (forest root domain only) |
| 6 | `{forestRootDomainSID}-519` | Enterprise Admins | Full administrative control over the entire forest (forest root domain only) |
| 7 | `{domainSID}-521` | Read-Only Domain Controllers | RODC machine accounts |
| 8 | `{domainSID}-526` | Key Admins | Can perform privileged key operations |
| 9 | `{forestRootDomainSID}-527` | Enterprise Key Admins | Forest-wide key administration (forest root domain only) |
| 10 | `S-1-5-32-544` | BUILTIN\Administrators | Local administrators group |
| 11 | `S-1-5-32-548` | Account Operators | Can modify most user and group accounts |
| 12 | `S-1-5-32-549` | Server Operators | Can administer domain controllers |
| 13 | `S-1-5-32-550` | Print Operators | Can load drivers on DCs — code execution vector |
| 14 | `S-1-5-32-551` | Backup Operators | Can back up and restore domain controller data — can extract the AD database |

**Note on ignored trustee list:** Account Operators (`S-1-5-32-548`), Server Operators (`S-1-5-32-549`), Print Operators (`S-1-5-32-550`), and Backup Operators (`S-1-5-32-551`) are **not in the ignored trustee list** (see Section 6, which explicitly notes these groups are reported by default). Their ACEs appear in the output and are risk-classified when they match the Tier 0 resource list. No change to the ignored trustee list is needed.

**Tier 0 Structural Objects (identified by DN pattern and/or object class):**

| # | Identification Method | Identity | Rationale |
|---|---|---|---|
| 15 | DN = `{domainDN}` (the domain root object) | Domain root object | ACEs here can grant domain-wide permissions via inheritance |
| 16 | DN = `CN=AdminSDHolder,CN=System,{domainDN}` | AdminSDHolder | SDProp copies this DACL to all protected accounts |
| 17 | DN = `OU=Domain Controllers,{domainDN}` | Domain Controllers OU | Contains all DC machine accounts |
| 18 | DN = `CN=Users,{domainDN}` | Users container | Default location for privileged accounts |
| 19 | DN = `CN=Schema,CN=Configuration,{forestRootDN}` | Schema partition root | Controls the AD schema |
| 20 | DN = `CN=Configuration,{forestRootDN}` | Configuration partition root | Controls forest-wide configuration |
| 21 | DN = `CN=Sites,CN=Configuration,{forestRootDN}` | Sites container | Controls AD replication topology |
| 22 | DN = `CN=Partitions,CN=Configuration,{forestRootDN}` | Partitions container | Controls naming context references |
| 23 | `objectClass=trustedDomain` | Trust objects | Control trust relationships — can enable cross-forest attack paths |
| 24 | `objectClass=pKICertificateTemplate` in `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{forestRootDN}` | Certificate templates | Misconfigured templates enable ESC1–ESC8 privilege escalation |
| 25 | `objectClass=pKIEnrollmentService` in `CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{forestRootDN}` | Enterprise CA objects | Certificate Authority enrollment service objects |
| 26 | Objects with `objectClass=groupPolicyContainer` linked (via `gpLink`) to Tier 0 OUs/domains | GPOs linked to Tier 0 containers | Modification of linked GPOs grants code execution on Tier 0 systems |

**Comparison with ADeleginator:** ADeleginator defines 20 resources by name, matched via regex. The new tool uses SID-based matching for principals (language-independent, unambiguous) and DN-pattern/object-class matching for structural objects (structural, not name-dependent). The new list is significantly expanded — ADeleginator omits Schema/Configuration partition roots, Sites, Partitions, trust objects, ADCS certificate templates and enrollment services, Key Admins, Enterprise Key Admins, and RODC accounts.

#### 16.4.2. Tier 0 GPO Detection

ADeleginator includes `"GPO linked to Tier Zero container"` as a Tier 0 resource but provides no mechanism to resolve which GPOs are linked. The new tool implements this by:

1. For each Tier 0 DN entry that is a valid GPO link target — i.e., domains, OUs, or sites (note: `CN=Users` is a container, not an OU, and is **not** a valid GPO link target in Active Directory) — read the `gpLink` attribute via `(string)entry.Properties["gpLink"][0]` (note: `Properties["gpLink"]` returns a `PropertyValueCollection`, so a `Count > 0` check must precede `[0]` indexing — `gpLink` is often absent on containers that have no linked GPOs, in which case this step is skipped for that container; a `string` cast is also required; the `DirectoryEntry` should be obtained via `using` to prevent handle leaks). This includes the domain root and Domain Controllers OU (which are always in the baseline Tier 0 set) as well as any custom Tier 0 OUs added via `<tier0Resources>` configuration (Section 16.4.3).
2. Parse the `gpLink` value, which is a string of the form `[LDAP://CN={GUID},CN=Policies,CN=System,{domainDN};status]`, extracting each linked GPO's DN.
3. Add each linked GPO DN to the Tier 0 resource set.
4. This resolution is performed once during the bootstrap phase (after domain enumeration, before the main scan) and cached for the duration of the scan.

**Implementation in .NET Framework 2.0:** Read `gpLink` as a string property from the relevant `DirectoryEntry` objects. Parse the semicolon-and-bracket-delimited format using `String.Split()` and `String.IndexOf()` — no regex is needed for this structured format.

#### 16.4.3. Configurable Tier 0 Definitions

The Tier 0 resource list is configurable via the XML delegation/template format (see Section 11). The XML schema supports:

- Adding custom Tier 0 resources by SID, DN, DN pattern, or object class
- Removing default Tier 0 resources (e.g., if an organization intentionally delegates control of the Users container)
- Specifying Tier 0 sub-tiers (e.g., `Tier0-Critical` vs. `Tier0-High`) for more granular risk classification

#### 16.4.4. Tier 0 Resource Matching During the Scan

During the main scan, each object is checked against the Tier 0 resource set using:

1. **SID-based check:** If the object has an `objectSid` attribute, parse it as a `SecurityIdentifier` and look up its `Value` in the Tier 0 SID `Dictionary<string, bool>`.
2. **DN-based check:** Look up the object's `distinguishedName` in the Tier 0 DN `Dictionary<string, bool>` (constructed with `StringComparer.OrdinalIgnoreCase`).
3. **Object-class-based check:** For objects matching Tier 0 object class rules, check the object's most-specific `objectClass` value against the Tier 0 object class set. Some object-class rules are **container-scoped** — that is, the object class match is only valid when the object resides within (or directly under) a specific container DN. For example, `pKICertificateTemplate` objects are Tier 0 only when located under `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{forestRootDN}`, and `pKIEnrollmentService` objects only when under `CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{forestRootDN}`. The container scope is evaluated by checking whether the object's `distinguishedName` ends with the container DN (case-insensitive comparison). Object-class rules without a container qualifier (e.g., `trustedDomain`) apply globally regardless of location.

If any check matches, the object is classified as a Tier 0 resource for risk classification purposes.

---

## 17. Dangerous Delegation Type Detection

ADeleginator identifies seven dangerous delegation patterns by regex-matching the human-readable `Details` field. The new tool replaces this with access-mask-based and GUID-based detection using the typed `ActiveDirectoryAccessRule` properties available during the scan.

### 17.1. Baseline Dangerous Delegation Types

The following delegation types are classified as dangerous by default, organized by the `ActiveDirectoryRights` flags and object type GUIDs that identify them:

**Category A — Full-Control Delegations (always dangerous regardless of object type GUID):**

| # | Detection Criteria | ADeleginator Equivalent | Human-Readable Description |
|---|---|---|---|
| 1 | Owner SID matches unsafe trustee | `"owns"` | Ownership grants implicit WRITE_DAC + READ_CONTROL — the owner can rewrite the entire DACL |
| 2 | `ActiveDirectoryRights.WriteOwner` | `"Change the owner"` | Can take ownership, then rewrite the DACL |
| 3 | `ActiveDirectoryRights.WriteDacl` | `"add/delete delegations"` | Can directly modify the DACL to grant any permission |
| 4 | `(rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll` — i.e., all bits of `0xF01FF` are set in the access mask | *(not detected by ADeleginator)* | Full control — grants every possible permission on the object |
| 5 | `(rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericWrite) == ActiveDirectoryRights.GenericWrite` — i.e., all bits of `0x20028` are set in the access mask | *(not detected by ADeleginator)* | `ReadControl` + `WriteProperty` + `Self` — very broad write access |

**Note on GenericAll and GenericWrite:** The `System.DirectoryServices.ActiveDirectoryRights` enum defines `GenericAll` (value `983551` / `0xF01FF`) which combines all standard and specific rights into full control, and `GenericWrite` (value `131112` / `0x20028`) which decomposes into `ReadControl` (`0x20000`) + `WriteProperty` (`0x20`) + `Self` (`0x8`). The `ReadControl` component is a read-only right, so the dangerous components of `GenericWrite` are `WriteProperty` and `Self`.

**Important distinction from standard Windows GENERIC_* bits:** The values `0xF01FF` and `0x20028` in the `ActiveDirectoryRights` enum are **not** the standard Windows generic access mask bits (`GENERIC_ALL = 0x10000000`, `GENERIC_WRITE = 0x40000000`). Active Directory maps generic access bits to object-type-specific rights when storing ACEs. The `ActiveDirectoryRights` enum values reflect the **mapped (resolved) specific rights**, not the raw generic bits. When an ACE is read from AD via `ActiveDirectoryAccessRule.ActiveDirectoryRights`, the property returns the access mask as stored in the ACE — which contains the mapped values (`0xF01FF` for full control, `0x20028` for generic write), not the pre-mapping generic bits. Consequently, checking `((int)rule.ActiveDirectoryRights & 0xF01FF) == 0xF01FF` for GenericAll and `((int)rule.ActiveDirectoryRights & 0x20028) == 0x20028` for GenericWrite is correct — these bit patterns will be present in stored ACEs that were created with full-control or generic-write access.

**Category B — Dangerous Write Delegations (dangerous when the object type GUID targets a sensitive attribute or is empty):**

| # | Detection Criteria | Object Type GUID | Human-Readable Description | Attack Vector |
|---|---|---|---|---|
| 6 | `WriteProperty` | `Guid.Empty` (all properties) | `"write all properties"` | Modify any attribute — subsumes all specific attribute attacks |
| 7 | `WriteProperty` | GUID of `servicePrincipalName` | Write SPN | Kerberoasting — set an SPN on a user, then request a ticket encrypted with the user's password hash |
| 8 | `WriteProperty` | GUID of `msDS-AllowedToActOnBehalfOfOtherIdentity` | Write RBCD | Resource-Based Constrained Delegation — configure the target to accept delegation from an attacker-controlled account |
| 9 | `WriteProperty` | GUID of `msDS-KeyCredentialLink` | Write Key Credential Link | Shadow Credentials — add an attacker-controlled key credential, then authenticate as the target via PKINIT |
| 10 | `WriteProperty` | GUID of `userAccountControl` | Write userAccountControl | Disable Kerberos pre-authentication (AS-REP Roasting), set trusted-for-delegation, or disable the account |
| 11 | `WriteProperty` | GUID of `scriptPath` | Write logon script path | Code execution — change the user's logon script to an attacker-controlled path |
| 12 | `WriteProperty` | GUID of `msDS-GroupMSAMembership` | Write gMSA membership | gMSA abuse — add an attacker-controlled principal to the gMSA's retrieval group |
| 13 | `WriteProperty` | GUID of `member` | Write group membership | Add an attacker-controlled account to the target group |
| 14 | `WriteProperty` | GUID of `gpLink` | Write GPO link | Link an attacker-controlled GPO to a container |
| 15 | `WriteProperty` | GUID of `gPCFileSysPath` | Write GPO file path | Redirect GPO file path to an attacker-controlled share |
| 16 | `WriteProperty` | GUID of `msDS-AllowedToDelegateTo` | Write constrained delegation target | Configure constrained delegation to a target service |

**Category C — Dangerous Control Access Rights (identified by `ExtendedRight` flag and control access right GUID):**

| # | Detection Criteria | Control Access Right GUID | Human-Readable Description | Attack Vector |
|---|---|---|---|---|
| 17 | `ExtendedRight` | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes) | Replicate directory changes | Required for DCSync (part 1 of 2) |
| 18 | `ExtendedRight` | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All) | Replicate directory changes (all) | Required for DCSync (part 2 of 2) — together with #17, enables full credential theft |
| 19 | `ExtendedRight` | `00299570-246d-11d0-a768-00aa006e0529` (User-Force-Change-Password) | Reset password | Reset any user's password without knowing the current password |
| 20 | `ExtendedRight` | `Guid.Empty` (all extended rights) | All extended rights | Grants every control access right — subsumes DCSync, password reset, and all others |

**Category D — Dangerous Create/Delete Delegations:**

| # | Detection Criteria | ADeleginator Equivalent | Human-Readable Description |
|---|---|---|---|
| 21 | `CreateChild` with `Guid.Empty` | `"create child objects"` | Create any type of child object |
| 22 | `DeleteChild` with `Guid.Empty` | `"delete child objects"` | Delete any type of child object |
| 23 | `Delete` | `"delete"` | Delete the object itself |
| 24 | `DeleteTree` | *(not detected by ADeleginator)* | Delete the object and all its children |

**Category E — Dangerous Validated Writes:**

| # | Detection Criteria | Validated Write GUID | Human-Readable Description | Attack Vector |
|---|---|---|---|---|
| 25 | `Self` | GUID of `Validated-SPN` (`f3a64788-5306-11d1-a9c5-0000f80367c1`) | Validated write to SPN | Kerberoasting vector — validated write may bypass SPN validation checks |
| 26 | `Self` | GUID of `Validated-DNS-Host-Name` (`72e39547-7b18-11d1-adef-00c04fd8d5cd`) | Validated write to DNS host name | Can alter the DNS host name of a computer object |
| 27 | `Self` | `Guid.Empty` (all validated writes) | All validated writes | Grants every validated write |

**Comparison with ADeleginator:** ADeleginator detects 7 delegation types via regex string matching. The new tool detects 27 delegation types via typed access mask and GUID comparisons. The 20 additional types address well-known attack techniques that ADeleginator entirely misses: DCSync, Kerberoasting via SPN write, Shadow Credentials, Resource-Based Constrained Delegation, gMSA abuse, GPO linking/path manipulation, GenericAll/GenericWrite composites, password reset, and others.

### 17.2. Object Type GUID Resolution for Dangerous Attribute Detection

The dangerous delegation types in Categories B and E require comparing the `ActiveDirectoryAccessRule.ObjectType` GUID against specific schema attribute GUIDs and control access right GUIDs. These GUIDs are resolved during the schema loading phase (Step 2 of the pipeline described in Section 9):

1. During schema attribute enumeration (via `ActiveDirectorySchema.GetCurrentSchema().FindAllProperties()`, or `ActiveDirectorySchema.GetSchema(ctx).FindAllProperties()` with `--server` — see Section 9, Step 2), build a `Dictionary<string, Guid>` mapping attribute `Name` (lDAPDisplayName) to `SchemaGuid`. This name-to-GUID map is needed because the dangerous attribute definitions reference attributes by name.
2. Look up each dangerous attribute by name (e.g., `"servicePrincipalName"`, `"msDS-AllowedToActOnBehalfOfOtherIdentity"`) and retrieve its `SchemaGuid`.
3. Store the resolved dangerous attribute GUIDs in a `Dictionary<Guid, string>` mapping GUID to attack description, for O(1) lookup during the scan.
4. If a dangerous attribute name is not found in the schema (e.g., `msDS-KeyCredentialLink` may not exist in older schema versions), log a warning to stderr and skip that detection rule.

Control access right GUIDs (Category C) are well-known fixed values that do not require schema lookup.

### 17.3. DCSync Compound Detection

DCSync requires **both** `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` extended rights, granted to the same trustee SID, on the domain root object. Neither right alone is sufficient for DCSync. The tool implements compound detection:

1. During the scan, when an `ExtendedRight` ACE with the `DS-Replication-Get-Changes` GUID is found on a domain root object, record the trustee SID and resource.
2. When an `ExtendedRight` ACE with the `DS-Replication-Get-Changes-All` GUID is found on the same domain root object for the same trustee SID, flag the combination as a `Critical` risk DCSync finding.
3. Each individual replication right is still flagged independently (as `High` risk), since they are unusual for non-DC principals.

**Implementation in .NET Framework 2.0:** Use a `Dictionary<string, Dictionary<string, int>>` where the outer dictionary is keyed by resource DN with `StringComparer.OrdinalIgnoreCase` (since Distinguished Names are case-insensitive in Active Directory), and the inner dictionary is keyed by trustee SID `Value` (case-sensitive, as SID strings have a fixed format). The `int` value is a bitmask tracking which replication rights have been seen (bit 0 / value `1` = DS-Replication-Get-Changes, bit 1 / value `2` = DS-Replication-Get-Changes-All; value `3` = both present = DCSync compound condition). After scanning each domain root object's ACEs, check for trustee entries where the bitmask equals `3`.

### 17.4. Configurable Dangerous Delegation Definitions

The dangerous delegation type list is configurable via the XML delegation/template format (see Section 11). The XML schema supports:

- Adding custom dangerous delegation types by access mask flags, object type GUID, and control access right GUID
- Removing default dangerous delegation types (e.g., if an organization legitimately delegates password reset to a help desk)
- Specifying custom risk levels for each dangerous delegation type

---

## 18. Risk Classification Rules

ADeleginator uses a binary classification: a delegation either matches the insecure pattern or it does not. The new tool uses a graduated risk severity model that considers the combination of trustee risk, resource criticality, and delegation danger.

### 18.1. Risk Severity Levels

| Level | Meaning | Action Required |
|---|---|---|
| **Critical** | Direct path to domain compromise. Exploitation by any authenticated user (or unauthenticated, for Anonymous Logon) could result in full domain takeover. | Immediate remediation required. |
| **High** | Significant privilege escalation risk. Exploitation requires compromise of a broadly-scoped account or group, and the target is a Tier 0 resource or the delegation type enables credential theft or persistence. | Remediation strongly recommended. |
| **Medium** | Elevated risk that does not directly lead to domain compromise but expands the attack surface. Includes dangerous delegation types granted to broadly-scoped trustees on non-Tier-0 objects, or less-dangerous delegations on Tier 0 objects. | Review and remediate as part of delegation hygiene. |
| **Informational** | Delegation patterns that are atypical or warrant awareness but do not represent a concrete attack path under normal conditions. | Review during periodic security assessments. |

### 18.2. Risk Classification Matrix

The risk level for a given ACE or owner finding is determined by the intersection of three dimensions:

1. **Trustee classification**: Is the trustee in the unsafe trustee set (Section 16.3)?
2. **Resource classification**: Is the target resource in the Tier 0 set (Section 16.4)?
3. **Delegation type classification**: Is the delegation type in the dangerous set (Section 17.1), and if so, which category?

| Unsafe Trustee? | Tier 0 Resource? | Dangerous Delegation Category | Risk Level |
|---|---|---|---|
| Yes | Yes | A (Full-Control) | **Critical** |
| Yes | Yes | C (DCSync compound — both replication rights) | **Critical** |
| Yes | Yes | B (Dangerous Write) | **High** |
| Yes | Yes | C (Single replication right, password reset, or all extended rights) | **High** |
| Yes | Yes | D (Create/Delete) | **High** |
| Yes | Yes | E (Dangerous Validated Write) | **High** |
| Yes | No | A (Full-Control) | **High** |
| Yes | No | B or C (non-DCSync) | **Medium** |
| Yes | No | D or E | **Medium** |
| No | Yes | A, B, or C | **Informational** |
| No | Yes | D or E | *(no risk tag)* |
| No | No | Any | *(no risk tag)* |

**Notes:**

- Domain root objects are inherently Tier 0 (Section 16.4.1, item #15). DCSync compound detection targets domain root objects, so it always falls under the `Critical` row.
- Owner findings follow the same matrix: if the owner SID is an unsafe trustee and the object is Tier 0, the risk level is `Critical`; if non-Tier-0, `High`.
- **Deny ACEs are not assigned a risk level**, since deny ACEs restrict rather than grant access. This corrects ADeleginator's approach, which only checks for `"Allow"` in the Category field but does not explicitly exclude deny ACEs.
- Warning-category rows (unreadable SDs, DACL protection, non-canonical ACLs, deleted trustees) do not receive a risk level, as they represent structural issues rather than delegation risks.

### 18.3. Implementation Approach

During the scan, after each ACE passes the filtering logic (or its .NET equivalent of `is_ace_interesting()`), the tool evaluates the risk classification matrix:

1. **Check trustee**: Look up the ACE's trustee SID in the unsafe trustee `Dictionary<string, bool>` (keyed by `SecurityIdentifier.Value`). If found, set `isUnsafeTrustee = true`.
2. **Check resource**: Look up the current object's DN (or SID, for security principals) in the Tier 0 resource set. If found, set `isTier0Resource = true`.
3. **Check delegation type**: Evaluate the ACE's `ActiveDirectoryRights` flags and `ObjectType` GUID against the dangerous delegation type definitions (Section 17.1). Determine the matching category (A through E) and whether a DCSync compound condition exists.
4. **Apply the matrix**: Use the three boolean/categorical values to determine the `Risk Level` from the matrix in Section 18.2.
5. **Store the risk level** alongside the ACE data for inclusion in the CSV `Risk Level` column.

This evaluation is O(1) per ACE (dictionary lookups + bitwise flag checks), adding negligible overhead to the scan.

### 18.4. Risk Level for Specific Row Types

The `Risk Level` column should be:

- **Populated** for: `Owner` rows where the owner is an unsafe trustee, and all `Allow ACE` rows that match a risk rule.
- **Empty (blank)** for: `Delegation`/`Built-in`/`Expected allow ACE found` summary rows (these are aggregation rows that may correspond to multiple constituent ACEs with different risk levels; consumers should derive summary-level risk from the individual `Allow ACE` rows that follow), `Owner` rows where the owner is not an unsafe trustee, all `Warning` rows, all `Deny ACE` rows, and any Allow ACE rows that do not match any risk rule.

---

## 19. Current User Context Reporting

ADeleginator enriches its analysis with the current user's group memberships, enabling identification of delegations directly exploitable by the operator. The new tool incorporates this concept with improvements.

### 19.1. Current User SID and Group Resolution

At startup (before the main scan), the tool:

1. Retrieves the current user's SID via `System.Security.Principal.WindowsIdentity.GetCurrent().User` (returns a `SecurityIdentifier`).
2. Resolves the current user's transitive group memberships using the `WindowsIdentity.Groups` property:
   ```csharp
   WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent();
   SecurityIdentifier currentUserSid = currentIdentity.User;
   IdentityReferenceCollection groupSids = currentIdentity.Groups;
   // groupSids contains SecurityIdentifier objects for all transitive group memberships
   ```
   The `Groups` property returns the user's token group SIDs (equivalent to the `tokenGroups` constructed attribute), which include all transitive/nested group memberships. This is a .NET Framework 2.0 managed API that does not require any LDAP query or `DirectoryEntry` usage, avoiding the need for `--server` prefix handling.
3. Stores the current user's SID and all group SIDs in a **separate** `Dictionary<string, bool>` (the "current user principals set"), keyed by `SecurityIdentifier.Value`. This set is **not** merged into the policy-based unsafe trustee set (Section 16.3).
4. Reports the current user context to stderr:
   ```
   [i] Running as: DOMAIN\username (S-1-5-21-...), member of {n} groups ({m} non-Tier-0)
   ```
   Here, `{n}` is the total count of SIDs returned by `WindowsIdentity.Groups` and `{m}` is `{n}` minus the count of those group SIDs that are present in the Tier 0 SID Dictionary (i.e., `{m}` counts the group SIDs that are **not** in the Tier 0 set).

**Rationale for `WindowsIdentity.Groups` over `tokenGroups` via LDAP:** ADeleginator uses the `memberOf` attribute via an LDAP query, which only returns direct group memberships and misses nested/transitive groups. An alternative approach would use the `tokenGroups` constructed attribute via `DirectoryEntry.RefreshCache()`, but `WindowsIdentity.Groups` provides the same transitive group resolution without requiring an LDAP query. This avoids `--server` targeting concerns (since it reads from the local access token, not from a directory server) and is the idiomatic .NET Framework 2.0 approach. The `Groups` property returns `IdentityReferenceCollection` containing `SecurityIdentifier` objects, which can be iterated directly.

**Limitation:** `WindowsIdentity.GetCurrent().Groups` reflects the group memberships in the current process's access token, which is populated at logon time. If the operator's group memberships have changed since logon (e.g., groups added or removed), the token may be stale. Additionally, when the tool is run with explicit credentials (`--username`) targeting a different domain, the `Current User Can Exploit` column reflects the local process identity's groups, not the explicit credential's groups. This is an acceptable trade-off: the `Current User Can Exploit` column is an advisory annotation (not a security control), and the primary risk classification (`Risk Level` column) is unaffected since it uses the policy-based unsafe trustee set.

**Fixes for ADeleginator bugs:**

| ADeleginator Bug | Fix |
|---|---|
| **All-or-nothing group append:** If user has any non-Tier-0 group, all groups (including Tier 0) are appended to unsafe list | **Eliminated:** Current user groups are stored in a separate set and never merged into the policy-based unsafe trustee set |
| **Space-join bug:** Group array is space-joined instead of pipe-joined, creating a never-matching regex | **Eliminated:** Groups are stored individually in a `Dictionary<string, bool>` keyed by SID; no string concatenation involved |
| **`memberOf` misses transitive groups:** `memberOf` only returns direct group memberships | **Fixed:** Uses `WindowsIdentity.GetCurrent().Groups` to resolve all transitive group memberships from the local access token — no LDAP query needed |

### 19.2. Per-Finding Exploitability Annotation

The `Current User Can Exploit` column (column 7 in the CSV, defined in Section 16.2) is populated as follows:

- During the scan, each ACE's trustee SID is compared against the current user principals `Dictionary<string, bool>` using `ContainsKey()`.
- If the trustee SID matches the current user's SID or any of the current user's transitive group SIDs, the column value is `Yes`.
- Otherwise, the column value is empty (blank).

This per-row annotation enables the report consumer to immediately identify which findings are exploitable by the person who ran the tool — a direct analog to ADeleginator's user-group-augmented unsafe trustee detection, but more precisely targeted (per-ACE annotation rather than bulk addition to the unsafe trustee list).

---

## 20. Risk Output and Console Feedback

### 20.1. Risk Summary Messages

After the scan completes, the tool prints a risk summary to stderr:

```
[i] Risk summary: Critical: {criticalCount}, High: {highCount}, Medium: {mediumCount}, Informational: {informationalCount}
```

If any `Critical` or `High` findings exist, an additional alert is printed:

```
[!] {criticalCount} Critical and {highCount} High risk delegations found. Review the output for details.
```

If no findings of any risk level exist:

```
[+] No insecure delegations detected.
```

These messages are emitted via `Console.Error.WriteLine()` to keep stdout clean for CSV data. The `[!]` / `[+]` / `[i]` prefix conventions from ADeleginator are adopted for consistency.

### 20.2. Separate Filtered Output Reports

The tool supports filtered risk output via the following CLI options:

| Option | Description |
|---|---|
| `--risk-csv <path>` | Write a filtered CSV containing only rows whose `Risk Level` column meets the `--risk-level` threshold (default: Medium, i.e., Critical, High, and Medium findings). Uses the same schema as the main output (including the `Risk Level` and `Current User Can Exploit` columns). |
| `--risk-level <level>` | Minimum risk level to include in the `--risk-csv` output. One of: `Critical`, `High`, `Medium`, `Informational`. Default: `Medium` (includes Critical, High, and Medium). Has no effect unless `--risk-csv` is also specified. |

#### Filtered Report Behavior

- If both `--csv` and `--risk-csv` are specified, the main unfiltered CSV and the filtered risk CSV are both generated from the same scan — no additional AD queries are needed.
- If `--risk-csv` is specified without `--csv`, only the filtered risk CSV is generated. The main unfiltered CSV is **not** written to stdout. (The default CSV-to-stdout behavior described in Section 13.8 applies only when **neither** `--csv` **nor** `--risk-csv` is specified.)
- If `--csv` is specified without `--risk-csv`, only the main unfiltered CSV is generated.
- The filtered report includes a header row and uses the same RFC 4180 formatting and UTF-8 (no BOM) encoding as the main CSV (see Section 10).
- If no findings meet the risk level threshold, the filtered report contains only the header row (an empty result is still a valid CSV file). This differs from ADeleginator, which does not create the file if no findings exist — always creating the file simplifies downstream tooling.
- The file is written using `StreamWriter` with `new UTF8Encoding(false)` (UTF-8 without BOM).

#### Comparison with ADeleginator Output

| ADeleginator Behavior | New Tool Behavior |
|---|---|
| Produces `ADeleg_InsecureTrusteeDelegationReport_<ddMMyyyy>.csv` and `ADeleg_InsecureResourceDelegationReport_<ddMMyyyy>.csv` as two separate files | Produces a single `--risk-csv` file containing all risk-classified findings with the `Risk Level` column indicating severity. Consumers can filter by `Risk Level` to replicate the two-file approach. |
| Files are not created if no findings exist | File is always created (may contain only the header row) |
| Filename includes a date stamp (`<ddMMyyyy>`) | Filename is user-specified via `--risk-csv <path>` |
| Uses a simplified 5-column schema (`Trustee`, `TrusteeType`, `Resource`, `Category`, `Delegations`) | Uses the full CSV schema (all columns including `Risk Level` and `Current User Can Exploit`) |

### 20.3. Per-Naming-Context Risk Counts

At verbosity level 1 or higher (`--verbose`), as each naming context completes, the tool reports risk findings for that NC:

```
[i] {ncDN}: {n} objects scanned, {criticalCount} Critical, {highCount} High, {mediumCount} Medium, {informationalCount} Informational risk findings
```

The placeholder names (`{criticalCount}`, `{highCount}`, `{mediumCount}`, `{informationalCount}`) match the names used in the end-of-scan risk summary (Section 20.1) for consistency. This message includes all four risk levels so that per-NC totals are directly comparable with the final summary. The message integrates with the progress reporting described in Section 9 and is gated by the verbosity level defined in Section 13.7.

### 20.4. Improvements Over ADeleginator — Summary of Corrections

The following table summarizes the specific ADeleginator defects and limitations that the new tool's integrated risk classification corrects:

| ADeleginator Defect/Limitation | Correction in New Tool |
|---|---|
| **Name-based regex matching** — fragile, locale-dependent, susceptible to false positives from substring matching | **SID-based and access-mask-based matching** — language-independent, structurally precise, no regex needed |
| **Space-join bug** — current user's groups are space-joined into a single never-matching regex alternative | **Eliminated** — groups are resolved via `WindowsIdentity.Groups` and stored individually in a `Dictionary<string, bool>` keyed by SID |
| **All-or-nothing group append** — if any non-Tier-0 group exists, all groups (including Tier 0) are added as unsafe | **Separated concerns** — current user groups stored in a separate set used only for `Current User Can Exploit` annotation; risk classification is deterministic |
| **Unescaped regex metacharacters** — `"Users (container)"` fails to match due to unescaped parentheses | **Eliminated** — no regex is used; matching is by SID, DN pattern, or object class |
| **Only 3 baseline unsafe trustees** — misses Anonymous Logon, Pre-Windows 2000 Compatible Access, Domain Computers, Domain Guests | **7 baseline unsafe trustee SIDs** — covers the full set of broadly-scoped well-known principals |
| **Only 20 Tier 0 resources** — misses Schema/Configuration roots, trust objects, ADCS objects, Key Admins, RODCs | **26+ Tier 0 resources** — covers critical structural objects, ADCS, trusts, and additional privileged groups |
| **Only 7 dangerous delegation types** — misses DCSync, Kerberoasting, Shadow Credentials, RBCD, GenericAll/GenericWrite | **27 dangerous delegation types** across 5 categories — covers all major AD attack techniques |
| **Binary risk classification** — insecure or not, no gradation | **Four-level graduated risk severity** — Critical, High, Medium, Informational, based on a three-dimensional matrix |
| **External wrapper dependency** — requires ADeleg binary as a separate download | **Integrated** — risk classification performed during the scan using typed data; no external tool needed |
| **No GPO link resolution** — `"GPO linked to Tier Zero container"` is a name pattern without actual GPO link resolution | **Dynamic GPO link resolution** — reads `gpLink` attributes from Tier 0 containers and adds linked GPO DNs to Tier 0 set |
| **`memberOf` attribute for group enumeration** — misses nested/transitive group memberships | **`WindowsIdentity.GetCurrent().Groups`** — resolves all transitive group memberships from the local access token without requiring an LDAP query |
| **No compound detection** — does not detect DCSync (requires two specific rights granted together) | **DCSync compound detection** — tracks both replication rights per trustee per domain root and flags compound condition as Critical |
| **Hardcoded, non-configurable lists** — no user customization without source modification | **XML-configurable lists** — unsafe trustees, Tier 0 resources, and dangerous delegation types are all configurable |
| **No per-finding exploitability annotation** — does not indicate which findings the current user can personally exploit | **`Current User Can Exploit` column** — per-row annotation indicating whether the ACE trustee matches the current user's SID or group SIDs |
| **No deny ACE consideration** — only filters `Category MATCHES "Allow"` | **Explicit deny ACE exclusion** — deny ACEs explicitly excluded from risk classification |
| **PathToADeleg parameter override** — parameter accepted but unconditionally overwritten with default | **Eliminated** — no external ADeleg dependency; all enumeration is native |
| **Silent error suppression during ADeleg execution** — ADeleg errors are silently caught and suppressed | **Eliminated** — no external process invocation; all errors are handled inline with diagnostic output to stderr |
| **No CSV schema validation** — no validation that ADeleg CSV contains expected columns | **Eliminated** — the tool generates its own CSV with a fixed, known schema |

### 20.5. Implementation Data Structures for .NET Framework 2.0

**Note on `Dictionary<string, bool>` for set membership:** .NET Framework 2.0 does not include `HashSet<T>` (introduced in .NET 3.5). `Dictionary<string, bool>` with `ContainsKey()` is the standard .NET Framework 2.0 idiom for O(1) set membership checks. The `bool` value is unused (always `true`).

| Data Structure | Purpose | .NET Framework 2.0 Type |
|---|---|---|
| Unsafe trustee SID set | O(1) lookup during scan | `Dictionary<string, bool>` keyed by `SecurityIdentifier.Value` |
| Tier 0 resource SID set | O(1) lookup for security principals | `Dictionary<string, bool>` keyed by `SecurityIdentifier.Value` |
| Tier 0 resource DN set | O(1) lookup for structural objects | `Dictionary<string, bool>` keyed by DN (`StringComparer.OrdinalIgnoreCase`) |
| Tier 0 object class set | O(1) lookup for class-based matching | `Dictionary<string, bool>` keyed by `objectClass` value (`StringComparer.OrdinalIgnoreCase`) |
| Dangerous attribute GUIDs | O(1) lookup during ACE evaluation | `Dictionary<Guid, string>` mapping GUID to attack description |
| Dangerous control access right GUIDs | O(1) lookup during ACE evaluation | `Dictionary<Guid, string>` mapping GUID to attack description |
| DCSync tracking | Compound detection per trustee per resource | `Dictionary<string, Dictionary<string, int>>` keyed by resource DN (`StringComparer.OrdinalIgnoreCase`), then trustee SID Value; `int` bitmask where bit 0 (value `1`) = DS-Replication-Get-Changes, bit 1 (value `2`) = DS-Replication-Get-Changes-All; value `3` = DCSync compound |
| Current user group SIDs | Exploitability annotation | `Dictionary<string, bool>` keyed by `SecurityIdentifier.Value` |

### 20.6. Performance Impact

The risk classification logic adds only dictionary lookups and bitwise flag checks per ACE — all O(1) operations. The primary additional cost is the startup-phase group resolution via `WindowsIdentity.GetCurrent().Groups` (reads from the local access token — no LDAP query) and `gpLink` resolution (one read per Tier 0 container). These are negligible compared to the main subtree scan.

The `--risk-csv` filtered output does not require a second pass. As each row is emitted during the scan, it can be conditionally written to the `--risk-csv` writer (if its `Risk Level` meets the `--risk-level` threshold) in addition to (or instead of) the main CSV writer. Both outputs are produced in a single pass regardless of whether streaming or in-memory accumulation is used.

### 20.7. Integration with Existing Filtering

The risk classification is applied **after** the existing filtering logic. ACEs that are already filtered out (inherited ACEs, schema defaults, AdminSDHolder ACEs, ignored trustee ACEs, read-only ACEs) are not risk-classified. Risk classification is an additional annotation on ACEs that survive the existing filter — it does not change which ACEs are included or excluded from the output.

This means:

- ACEs for trustees in the "ignored trustee" list (SELF, Local System, BUILTIN\Administrators, Domain Admins, etc.) are already excluded from the output and not risk-classified. Note that Account Operators, Server Operators, Print Operators, and Backup Operators are **not** in the ignored trustee list (see Section 6) — their ACEs are reported by default and are subject to risk classification.
- Built-in delegation ACEs that are hidden by default (visible only with `--show-builtin`) are risk-classified only if `--show-builtin` is enabled.
- The `Risk Level` column is empty for rows with Category values of `Owner` where the owner is not an unsafe trustee, all `Warning` rows, and all `Deny ACE` rows.
