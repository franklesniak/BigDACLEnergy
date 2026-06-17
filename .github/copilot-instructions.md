<!-- markdownlint-disable MD013 -->
# Repository Copilot Instructions (Repo-Wide Constitution)

**Version:** 1.5.20260617.0

## Metadata

- **Status:** Active
- **Owner:** Repository Maintainers
- **Last Updated:** 2026-06-17
- **Scope:** Repo-wide canonical instructions ("constitution") that govern all changes in this repository. This file is the authoritative source of truth for repository rules; all language-specific instruction files and agent entry points defer to it.
- **Related:** [Documentation Writing Style](instructions/docs.instructions.md)

These instructions are authoritative for all changes in this repository.

## Protected Instruction Files

Instruction files and style guides are protected governance files. This rule applies to:

- The repo-wide constitution: `.github/copilot-instructions.md`
- Root agent entry points: `.hermes.md`, `AGENTS.md`, `CLAUDE.md`, and `GEMINI.md`
- Cursor project rules under `.cursor/rules/`
- Modular instruction files under `.github/instructions/`

Agents **MUST NOT** create, edit, delete, rename, or otherwise change protected instruction files unless the repository owner or maintainer has directly and explicitly authorized the specific instruction-file change in the current task. Implied consent is insufficient.

Authorization **MUST NOT** be inferred from:

- An agent-generated plan, rubric, option analysis, or implementation strategy.
- A request to fix code, resolve review feedback, update documentation as needed, or keep files in sync.
- Pre-commit, formatting, linting, validation, or other cleanup work.
- An automated review loop, reusable prompt, or generic permission to make repository changes.

When an agent identifies a warranted instruction or style-guide update without explicit authorization, it **MUST** propose the change separately (for example, as a prompt or Open Question) and wait for explicit approval before editing protected files.

When explicit authorization is granted, keep protected instruction-file edits narrowly scoped, preserve the canonical source-of-truth hierarchy, and update related metadata and version fields according to [Documentation Writing Style](instructions/docs.instructions.md).

## Non-negotiable Safety and Security Rules

1. **No secrets in code or repo**
   - Never hardcode API keys, tokens, connection strings, or credentials.
   - Do not introduce `.env` files or secret placeholders that look like real keys.
   - Never print secrets to stdout/stderr or logs.

2. **Treat all external input as untrusted**
   - Never execute untrusted outputs or commands.
   - Validate and sanitize all inputs at boundaries.
   - Never allow external input to influence file/network access beyond explicitly implemented adapters.

3. **Allowlisted file access only**
   - Read only explicitly allowed inputs/config/rules files and tool-owned runtime dependencies.
   - Refuse path traversal and symlink escapes.

## Pre-commit Discipline (CRITICAL)

**⚠️ ALWAYS run pre-commit checks before committing code.**

Pre-commit hooks are NOT optional. They enforce:

- Code formatting
- Linting
- Trailing whitespace removal
- End-of-file fixes

**Workflow:**

1. Make your code changes
2. Run pre-commit checks locally (e.g., `pre-commit run --all-files` or `npm run lint:md`)
3. Review and commit ALL auto-fixes as part of your change
4. Push to GitHub

**If pre-commit CI fails after a push:**

1. Pull the latest branch
2. Run pre-commit checks locally and review the fixes
3. Add the fixes to commit history before pushing again: prefer amending the commit(s) that introduced the failures, or include the fixes in your next substantive commit on the same branch, rather than landing a standalone formatting-only or lint-only commit (see "What Not to Do" below). For `copilot/**` branches, the auto-fix workflow described under "Auto-Fix Workflow (Safety Net for Copilot Branches)" will normally apply these fixes automatically.
4. Push again (force-push if you amended or rebased earlier commits)

**CI is a safety net, not a substitute for local checks.**

### Data-File Validation

In addition to formatting, linting, trailing-whitespace, and end-of-file fixes, pre-commit also parse-checks structured data files. Run `pre-commit run --all-files` to execute the full hook set. The data-file check currently in place is:

- `check-yaml` — parse-checks `.yml` / `.yaml` files.

`.pre-commit-config.yaml` is the authoritative list of active hooks. Do **not** rely on a hardcoded total hook count when describing the validation model; consult `.pre-commit-config.yaml` directly to see which hooks are wired up.

### For GitHub Copilot Coding Agent (Automated PRs)

**⚠️ CRITICAL: You are an automated agent creating PRs. You MUST follow this workflow:**

When creating automated PRs, you **MUST**:

1. Run all linting/formatting checks as the **FINAL step** before each commit
2. Include **ALL** auto-fixes in the **SAME commit** with your code changes
3. **NEVER** push code that will fail pre-commit CI
4. If pre-commit fails, fix issues and re-run until all checks pass

**The pre-commit step is NON-NEGOTIABLE for automated PRs.**

If you encounter issues:

- Do NOT create a separate "fix formatting" commit
- Do NOT push and wait for CI to fail
- Fix locally, include in your commit, then push

**Failure to follow this will cause CI failures and require manual intervention.**

### Auto-Fix Workflow (Safety Net for Copilot Branches)

This repository includes an auto-fix workflow (`.github/workflows/auto-fix-precommit.yml`) that automatically runs pre-commit hooks and commits fixes for `copilot/**` branches. This serves as a safety net when the Copilot Coding Agent pushes code that fails pre-commit checks.

**How it works:**

- Triggers only on `push` events to `copilot/**` branches
- Only runs when the pusher is `copilot-swe-agent[bot]` (prevents infinite loops)
- Automatically commits any auto-fixes with message `chore: Apply pre-commit auto-fixes [automated]`
- Uses `github-actions[bot]` identity for commits

**Important notes:**

- This is a **safety net**, not a substitute for running pre-commit locally
- Agents should still try to run pre-commit checks before pushing when possible
- The workflow only applies to `copilot/**` branches—human branches are not affected
- Manual intervention may still be required for issues that cannot be auto-fixed

## Workflow Version Pinning

GitHub Actions workflow files in this repository (`.github/workflows/*.yml`) reference both **action versions** (in `uses:` lines) and **tool versions** (passed to actions or shell commands as inputs or arguments). The two categories have different update mechanisms and different rules. Conflating them — or mirroring an action version into a secondary location that Dependabot does not rewrite — produces partial updates where the declared action version moves but related literals silently drift to the old version. The rules below prevent that drift.

For the rationale, see the **Workflow Version Pinning and Dependabot Coherence** ADR in [`.github/TEMPLATE_DESIGN_DECISIONS.md`](https://github.com/franklesniak/copilot-repo-template/blob/HEAD/.github/TEMPLATE_DESIGN_DECISIONS.md).

### Action versions in `uses:` references

- Third-party action versions **MUST** remain directly visible in `uses:` references (for example, `actions/checkout@v6`, `actions/setup-node@v6`) so Dependabot's `github-actions` ecosystem can update them.
- Repeated `uses:` references to the same action across jobs and steps are acceptable when each occurrence is a normal Dependabot-managed `uses:` reference. Dependabot updates each `uses:` line directly.
- Do **NOT** store an action version in a workflow-level `env:` variable, comment, cache key, file path, shell literal, manually constructed image tag, or any other secondary location as a mirror of a `uses:` version. The `uses:` line **MUST** be the only authoritative source for the action version because Dependabot rewrites `uses:` references and will leave unrelated literals stale.
- Do **NOT** copy a Dependabot-managed action version into secondary workflow locations that Dependabot will not reliably rewrite (for example, cache keys, file paths, shell commands, manually constructed image tags, or comments presented as authoritative version state).
- If secondary workflow behavior needs to change when a `uses:` version changes, derive that behavior from a stable source that naturally changes with the workflow or tool configuration. Prefer cache keys scoped to the specific configuration file that governs the cached artifact — for example, `hashFiles('.pre-commit-config.yaml')` for pre-commit caches. Avoid broad wildcard patterns such as `hashFiles('.github/workflows/*.yml')` for cache keys: any unrelated workflow edit would invalidate every job's cache. The goal is to track the configuration that actually drives the cached content, not the workflow definition that consumes it.

### Tool versions passed as action inputs or shell arguments

Tool versions that are not managed by Dependabot — for example, a CLI or runtime version passed as a `with:` input to a `setup-*` action, or a tool version referenced in a shell argument — **SHOULD** still avoid unnecessary duplication. If the same tool version is required in multiple workflow jobs or steps, prefer a single source of truth where GitHub Actions supports one, such as a workflow-level `env:` value for the CLI/tool version.

### Asymmetry: workflow-level `env:` for action versions vs. tool versions

The two categories are **not** symmetric, and the difference is the entire point of this rule:

- **Action versions** (`uses:`): a workflow-level `env:` mirror is **forbidden**. Dependabot will not rewrite the `env:` value, so it would silently desynchronize from the actual `uses:` reference. The `uses:` line is the only authoritative source.
- **Tool versions** (action inputs, shell args): a workflow-level `env:` value is **encouraged** as the single source of truth. Dependabot does not manage these versions, so there is no desync risk; one `env:` value can serve as the source of truth across multiple steps.

### Distinguishing wrapper actions from the tools they install

Action wrapper versions and the tool versions they install are **separate pins** that travel through different channels:

- A `setup-*` action reference such as `actions/setup-node@v6` is the setup action version (managed by Dependabot via `uses:`).
- A `with: node-version:` input is the runtime/CLI version installed by that setup action (not managed by Dependabot; manually maintained).

Both pins exist in the same workflow step, but they update on different cadences and through different mechanisms. Do not conflate them.

### When a Dependabot-managed dependency cannot be expressed without duplication

If a Dependabot-managed dependency genuinely cannot be represented only through Dependabot-managed declarations, and Dependabot would otherwise produce partial updates, add an appropriate `.github/dependabot.yml` `ignore:` entry with a YAML comment explaining why the dependency is intentionally not auto-updated. Use this escape hatch sparingly: it disables automation for that dependency, so it should be applied only when the partial-update problem cannot be solved by removing the duplication or by deriving secondary behavior from a stable source.

### Concrete examples in this repository

- Pinned action majors such as `actions/checkout@v6` and `actions/setup-node@v6` appear repeatedly in workflow `uses:` lines. These are acceptable because each occurrence is a normal Dependabot-managed `uses:` reference.
- A `with:` tool-version input passed to a `setup-*` action is a manually maintained CLI/runtime version (not the setup action's own `uses:` version), so it is **not** a Dependabot `uses:` desynchronization case. If the same tool version is duplicated across jobs, it is a useful candidate for a single source of truth such as a workflow-level `env:` value.

## Repository Self-Containment

All files committed to this repository MUST be interpretable—meaning understandable to a reader without access to private or internal resources—using only the contents of this repository and public references that are clearly linked from it.

This rule governs the meaning of documentation, code comments, and embedded references. It does not require the repository to build or run without standard external dependencies declared in its manifests (for example, PowerShell module dependencies or action dependencies pinned in workflow `uses:` entries).

It applies to, but is not limited to:

- `README.md` and other top-level `*.md` files.
- Files under `.github/`, including workflows, instructions, and design-decision docs.
- Code comments embedded in committed files.

Do not embed references to:

- Work stream identifiers, sprint names, milestone labels, or phase numbers that are not defined inside this repository.
- Ticket, issue, or project IDs that resolve only inside a private or external tracker.
- Internal team, person, or communication-channel names.
- Roadmap, design, or planning documents that are not published in this repository or otherwise publicly resolvable from links in this repository.

Where a future-extension hook needs to be described, phrase the condition in repository-observable terms. For example, prefer "Once a new hook is enabled in `.pre-commit-config.yaml`, ..." rather than referencing the work stream that will introduce those changes.

If a needed reference cannot be expressed in repository-observable terms, follow the existing **What Not to Do** guidance and open an issue or add an explicit "Open Question" in the affected file instead of inventing or importing an external reference.

## Determinism and Correctness Rules

- Prefer deterministic tooling over manual rewriting.
- Sanitation pipelines must be bounded (iteration caps, no-progress detection).
- Preserve formatting, indentation, and ordering when processing structured content.
- Concurrency is allowed, but outputs must be deterministic.

## How to Work (Definition of Done)

For each PR-sized change:

- **Run pre-commit checks locally and fix all issues before committing.**
  - Pre-commit hooks will auto-fix many issues (formatting, linting, whitespace).
  - Always review and commit these auto-fixes as part of your change.
- Add/adjust tests for new behavior.
  - PowerShell: Pester tests in `tests/PowerShell/`
- For data-file changes (YAML, including YAML-based GitHub Actions workflows), run the applicable validation hooks via `pre-commit run --all-files` so that `check-yaml` passes before committing.
- Keep changes small and reviewable; avoid "big bang" refactors.
- Update docs/spec only if behavior is intentionally changed (and note why).
- Ensure:
  - unit tests pass
  - linters/formatters pass
  - no secrets appear in logs, artifacts, or test fixtures

## What Not to Do

- Do not add any feature that executes scripts or commands generated by untrusted sources.
- Do not add telemetry or external logging services without explicit approval.
- Do not weaken security constraints to "make it work."
- Do not add new major dependencies without clear justification in the PR description.
- Do not implement "Copilot agent fixes" or rely on non-public APIs for lint correction.
- Do not silently invent behavior when specs or requirements are ambiguous—open an issue or add an explicit "Open Question" instead.
- Do not create separate "fix formatting" or "fix linting" commits—include all auto-fixes in the same commit as your changes.

## Modular Instructions

This repository uses modular instruction files covering both language-specific standards and cross-cutting repository rules:

| Scope | Instruction File | Applies To |
| --- | --- | --- |
| Git attributes | `.github/instructions/gitattributes.instructions.md` | `**/.gitattributes` |
| Markdown/Docs | `.github/instructions/docs.instructions.md` | `**/*.md`, `**/*.mdc` |
| PowerShell | `.github/instructions/powershell.instructions.md` | `**/*.ps1` |
| YAML | `.github/instructions/yaml.instructions.md` | `**/*.yml`, `**/*.yaml` |

**Note:** The PowerShell instructions include comprehensive guidance on Pester testing.

**To customize for your project:**

- Remove instruction files for scopes you don't use
- Add new instruction files for additional languages or cross-cutting rules as needed
- Update this table to reflect the instruction files present in your project

## Agent Instruction Files

This repository includes agent instruction files at the repository root and under platform-specific rule directories to support multi-platform AI coding agents:

| File | Target Agent(s) |
| --- | --- |
| `.cursor/rules/repository-instructions.mdc` | Cursor Agent |
| `.hermes.md` | Hermes Agent |
| `CLAUDE.md` | Claude Code, GitHub Copilot coding agent |
| `AGENTS.md` | OpenAI Codex CLI, GitHub Copilot coding agent |
| `GEMINI.md` | Gemini Code Assist, GitHub Copilot coding agent |

`.github/copilot-instructions.md` remains the **canonical source of truth** for all repository rules. The agent instruction files are thin entry points: each keeps a minimal inline summary of the highest-priority shared rules for reliability and may add platform-specific guidance that does not conflict with this file.

Thin entry point means "brief shared-rule summary plus platform-specific protocol," not "safe to collapse into a stub." Sections classified in an agent file as platform protocol or required protocol MUST be preserved during downstream stack pruning unless the repository owner explicitly waives that protocol for the retained agent platform.

When explicitly authorized to modify high-priority shared guidance in `.github/copilot-instructions.md` (for example, canonical file location, safety rules, pre-commit expectations, validation commands, or language-instruction references), update the minimal summaries in any remaining agent files as needed. Avoid copying large shared sections into the entry point files.

**To customize for your project:**

- Remove agent files for platforms you do not use
- Keep the remaining agent files limited to minimal inline summaries plus any necessary platform-specific guidance

## Linting and Validation Configurations

This repository includes linting and validation tool configurations that align with the coding standards:

| Tool / Validator | Configuration / Contract | Purpose |
| --- | --- | --- |
| PSScriptAnalyzer | `.github/linting/PSScriptAnalyzerSettings.psd1` | PowerShell formatting/linting (OTBS style) |
| markdownlint | `.markdownlint.jsonc` | Markdown linting |
| `check-yaml` | `.pre-commit-config.yaml` | YAML parse-checking |

### Running Linters

**Markdown:**

```bash
npm run lint:md
```

**PowerShell:**

```powershell
Invoke-ScriptAnalyzer -Path .\script.ps1 -Settings .\.github\linting\PSScriptAnalyzerSettings.psd1
```

**YAML:**

```bash
pre-commit run check-yaml --all-files
```

## Testing Tools

This repository includes PowerShell testing infrastructure:

| Language / Contract | Framework | Configuration | Test Location |
| --- | --- | --- | --- |
| PowerShell | Pester 5.x | Inline in `.github/workflows/powershell-ci.yml` | `tests/PowerShell/` |

### Running Tests

**PowerShell:**

```powershell
Invoke-Pester -Path tests/ -Output Detailed
```
