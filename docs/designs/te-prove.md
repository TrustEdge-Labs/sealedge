# te-prove: Trust Policy Engine for FOSS Supply Chain Integrity

> **Status: PARKED (idea/design only — not on the roadmap).** Preserved here when
> the legacy `.planning/` planning tree was removed; parked pending demand
> evidence. Nothing in this document is implemented.

## Purpose

te-prove is a standalone trust policy engine under the TrustEdge ecosystem. It protects solo developers and small FOSS teams from supply chain attacks — like the Drift Protocol $286M hack[cite:33] and the xz-utils backdoor[cite:50] — by enforcing cryptographically-verifiable trust policies at the code boundary, without restricting open social collaboration.

**Core principle:** Talk to anyone. Meet anyone at a conference. Accept PRs from anyone. But nothing crosses the code trust boundary without passing your declared policy.

---

## Problem Statement

Nation-state actors (notably DPRK-linked groups) are running multi-month social engineering campaigns targeting open-source developers[cite:33][cite:41]. The attack pattern is consistent: build social trust with a target, then exploit that trust to deliver malicious code — fake wallet apps, poisoned repositories, compromised build tools.

Current defenses fail solo devs and small teams:

- **OS install warnings** are binary and contextless ("unverified developer — install anyway?"). Users are trained to click through them.
- **GPG signing** proves identity-to-artifact binding but says nothing about build provenance, dependencies, or build environment integrity[cite:60][cite:65].
- **SLSA, Sigstore, Syft** provide excellent primitives (provenance, keyless signing, SBOM generation) but no unified policy layer that evaluates them together and makes a trust decision[cite:20][cite:18].
- **Enterprise supply chain platforms** (Chainguard, Snyk, FOSSA) are priced and scoped for organizations, not solo maintainers.

The risk: developers become afraid to collaborate openly, retreating from FOSS culture. te-prove exists to prevent that chilling effect.

---

## Architecture

### Relationship to TrustEdge

```
trustedge-core          ← shared trust primitives (scoring, attestation, policy engine)
  ├── trustedge         ← AI/agent trust framework (existing repo)
  └── te-prove          ← FOSS supply chain trust policy engine (this project)
```

te-prove is a **separate repo** with its own README, docs, CLI, and identity. It imports `trustedge-core` for the trust scoring model and policy evaluation engine. It does not reference AI agent use cases in its documentation or onboarding flow.

### Core Loop

```
event (install, clone, PR, build)
  → collect attestations (SLSA provenance, Sigstore signatures, SBOM, contributor history)
  → evaluate against policy (.trust-policy.yml)
  → decision (ALLOW / BLOCK / REVIEW / SANDBOX)
  → log (immutable local audit trail)
```

### Trust Inputs

| Input | Source | What It Answers |
|-------|--------|-----------------|
| SLSA provenance | SLSA framework / GitHub Actions | Where and how was this built? |
| Sigstore attestation | Cosign / Rekor transparency log | Who signed this? Is the cert valid? Short-lived or long-lived key? |
| SBOM | Syft / CycloneDX / SPDX | What dependencies are inside? Any known-bad components? |
| Contributor history | Git log / transparency logs | How long has this person been verifiably contributing? |
| Package metadata | Registry APIs (npm, crates.io, PyPI) | How old is this package? How many maintainers? Download patterns? |
| CVE data | OSV / NVD | Any known vulnerabilities? |
| Binary analysis | Code signing certs, hash lookups | Is this binary attested? Is the publisher known? |

### Policy Schema (.trust-policy.yml)

```yaml
version: 1
name: "my-project-trust-policy"

defaults:
  minimum_trust_score: 60
  action_on_fail: block          # block | review | warn | sandbox

dependencies:
  require_provenance: true
  minimum_slsa_level: 2
  require_sbom: true
  allow_unattested: false
  minimum_package_age_days: 30
  maximum_new_dependencies_per_update: 3
  blocked_publishers: []
  trusted_publishers:
    - "github.com/rust-lang"
    - "github.com/nodejs"

contributors:
  require_signed_commits: true
  new_contributor_review_period_days: 7
  trust_after_verified_contributions: 3
  require_verified_identity: false   # true = require DID/VC-backed identity

binaries:
  require_code_signing: true
  require_sigstore_attestation: true
  require_known_publisher: true
  allow_override: true
  override_ttl_days: 30
  override_requires_reason: true

audit:
  log_all_decisions: true
  log_overrides: true
  log_path: ".te-prove/audit.log"
```

---

## Trust Scoring Model

Trust is not binary. te-prove computes a composite trust score (0-100) from weighted inputs:

| Signal | Weight | Scoring Logic |
|--------|--------|---------------|
| SLSA provenance level | 25 | L0=0, L1=10, L2=18, L3=25 |
| Sigstore attestation | 20 | None=0, long-lived key=10, keyless OIDC=20 |
| SBOM present + clean | 15 | None=0, present=8, present+no CVEs=15 |
| Package/repo age | 10 | <7d=0, <30d=3, <1yr=7, >1yr=10 |
| Contributor history | 15 | New=0, <3 verified contributions=5, established=15 |
| Known publisher | 10 | Unknown=0, recognized registry=5, trusted list=10 |
| Binary code signing | 5 | Unsigned=0, signed=3, signed+attested=5 |

Score thresholds are policy-configurable. Defaults: >=60 ALLOW, 30-59 REVIEW, <30 BLOCK.

Trust accrues over time — a dependency that has maintained signed provenance across 50 releases scores higher than one that started attesting yesterday. This graduated model prevents gaming through one-time compliance.

---

## Interception Points

### Phase 1: Package Manager CLI Wrapper

Highest-value, lowest-effort integration. Wraps existing package managers with pre-install policy checks.

```bash
# Instead of: npm install sketchy-quant-lib
te-prove install npm sketchy-quant-lib

# Or via shell alias/hook (transparent):
npm install sketchy-quant-lib
# → te-prove intercepts, evaluates, reports before proceeding
```

**Output on policy failure:**

```
┌─ te-prove ─────────────────────────────────────────┐
│ Package: sketchy-quant-lib@2.1.0                   │
│ Trust Score: 12/100 ⚠  BELOW POLICY THRESHOLD     │
│                                                     │
│ ✗ No SLSA provenance attached                      │
│ ✗ No SBOM available                                │
│ ✗ Published 3 days ago (policy: min 30 days)       │
│ ✗ Single maintainer, no verified identity           │
│ ✓ No known CVEs                                    │
│ ✗ Requests filesystem + network permissions         │
│                                                     │
│ Policy decision: BLOCK                              │
│ Override: te-prove allow <hash> --reason "..."      │
└─────────────────────────────────────────────────────┘
```

Supported package managers (initial): npm, cargo, pip. Extensible via adapter pattern.

### Phase 2: GitHub Action

Runs te-prove on every PR and dependency update in CI.

```yaml
# .github/workflows/trust-check.yml
- uses: trustedge/te-prove-action@v1
  with:
    policy: .trust-policy.yml
    fail_on: block
```

Produces a PR comment with the trust report for any flagged dependencies or contributors.

### Phase 3: Browser Extension

Intercepts binary downloads, checks attestations before save/execute. Renders a trust report in-browser with comparison to known legitimate publishers.

### Phase 4: OS-Level Daemon (Long-term)

Pre-execution hook that evaluates binaries against policy. Platform-specific (Linux first via eBPF or security module, then macOS).

---

## Override Model

Overrides are explicit, scoped, logged, and expiring:

- **Explicit**: `te-prove allow <artifact-hash> --reason "reviewed source manually, building from source"`
- **Scoped**: Override applies to a specific artifact hash, not the publisher or package name globally
- **Logged**: Every override written to immutable audit log with timestamp, user, reason, and artifact details
- **Expiring**: Overrides have a policy-defined TTL (default 30 days), then the artifact is re-evaluated

This prevents the "click yes to everything" pattern that current OS warnings create. Friction is proportional to risk.

---

## Extraction Plan from TrustEdge

### Step 1: Identify shared primitives in current trustedge codebase
- Trust scoring model
- Attestation verification interfaces
- Policy schema and evaluation engine

### Step 2: Extract to trustedge-core
- New repo: `trustedge-core`
- Shared types, interfaces, scoring algorithms
- Published as standalone package

### Step 3: Build te-prove
- New repo: `te-prove`
- Depends on `trustedge-core`
- CLI, policy schema, package manager adapters, GitHub Action

### Step 4: Refactor trustedge main
- Update `trustedge` to depend on `trustedge-core`
- Remove duplicated primitives

---

## Tech Stack (Aligned with gstack)

- **Language**: TypeScript (primary), with Rust for performance-critical verification paths
- **CLI framework**: Commander.js or oclif
- **Attestation verification**: sigstore-js, in-toto-js
- **SBOM parsing**: CycloneDX and SPDX libraries
- **CVE lookup**: OSV API
- **Package metadata**: npm registry API, crates.io API, PyPI JSON API
- **Audit logging**: Append-only local JSON log (SQLite optional)
- **GitHub Action**: TypeScript action with composite workflow
- **Distribution**: npm global install, standalone binary via pkg/bun compile

---

## Success Criteria

- A solo FOSS developer can add te-prove to their workflow in under 5 minutes
- First run produces an actionable trust report with zero configuration (sensible defaults)
- The tool is useful standalone — does not require anyone else in the dependency chain to adopt it
- Policy files are forkable — communities can publish and share baseline policies
- No SaaS dependency, no phoning home, fully local-first operation
- Clear separation from TrustEdge AI features — discoverable independently

---

## Open Questions

- Should te-prove support DID/Verifiable Credential-based contributor identity from day one, or defer to a later version?
- How aggressive should defaults be? Too strict = immediate uninstall. Too loose = false sense of security.
- Is there value in a shared public trust registry (like a CT log but for package trust scores), or does that introduce centralization risk?
- How to handle transitive dependencies — score the full tree or just direct dependencies?
- Naming: te-prove vs trustgate vs something else. Must work as a CLI command people type daily.

---

## Context Note (archived 2026-04-05)

This design document was authored during the v5.0 portfolio polish planning session (April 5, 2026 office hours). Key findings from that discussion:

- **No demand evidence.** No user or prospect has requested this feature. The idea surfaced from internal brainstorming, not from user pull.
- **FOMO-driven.** The motivation was "this would be cool" rather than "someone needs this." That is not a sufficient basis for building a new product.
- **Parked, not cancelled.** If demand evidence emerges (user requests, GitHub issues, prospect interest), revisit this doc. The design is solid and the problem is real.
- **Out of v5.0 scope.** Explicitly excluded from the Portfolio Polish milestone. See `.planning/REQUIREMENTS.md` out-of-scope table.

Reference: `.planning/STATE.md` decisions section.
