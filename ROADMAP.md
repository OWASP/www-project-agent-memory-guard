# Roadmap

This roadmap covers **September 2026 through September 2027**. It describes the project’s intended direction, not a promise that every item will ship on a fixed date. Security and correctness work takes priority over feature expansion. Community proposals remain subject to maintainer review, tests, compatibility checks, and available volunteer capacity.

## Release principles

AMG will use small, reviewable releases. A release candidate must have its documented behavior aligned with the implementation, pass the supported Python test matrix, include human-readable release notes, and disclose known limitations. Security-relevant changes must include regression coverage when practical. Project status, external references, and benchmark results will be described factually and will not be presented as certification, adoption, or endorsement unless the source expressly supports that characterization.

## September–December 2026: stabilization and audit readiness

| Priority | Intended work | Completion gate |
|---|---|---|
| Security and correctness queue | Review or disposition the open composite-action, trust-boundary, policy, scanner, server, and supply-chain items. Close obsolete or superseded pull requests rather than merging overlapping changes. | Maintainer review recorded; integrated checks pass; residual limitations documented. |
| Secure contribution and release controls | Pin third-party workflow/action dependencies, keep dependency monitoring active, provide a working private/fallback vulnerability-reporting route, and define code-review and release responsibilities. | Repository policy and workflows match actual practice; no known broken reporting link. |
| Documentation currentness | Align the architecture, threat model, server defaults, CORS/authentication guidance, supported versions, and quick-start material with the latest release. | A documentation review finds no known security-relevant contradiction with released code. |
| External review package | Maintain an architecture map, trust boundaries, dependency inventory, threat model, assurance case, test instructions, and bounded audit scope. | Package references a stable tagged release and identifies unresolved risks. |
| Project maturity | Complete only OpenSSF Best Practices Silver claims that are supported by public evidence; request OWASP Lab review only after the documented readiness gates are met. | Evidence links are public and each self-certification answer is accurate. |

## January–March 2027: integration quality and reproducibility

| Priority | Intended work | Completion gate |
|---|---|---|
| Framework adapters | Stabilize selected adapters whose maintainers or users provide a reproducible use case, ownership path, and tests. | Adapter has documented compatibility, an owner, automated tests, and a maintenance decision. |
| Packaging and distribution | Resolve accepted third-party packaging and distribution work, including dependency bounds and clean-environment installation checks. | Independent repository or package review is complete; published packages match tagged source. |
| Build and release reproducibility | Evaluate bit-for-bit reproducible Python artifacts and a cryptographic signing/verification process appropriate to PyPI and GitHub releases. | A public procedure is repeatable by a second maintainer; otherwise the criterion remains unmet. |
| Governance continuity | Verify that at least two maintainers can triage issues, merge approved changes, handle private reports, and perform a release without relying on one person’s credentials. | Access is verified in the relevant services and continuity is documented without publishing credentials. |

## April–June 2027: evaluation and independent validation

| Priority | Intended work | Completion gate |
|---|---|---|
| Benchmark maintenance | Version the synthetic test corpus, document sampling limits, and separate project-authored measurements from independent results. | Results identify corpus size, environment, version/commit, method, and limitations. |
| External reproduction | Encourage reproducible third-party evaluation and accept corrections through the normal issue/PR process. | Any public summary links to the evaluator’s own record and preserves their stated scope. |
| Dynamic analysis | Select a repeatable dynamic-analysis method for release candidates and document whether it applies to each package/runtime surface. | Procedure runs before a major production release or is accurately marked not yet met. |
| Security review | Pursue an independent security review only when scope, funding, disclosure handling, and remediation ownership are agreed without a project fee. | Signed scope or public intake acknowledgment exists; a request is not described as an audit. |

## July–September 2027: sustainable maturity

| Priority | Intended work | Completion gate |
|---|---|---|
| Maintenance review | Reassess supported versions, unresolved issues, maintainer capacity, dependency health, and roadmap priorities. | Support table and roadmap are updated from evidence. |
| OWASP maturity | If earlier gates are complete, proceed through the applicable OWASP project-review process and remediate reviewer findings. | Only the OWASP decision is described as a promotion; submission alone remains pending. |
| Standards alignment | Track relevant agentic-AI security and protocol work and contribute narrowly scoped, implementation-backed material when maintainers request or accept the scope. | Contribution has an attributable public record and is not described as adoption until accepted. |

## Explicitly out of scope for this roadmap

AMG does not promise complete attack prevention, principal authentication, authorization for the surrounding agent platform, secure hosting of the unauthenticated API server, automatic protection of memory operations that bypass `MemoryGuard`, verification of caller-supplied provenance labels or receipt URIs, compliance certification, formal verification, enterprise RBAC, or production support guarantees. Those may be proposed separately, but none should be inferred from current project status.

## How to contribute

Before starting a change, open or join an issue describing the use case, threat model, and intended test. Small, reviewable changes are preferred. See [CONTRIBUTING.md](CONTRIBUTING.md) for development, review, testing, security-reporting, and authorship requirements.
