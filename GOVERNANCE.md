# Governance

OWASP Agent Memory Guard (AMG) is an OWASP Foundation project maintained in public. This document explains how project decisions are made, which roles exist, what each role is responsible for, and which continuity controls must be verified before the project claims that it can operate without any one individual.

## Project scope and independence

Contributions are made to the OWASP project in an individual or explicitly authorized organizational capacity. A contributor’s employer is not a project sponsor, adopter, or endorser merely because the contributor identifies an affiliation. Contributors must not submit confidential, proprietary, personal, export-controlled, or employer-restricted information.

## Roles and responsibilities

| Role | Appointment | Responsibilities | Authority |
|---|---|---|---|
| Project Leader | Named in the OWASP project record | Sets the project’s maintenance priorities; applies OWASP policies; coordinates security response; ensures releases and public claims are evidence-based. | Final decision when documented consensus cannot be reached, subject to OWASP policy. |
| Co-Leader | Named in the OWASP project record by the Project Leader/OWASP process | Shares issue triage, review, security response, release continuity, and community coordination. | May approve and merge within verified repository permissions and agreed release controls. |
| Maintainer | Added by the Project Leader after sustained, reviewed contribution | Triages issues, reviews changes, enforces contribution requirements, and maintains assigned components. | May approve or merge changes within assigned scope; cannot approve their own security-sensitive change as the only reviewer. |
| Security Responder | Project Leader or specifically designated Maintainer with access to the private reporting channel | Acknowledges reports, limits access, coordinates remediation and disclosure, and credits reporters unless anonymity is requested. | May use a private branch or advisory workspace for embargoed fixes. |
| Release Manager | Project Leader or designated Maintainer with verified repository and package-registry access | Verifies version consistency, tests, changelog, artifacts, signatures/attestations when implemented, and publication status. | May create an approved release after all release gates pass. |
| Reviewer | Maintainer or invited subject-matter contributor | Evaluates scope, correctness, security impact, compatibility, tests, documentation, and unsupported claims. | May approve or request changes; review alone does not grant merge or release authority. |
| Contributor | Any participant who follows the contribution and conduct requirements | Proposes issues, code, tests, documentation, or reproductions and responds to review. | Retains authorship of contributed work under the project license and contribution certification. |

The current named project leadership is maintained in [`leaders.md`](leaders.md). Repository or package-registry access must not be inferred from a title; continuity claims require separate verification of actual permissions.

## Decision process

Technical work begins with an issue or pull request that states the use case, intended scope, security assumptions, and validation plan. Maintainers seek consensus through public, URL-addressable discussion. A reviewer may request changes, additional tests, a smaller scope, documentation corrections, or closure when work is obsolete, duplicative, unsafe, unsupported, or outside the roadmap.

Routine changes may be merged after required checks and maintainer review. Security-sensitive changes, release workflows, trust-boundary changes, policy defaults, authentication or authorization changes, cryptographic changes, and vulnerability fixes should receive review by someone other than the author. When only one qualified maintainer is available for an urgent fix, the exception, reason, validation performed, and follow-up review request must be recorded in the pull request or advisory.

The Project Leader resolves an impasse after summarizing the competing positions and reasons. Decisions remain subject to the OWASP Code of Conduct, project policies, license, and applicable OWASP Foundation requirements.

## Contribution authorization

For new non-trivial contributions, contributors should certify the Developer Certificate of Origin (DCO) by adding a `Signed-off-by:` line to each commit, using `git commit --signoff`. The certification states that the contributor has the right to submit the work under the project’s license. The project must not mark the OpenSSF DCO criterion met until the requirement is documented in the contribution guide and consistently enforced or reviewed.

## Review standard

A review considers whether the change:

1. fits the documented project scope and threat model;
2. avoids confidential data, credentials, personal data, and unsupported external claims;
3. preserves or deliberately changes public interfaces with appropriate compatibility notes;
4. handles untrusted input and failure modes safely for the stated use case;
5. includes regression tests for corrected bugs and tests for major new functionality when practical;
6. updates architecture, configuration, security, and user documentation affected by the change;
7. passes the supported automated checks; and
8. avoids unnecessary dependencies and mutable supply-chain references.

An approval means the reviewer found no known reason to block the proposed scope. It is not a certification that the software is vulnerability-free.

## Security response

Potential vulnerabilities must follow [`SECURITY.md`](SECURITY.md), not a public issue. Access to private reports is limited to designated Security Responders. The response record should preserve the affected versions, severity and scope assessment, remediation decision, reporter credit preference, release linkage, and disclosure date. Security-sensitive details should remain private until coordinated disclosure or the documented disclosure deadline.

## Release process

A Release Manager may publish only from an identified commit after the applicable checks pass. Each release must have a unique version, a version-control tag, human-readable release notes, supported-version information, and artifact/version consistency. A release that corrects a publicly discussed security or correctness limitation must describe the fix narrowly and retain residual limitations. Package-registry publication, signing, or trusted-publisher configuration is an account-level operation and requires an authorized maintainer with the relevant access.

## Continuity and access

The project’s goal is to maintain at least two people who can, within one week of a confirmed loss of one maintainer, triage and close issues, review and merge changes, respond to private vulnerability reports, and publish a release. Meeting this goal requires verified access—not merely named roles—to the OWASP GitHub repository, private security-reporting workspace, package registry, project page, and any release-signing or trusted-publishing configuration.

The project must not publish credentials or recovery material. Access is verified privately by the Project Leader and Co-Leader or another designated Maintainer. When a service supports role-based access, individual accounts and least privilege are preferred over shared credentials. The OpenSSF continuity and bus-factor criteria remain unmet until the necessary permissions and a release handoff are verified.

## Conflicts, recusal, and conduct

Reviewers disclose material conflicts that could reasonably affect an impartial review and recuse when appropriate. Paid work, sponsorship, or organizational affiliation must be disclosed when relevant to a proposal. Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Attribution and external statements

Merged contributions retain public commit and pull-request attribution. Releases credit security reporters unless anonymity is requested. A discussion, issue, pull request, reference, test, application, or expression of interest is not an endorsement, adoption, audit, appointment, or certification. External recognition is summarized only within the source’s express wording and linked to the original record.

## Amending this model

Governance changes use the same public issue and pull-request process as technical changes. Material changes to decision authority, security response, release control, or contributor certification should receive review from someone other than the author and must remain consistent with OWASP policy.
