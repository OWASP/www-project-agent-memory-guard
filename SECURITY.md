# Security Policy

OWASP Agent Memory Guard is a security tool. Defects in it can cause a user to believe
their agent memory is protected when it is not, so we treat reports seriously and
disclose them plainly.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅ Security fixes |
| 0.2.x   | ⚠️ Critical fixes only, until 2026-12-31 |
| < 0.2   | ❌ Unsupported |

Always report against the latest release. Fixes land on the newest minor line first.

## Reporting a vulnerability

**Use [GitHub private vulnerability reporting](https://github.com/OWASP/www-project-agent-memory-guard/security/advisories/new)** — Security → Advisories → Report a vulnerability.
That keeps the report private until a fix is ready and gives us a place to work with you
on it.

If you cannot use that, contact the project leaders listed on the
[project page](https://owasp.org/www-project-agent-memory-guard/).

**Please do not open a public issue for a security defect.**

Include what you have: affected version, what you did, what happened, what you expected.
A reproduction case is ideal but not required — a clear description of the wrong
behaviour is enough to start.

## What to expect

| Stage | Target |
|-------|--------|
| Acknowledgement | 3 business days |
| Initial assessment, with severity and scope | 10 business days |
| Fix released, or a plan with a date | 45 days |
| Public disclosure | With the fix, or 90 days from report, whichever is first |

If we are going to miss one of these, we will tell you rather than go quiet. If we
disagree that a report is a security issue, we will say so and explain why, and you are
free to disclose on your own timeline.

## Scope

**In scope**

- Bypasses of the runtime guard: memory writes or recalls that should be blocked by an
  active policy and are not
- Detector false negatives that a realistic attacker could rely on
- Integrity or rollback defects: baselines that fail to detect tampering, snapshots that
  do not restore
- Policy engine defects that cause a configured control not to apply
- **Silent failures of the static scanner** — a scan that reports no findings when it
  should report some. See the 0.3.0 advisory for a worked example; this class is
  in scope precisely because users cannot detect it themselves
- Vulnerabilities in the API server (`amg serve`) or the MCP server

**Out of scope**

- Detector false positives — report as a normal issue
- Missing detection of an attack class we do not claim to cover. Our published recall is
  92.5% on a 55-case corpus; the corpus is small and project-authored, and we say so.
  A payload we simply do not detect is a feature request unless we claimed to detect it
- Findings against the deliberately vulnerable fixtures in `semgrep/`, `examples/`, and
  the self-test workflows
- Denial of service through obviously unbounded input to a local CLI
- Results from automated scanners with no demonstrated impact

## Deployment notes that affect your security posture

- `Policy.strict()` declares no `protected_keys` by default, so identity and system keys
  are not protected out of the box. Declare them explicitly. (Tracked as #89.)
- The API server (`amg serve`) binds `0.0.0.0:8000` and ships **no authentication**. Run
  it on a private network or behind your own authenticating proxy. Do not expose it.

## Credit

We credit reporters in the advisory and release notes unless you ask us not to.
