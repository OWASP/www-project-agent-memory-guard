# Contributing to OWASP Agent Memory Guard

Thank you for helping improve OWASP Agent Memory Guard (AMG). Contributions are reviewed in public unless they concern a potential vulnerability, private data, or another issue that must be coordinated confidentially.

Before contributing, read the [governance model](GOVERNANCE.md), [roadmap](ROADMAP.md), [security policy](SECURITY.md), and [Code of Conduct](CODE_OF_CONDUCT.md).

## Legal authorization and DCO

For every new non-trivial contribution, contributors must certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/) by adding a `Signed-off-by:` line to each commit:

```bash
git commit --signoff
```

The sign-off certifies that you have the right to submit the work under the project’s Apache-2.0 license. Use your own name and an email address you are authorized to associate with the contribution. Do not submit confidential, proprietary, personal, export-controlled, employer-restricted, or third-party material you do not have the right to license.

A maintainer should not merge a new non-trivial contribution lacking the required sign-off until the contributor corrects the commit history. The project must not mark the OpenSSF DCO criterion met until this policy is consistently applied.

## Find or propose work

Search existing [issues](https://github.com/OWASP/www-project-agent-memory-guard/issues) and pull requests before starting. For a substantive change, open or join an issue that describes:

- the use case or defect;
- the affected component and supported version;
- the security assumptions and trust boundary;
- the smallest proposed scope;
- the validation or regression-test plan; and
- compatibility or documentation effects.

Do not open a public issue for a potential vulnerability. Follow [SECURITY.md](SECURITY.md).

## Development setup

Requirements are Python 3.9 or later, Git, and a Python package installer.

```bash
git clone https://github.com/OWASP/www-project-agent-memory-guard.git
cd www-project-agent-memory-guard
python -m venv .venv
. .venv/bin/activate       # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run the repository checks with the standard project commands:

```bash
ruff check src/ tests/
mypy src/agent_memory_guard --ignore-missing-imports
coverage run -m pytest tests/ -v
coverage report
```

The public CI matrix is the authoritative integration check for supported Python versions. A local pass does not guarantee CI approval.

## Coding standards

Python contributions must follow the repository’s Ruff configuration in `pyproject.toml`, which targets Python 3.9, uses a 100-character line length, and enables the selected pycodestyle, Pyflakes, isort, pep8-naming, and pyupgrade rule families. New public interfaces should include clear type hints and docstrings. Prefer small, explicit functions, fail-safe handling of invalid input, and standard-library or existing dependencies over a new dependency.

`ruff check` is enforced by CI. The current mypy check is advisory because CI invokes it with `|| true`; it must not be described as an enforced type-safety gate until that behavior changes.

## Test policy

Major new functionality must include automated tests in the repository test suite. A bug fix should include a regression test that fails before the fix and passes after it whenever practical. Security-sensitive changes should test the abuse case, safe case, failure behavior, and compatibility behavior relevant to the stated threat boundary.

Tests must not depend on real credentials, confidential data, external production services, or nondeterministic network state. Use synthetic fixtures and local fakes. If a regression test cannot be included, explain why in the pull request and identify an alternative verification method.

AMG collects statement coverage in CI. Do not claim an OpenSSF coverage threshold unless the configured gate, public report, and current test run support that exact number.

## Documentation requirements

Update the affected user, API, architecture, threat-model, configuration, security, and changelog material in the same change when behavior or public interfaces change. Documentation must distinguish:

- the default permissive library policy from explicit strict/tiered enforcement;
- project-authored tests and benchmarks from independent evaluation;
- a discussion, issue, pull request, or reference from acceptance, adoption, audit, endorsement, or certification; and
- the local unauthenticated REST service from a production security perimeter.

Do not add employer, customer, product, adoption, performance, originality, or external-recognition claims without a direct public source that supports the exact wording.

## Pull-request checklist

A pull request should be focused and include:

1. a clear problem statement and linked issue where applicable;
2. a description of the change and non-goals;
3. security and compatibility impact;
4. tests and exact commands/results;
5. documentation and changelog updates where user-visible;
6. no credentials, personal data, confidential material, or generated artifacts that are not needed;
7. DCO sign-offs on new non-trivial commits; and
8. confirmation that all third-party GitHub Action references introduced by the change use immutable full commit SHAs with readable version comments.

## Review standard

Reviewers evaluate scope, correctness, security impact, input and failure handling, compatibility, tests, documentation currentness, dependencies, and unsupported claims. Security-sensitive changes, policy defaults, trust-boundary changes, release workflows, cryptographic changes, and vulnerability fixes should receive review by someone other than the author.

An approval means the reviewer found no known reason to block the proposed scope. It is not a guarantee that the software is vulnerability-free. The decision process and urgent-review exception are defined in [GOVERNANCE.md](GOVERNANCE.md).

## Security reports

Do not disclose a potential vulnerability in a public issue, discussion, or pull request. Use the private and fallback channels documented in [SECURITY.md](SECURITY.md). Maintainers will coordinate scope, remediation, credit preference, and disclosure.

## Code of Conduct

All participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and applicable OWASP policies.

## License

By contributing under the DCO process, you submit the contribution under the project’s [Apache-2.0 license](LICENSE.md).
