import re
from pathlib import Path

WORKFLOWS = Path(".github/workflows")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
MUTABLE_RAW_GITHUB_REF = re.compile(
    r"raw\.githubusercontent\.com/[^/\s]+/[^/\s]+/(?:main|master)/"
)


def test_actions_are_pinned_to_commit_shas():
    unpinned = []

    for workflow in WORKFLOWS.glob("*.yml"):
        for line_number, line in enumerate(
            workflow.read_text(encoding="utf-8").splitlines(), start=1
        ):
            match = re.search(r"\buses:\s*\S+@([^#\s]+)", line)
            if match and not COMMIT_SHA.fullmatch(match.group(1)):
                unpinned.append(f"{workflow}:{line_number}: {match.group(1)}")

    assert not unpinned, "Actions must be pinned to commit SHAs:\n" + "\n".join(unpinned)


def test_downloaded_github_code_uses_immutable_refs():
    mutable_urls = []

    for workflow in WORKFLOWS.glob("*.yml"):
        for line_number, line in enumerate(
            workflow.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if MUTABLE_RAW_GITHUB_REF.search(line):
                mutable_urls.append(f"{workflow}:{line_number}: {line.strip()}")

    assert not mutable_urls, "Downloaded code must use immutable refs:\n" + "\n".join(
        mutable_urls
    )
