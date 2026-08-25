"""Regression tests for scanner file discovery.

Background: `_collect_files` normalized include patterns with

    pattern.lstrip("**/")

`str.lstrip` strips any leading character in the given *set*, not the prefix
string. For the default pattern "**/*.py" that strips '*', '*', '/', '*' and
leaves ".py", so the scanner called `root.rglob(".py")` — which matches nothing.

The effect: `amg scan <dir>` with default options reported "files_scanned: 0,
total_findings: 0" on every repository. A security scanner that silently finds
nothing is worse than one that errors, because the output is indistinguishable
from a clean result. The GitHub Action inherited the same default.

These tests fail against the old implementation and pass against `removeprefix`.
"""

from __future__ import annotations

import pytest

from agent_memory_guard.scanner import MemorySecurityScanner

VULNERABLE_SOURCE = '''\
import pickle

API_KEY = "sk-proj-notarealkeyjustafixture000000000000000"


def remember(store, tool_output):
    store["agent.notes"] = tool_output


def load(blob):
    return pickle.loads(blob)
'''


@pytest.fixture()
def project(tmp_path):
    (tmp_path / "agent.py").write_text(VULNERABLE_SOURCE, encoding="utf-8")
    nested = tmp_path / "pkg" / "inner"
    nested.mkdir(parents=True)
    (nested / "deep.py").write_text(VULNERABLE_SOURCE, encoding="utf-8")
    (tmp_path / "notes.md").write_text("not python", encoding="utf-8")
    return tmp_path


def test_default_include_pattern_finds_top_level_files(project):
    """The default '**/*.py' must match files directly under the scan root."""
    files = MemorySecurityScanner()._collect_files(project)
    names = {f.name for f in files}
    assert "agent.py" in names, (
        "Default include pattern matched no top-level Python file. This is the "
        "lstrip('**/') bug: the pattern was reduced to '.py' and rglob matched nothing."
    )


def test_default_include_pattern_recurses(project):
    files = MemorySecurityScanner()._collect_files(project)
    names = {f.name for f in files}
    assert "deep.py" in names


def test_non_python_files_are_not_collected(project):
    files = MemorySecurityScanner()._collect_files(project)
    assert all(f.suffix == ".py" for f in files)


def test_scan_reports_nonzero_files_scanned(project):
    """The end-to-end guard: a directory with Python files must not scan zero."""
    result = MemorySecurityScanner().scan_directory(project)
    assert result.files_scanned > 0, (
        "scan_directory reported files_scanned == 0 on a directory containing "
        "Python files. Any 'no findings' result from this state is a false negative."
    )


def test_scan_detects_the_planted_vulnerabilities(project):
    result = MemorySecurityScanner().scan_directory(project)
    assert result.files_scanned >= 2
    assert len(result.findings) > 0, (
        "Scanned a file with a hardcoded key, an unguarded memory write and a "
        "pickle.loads of stored content, and reported nothing."
    )


@pytest.mark.parametrize(
    ("pattern", "should_match"),
    [
        ("**/*.py", True),
        ("*.py", True),
        ("**/*.md", False),
    ],
)
def test_include_pattern_normalization(project, pattern, should_match):
    files = MemorySecurityScanner(include_patterns=[pattern])._collect_files(project)
    found_python = any(f.suffix == ".py" for f in files)
    assert found_python is should_match
