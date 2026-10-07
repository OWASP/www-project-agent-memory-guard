"""The multi-agent guide's sample and its runnable example must keep working."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DENIED = "denied: writer is not in writers ['supervisor'] of 'plan'"


def test_the_multi_agent_example_runs():
    done = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "multi_agent_access.py")],
        capture_output=True, text=True, timeout=120,
    )
    assert done.returncode == 0, done.stderr
    assert DENIED in done.stdout


def test_the_multi_agent_guide_sample_runs(capsys):
    guide = (ROOT / "docs" / "getting-started" / "multi-agent.md").read_text(encoding="utf-8")
    sample = re.search(r"```python\n(.*?)```", guide, re.S)
    assert sample is not None
    exec(compile(sample.group(1), "multi-agent.md", "exec"), {"__name__": "guide_sample"})
    out = capsys.readouterr().out
    assert DENIED in out
    assert "access     writer is not in writers" in out
