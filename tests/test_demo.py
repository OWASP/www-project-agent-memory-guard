import runpy
from pathlib import Path


def test_demo_runs_to_completion(capsys) -> None:
    runpy.run_path(Path(__file__).resolve().parents[1] / "demo.py", run_name="__main__")

    output = capsys.readouterr().out
    assert "BLOCKED [prompt_injection]" in output
    assert "Results: 4 allowed" in output
    # Redacted and quarantined writes are stopped too; the demo used to count
    # them as misses, and its 50 KB "size anomaly" sat under the 64 KiB limit.
    assert "REDACTED [sensitive_data]" in output
    assert "QUARANTINED [size_anomaly]" in output
    assert "5/5 stopped" in output
    assert "MISSED" not in output
