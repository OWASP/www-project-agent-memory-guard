import runpy
from pathlib import Path


def test_demo_runs_to_completion(capsys) -> None:
    runpy.run_path(Path(__file__).resolve().parents[1] / "demo.py", run_name="__main__")

    output = capsys.readouterr().out
    assert "BLOCKED [prompt_injection]" in output
    assert "Results: 4 allowed" in output
