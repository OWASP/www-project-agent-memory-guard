import runpy
from pathlib import Path

def test_demo_script_execution():
    """
    Ensure that demo.py runs successfully without throwing exceptions
    like AttributeError. This serves as a regression test for Issue #45,
    where demo.py crashed because it tried to access a non-existent
    `detector` attribute on PolicyViolation.
    """
    repo_root = Path(__file__).parent.parent
    demo_script = repo_root / "demo.py"
    
    # runpy.run_path executes the script in the current Python process.
    # It will raise an exception (like AttributeError) if the script fails.
    runpy.run_path(str(demo_script), run_name="__main__")
