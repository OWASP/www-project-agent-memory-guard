"""Fails if any ${{ ... }} expression is substituted into the text of a `run:` script.

Why this is a test and not a style rule: in a composite action, an expression is substituted
BEFORE bash parses the line. A value carrying a quote or a semicolon therefore becomes command
text rather than an argument, and the caller's runner executes it. GitHub's own hardening guide
says to pass such values through `env:` and reference them as "$VAR".

Two exceptions are declared rather than silently skipped:
  - an expression that can only render one of two fixed literals (a ternary over a comparison)
    cannot carry a value, so it is not a substitution of data;
  - expressions outside `run:` blocks (`with:`, `if:`) are not shell text.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

EXPR = re.compile(r"\$\{\{(.+?)\}\}", re.S)
# "inputs.x == 'y' && '--flag' || ''" renders one of two literals, never caller data.
LITTERAL_TERNAIRE = re.compile(r"==\s*'[^']*'\s*&&\s*'[^']*'\s*\|\|\s*'[^']*'")

ACTION_PAR_DEFAUT = Path(__file__).resolve().parent.parent / "action.yml"


def chemin_action() -> Path:
    """The file to check, resolved when called and never at import time.

    Under `pytest tests/`, sys.argv[1] is the path pytest was given, so resolving this at
    import would make the module read `tests/` as YAML. A command-line argument is honoured
    only when it names a YAML file; otherwise the action at the repository root is used.
    """
    if len(sys.argv) > 1 and sys.argv[1].endswith((".yml", ".yaml")):
        return Path(sys.argv[1])
    return ACTION_PAR_DEFAUT


def blocs_run(texte: str) -> list[tuple[int, str]]:
    """Return (line number, line) for every line inside a `run: |` block."""
    lignes = texte.splitlines()
    dedans, marge, out = False, 0, []
    for i, ligne in enumerate(lignes, start=1):
        depouille = ligne.strip()
        if re.match(r"^run:\s*\|", depouille):
            dedans, marge = True, len(ligne) - len(ligne.lstrip())
            continue
        if dedans:
            if depouille and (len(ligne) - len(ligne.lstrip())) <= marge:
                dedans = False
            else:
                out.append((i, ligne))
    return out


def main(action: Path | None = None) -> int:
    action = action or chemin_action()
    texte = action.read_text(encoding="utf-8")
    fautes = []
    for numero, ligne in blocs_run(texte):
        for m in EXPR.finditer(ligne):
            corps = m.group(1).strip()
            if LITTERAL_TERNAIRE.search(corps):
                continue
            fautes.append((numero, corps, ligne.strip()[:100]))
    if not fautes:
        print(f"{action}: no expression is substituted into a run script.")
        return 0
    print(f"{action}: {len(fautes)} expression(s) substituted into a run script — "
          f"pass them through env: and reference them as \"$VAR\".")
    for numero, corps, extrait in fautes:
        print(f"  line {numero}: {{{{ {corps} }}}}  in  {extrait}")
    return 1


def test_action_has_no_expression_in_run() -> None:
    """The assertion CI actually runs.

    Without a `test_` function, `pytest tests/` imports this module and calls nothing, so the
    check would pass by never running. The path is passed explicitly so the result does not
    depend on the arguments pytest happens to receive.
    """
    assert main(ACTION_PAR_DEFAUT) == 0


if __name__ == "__main__":
    sys.exit(main())
