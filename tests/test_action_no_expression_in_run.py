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

ACTION = Path(sys.argv[1] if len(sys.argv) > 1 else "action.yml")
EXPR = re.compile(r"\$\{\{(.+?)\}\}", re.S)
# "inputs.x == 'y' && '--flag' || ''" renders one of two literals, never caller data.
LITTERAL_TERNAIRE = re.compile(r"==\s*'[^']*'\s*&&\s*'[^']*'\s*\|\|\s*'[^']*'")


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


def main() -> int:
    texte = ACTION.read_text(encoding="utf-8")
    fautes = []
    for numero, ligne in blocs_run(texte):
        for m in EXPR.finditer(ligne):
            corps = m.group(1).strip()
            if LITTERAL_TERNAIRE.search(corps):
                continue
            fautes.append((numero, corps, ligne.strip()[:100]))
    if not fautes:
        print(f"{ACTION}: no expression is substituted into a run script.")
        return 0
    print(f"{ACTION}: {len(fautes)} expression(s) substituted into a run script — "
          f"pass them through env: and reference them as \"$VAR\".")
    for numero, corps, extrait in fautes:
        print(f"  line {numero}: {{{{ {corps} }}}}  in  {extrait}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
