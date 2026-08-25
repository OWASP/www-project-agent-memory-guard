#!/usr/bin/env python3
"""Merge GitHub's rolling 14-day clone window into a durable running total.

Replaces the previous approach in .github/workflows/clone.yml, which did this:

    curl .../MShawon/github-clone-count-badge/master/main.py > main.py
    python3 main.py

That downloads a script from a third party's *mutable* master branch and
executes it in a job holding a classic PAT with `repo` and `gist` scopes. Anyone
who can push to that branch — or anyone who compromises the account — gets code
execution with that token. For most projects that is a bad idea. For an OWASP
security project it is the finding a reviewer screenshots.

The logic is small enough to own outright, so this vendors it.

GitHub's traffic API returns only the last 14 days. To keep an all-time total,
each run merges the fresh window into the stored history keyed by day, then sums.
Re-reading a day that is already stored overwrites it rather than adding to it,
so re-runs are idempotent and a late-arriving day corrects itself.

Usage:
    python3 scripts/clone_count.py --current clone.json --history clone_before.json --out clone.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def load(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"warning: could not read {path} ({exc}); treating as empty", file=sys.stderr)
        return {}
    return data if isinstance(data, dict) else {}


def by_day(payload: dict) -> dict[str, dict]:
    """Index a traffic payload's per-day entries by timestamp."""
    days = {}
    for entry in payload.get("clones", []) or []:
        stamp = entry.get("timestamp")
        if not stamp:
            continue
        days[stamp] = {
            "timestamp": stamp,
            "count": int(entry.get("count", 0)),
            "uniques": int(entry.get("uniques", 0)),
        }
    return days


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", required=True, help="fresh traffic/clones API response")
    parser.add_argument("--history", required=True, help="previously stored merged history")
    parser.add_argument("--out", required=True, help="where to write the merged result")
    args = parser.parse_args()

    current = load(args.current)
    if not current.get("clones") and "count" not in current:
        print(
            "error: the current traffic payload has neither per-day entries nor a count. "
            "The API call failed or the token lost access — refusing to overwrite history "
            "with an empty window.",
            file=sys.stderr,
        )
        return 1

    merged = by_day(load(args.history))
    merged.update(by_day(current))  # fresh window wins for days present in both

    ordered = [merged[k] for k in sorted(merged)]
    total = sum(day["count"] for day in ordered)
    uniques = sum(day["uniques"] for day in ordered)

    result = {"count": total, "uniques": uniques, "clones": ordered}

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print(f"clones: {total} total, {uniques} unique, across {len(ordered)} recorded days")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
