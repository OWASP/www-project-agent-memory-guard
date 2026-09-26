"""``amg-bench`` — run the Agent Memory Security Benchmark and write results.

By default it grades the three offline baselines (unguarded dict + two Agent
Memory Guard configurations) and writes ``results.json`` and ``leaderboard.md``.
Third-party systems are graded only when explicitly requested, because they
pull in optional dependencies and, for hosted stores, a running service.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from agent_memory_guard.bench.adapters.baseline import baseline_adapters
from agent_memory_guard.bench.harness import run_suite
from agent_memory_guard.bench.report import build_results, save_json, save_markdown
from agent_memory_guard.bench.scenarios import corpus_stats, default_corpus
from agent_memory_guard.bench.scoring import score_report

# Third-party adapters that can be graded by name via --systems.
_THIRD_PARTY = {
    "mem0": ("agent_memory_guard.bench.adapters.third_party", "Mem0Adapter"),
    "letta": ("agent_memory_guard.bench.adapters.third_party", "LettaAdapter"),
    "zep": ("agent_memory_guard.bench.adapters.third_party", "ZepAdapter"),
}


def _load_third_party(name: str):
    import importlib

    module_name, attr = _THIRD_PARTY[name]
    module = importlib.import_module(module_name)
    return getattr(module, attr)


def _resolve_factories(systems: list[str] | None):
    """Return (label, factory) pairs for the requested systems.

    With no ``--systems`` filter, returns the offline baselines. Named
    third-party systems are appended when requested; ones whose dependency is
    missing are reported and skipped rather than aborting the whole run.
    """
    baseline = [(cls.name, cls) for cls in baseline_adapters()]
    if not systems:
        return baseline, []

    wanted = {s.strip().lower() for s in systems}
    factories = [(name, cls) for name, cls in baseline if name.split()[0] in wanted or name in wanted]
    skipped: list[str] = []
    for name in wanted:
        if name in _THIRD_PARTY:
            try:
                cls = _load_third_party(name)
                factories.append((cls.name, cls))
            except Exception as exc:  # noqa: BLE001 - report and continue
                skipped.append(f"{name}: {exc}")
    return factories, skipped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="amg-bench",
        description="Agent Memory Security Benchmark (AMSB) — grade memory "
        "systems for resilience to memory poisoning (OWASP ASI06).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Directory to write results.json and leaderboard.md into. "
        "If omitted, results are printed to stdout only.",
    )
    parser.add_argument(
        "--systems",
        nargs="*",
        default=None,
        help="Subset of systems to grade by name (e.g. mem0). Default: the "
        "offline baselines. Third-party systems require their package.",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Write only results.json (skip leaderboard.md).",
    )
    args = parser.parse_args(argv)

    corpus = default_corpus()
    stats = corpus_stats(corpus)
    print(
        f"AMSB: {stats['malicious']} attacks + {stats['benign']} benign controls "
        f"across {stats['total']} scenarios\n"
    )

    factories, skipped = _resolve_factories(args.systems)
    for note in skipped:
        print(f"  skipped {note}", file=sys.stderr)

    if not factories:
        print("No systems to grade.", file=sys.stderr)
        return 1

    scorecards = []
    for label, factory in factories:
        # A third-party adapter only fails on construction (missing package or
        # unconfigured service). Skip such a system instead of aborting the run
        # so the systems that can be graded still are.
        try:
            report = run_suite(factory, corpus)
        except Exception as exc:  # noqa: BLE001 - report and continue
            print(f"  skipped {label}: {exc}", file=sys.stderr)
            continue
        card = score_report(report)
        scorecards.append(card)
        cap = (
            f" (capped from {card.uncapped_grade.value})"
            if card.uncapped_grade != card.grade
            else ""
        )
        print(
            f"  {card.system:<32} grade {card.grade.value}{cap}  "
            f"score {card.score:5.1f}  "
            f"defended {card.defended_total}/{card.malicious_total}  "
            f"crit-breach {card.critical_breaches}  "
            f"FP {card.false_positives}/{card.benign_total}"
        )

    if not scorecards:
        print("No systems could be graded.", file=sys.stderr)
        return 1

    results = build_results(
        scorecards,
        corpus=corpus,
        generated_at=time.strftime("%Y-%m-%d"),
    )

    if args.out is not None:
        save_json(results, args.out / "results.json")
        if not args.json_only:
            save_markdown(results, args.out / "leaderboard.md")
        print(f"\nWrote results to {args.out}/")
    else:
        print("\n(no --out given; results not written to disk)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
