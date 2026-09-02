# AMG Analytics Summary

Generated: 2026-09-02 01:18 UTC

## How to read this data

- `referrers-*.json` — which sites send visitors to the repo (top 10)
- `paths-*.json` — which pages in the repo get the most views
- `views-*.json` — daily page views (14-day rolling window)
- `clones-*.json` — daily git clones (14-day rolling window)
- `pypi-*.json` — PyPI downloads by day
- `pypi-systems-*.json` — downloads by OS (Linux-heavy implies CI, not humans)

## What to watch

1. **Referrer sources** — which channel drove the most traffic?
2. **Clone-to-star ratio** — high clones with low stars means CI and scrapers, not adoption
3. **OS breakdown** — 90%+ Linux means the downloads are pipelines
4. **Version distribution** — users stuck on old versions usually means a stale tutorial somewhere

## Reading it honestly

Clones are not downloads and downloads are not users. A single CI
pipeline that installs on every run produces thousands of downloads and
zero adopters. When a number jumps, check `pypi-systems-*.json` before
treating it as growth.
