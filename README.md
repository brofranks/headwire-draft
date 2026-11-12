# Lockfile pin re-test

Checks how GitHub Actions treats `actions.lock` pins that differ from the tag
commit, re-testing the case behind github/gh-actions-lock#202.

| Workflow | Lockfile pin | Note |
| --- | --- | --- |
| `ancestor-pin` | `checkout@v7.0.1` → `9c091bb` (v7.0.0, in v7.0.1's history) | the case under test |
| `descendant-pin` | `checkout@v7.0.0` → `f548e57` (after v7.0.0, not in its history) | control, expected to fail at setup |
| `verify` | none | `gh actions-lock --verify` v0.4.1, expected to fail on both pins |

The first commit has untampered pins as a baseline. The second tampers both.
