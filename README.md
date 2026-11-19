# corvex-bench

Author: CorvexDevelops

A paired benchmark to measure security scanners and AI code auditors honestly. Every target comes in two versions: a vulnerable one with known flaws, and a clean twin with the same code and the flaws fixed. Every finding on a clean twin counts as a false alarm, the number most benchmarks forget and the one users feel.

Made by [Corvex](https://corvex.dev), the team of security agents that tests your web platforms, code, network and computer. Corvex finds 71 of 71 flaws here with zero false alarms, offline and without AI. The targets are twins of the benchmark Corvex is tuned on: it is our reference, not an independent test.

Python 3.9+ with the standard library only. No dependencies, no network access: the web targets listen on 127.0.0.1.

## What is inside

| Path | What it is |
|---|---|
| [`bench/`](bench/README.md) | the targets (web, code, network), the expected flaws by CWE, scoring of SARIF or JSON results, regression baseline |
| [`pcapgen/`](pcapgen/README.md) | builds the network captures of the traffic targets, deterministic and offline |
| [`tools/verify_quotes.py`](tools/verify_quotes.py) | checks that every finding quotes code that really exists, at the line it claims |
| [`skills/corvex-agent-benchmark/`](skills/corvex-agent-benchmark/SKILL.md) | the method: paired targets, expected findings, false alarms, baseline |
| [`skills/corvex-verified-evidence/`](skills/corvex-verified-evidence/SKILL.md) | how to report a finding with an exact, checkable quote of the code |
| `tests/` | offline tests |

## Measure a scanner in four steps

```bash
python3 bench/bench.py list                      # the 71 known flaws
python3 bench/bench.py serve                     # 1. web targets on 127.0.0.1
python3 bench/bench.py prepare work/             # 2. code targets and captures in work/
#                                                  3. run your tool, save results/<target>.sarif or .json
python3 bench/bench.py score results/ --baseline baseline.json --update   # 4. first run saves the baseline
python3 bench/bench.py score results/ --baseline baseline.json            #    then it fails only on regressions
```

The targets are `web-vulnerable`, `web-clean`, `code-vulnerable`, `code-clean`, `traffic-attacks` and `traffic-clean`. Score only the ones your tool covers.

| Target | Known flaws |
|---|---|
| web-vulnerable | 18 |
| code-vulnerable | 32 |
| traffic-attacks | 21 |

## Verified evidence

Every finding should carry `line` and `sink_quote`, copied character for character from the code. Check them:

```bash
python3 tools/verify_quotes.py findings.json --root path/to/project
```

Each finding is reported as `verified` (the quote is at that line), `moved` (the quote is elsewhere in the file, with the right line) or `invented` (the quote is nowhere in the file).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Licence

Apache License 2.0, see `LICENSE` and `NOTICE`.
