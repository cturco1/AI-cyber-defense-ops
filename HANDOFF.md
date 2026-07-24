# HANDOFF

## What we built

`parser.py` — a Python CLI tool that parses Sysmon Event ID 1 (Process
Creation) XML events and extracts key fields as JSON:

`EventID`, `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`,
`ParentImage`, `ParentCommandLine`, `Computer`, `Hashes`.

It validates that input is actually a Sysmon log (correct XML namespace,
`Provider Name="Microsoft-Windows-Sysmon"`) before parsing, and handles both
a single `<Event>` file and a multi-event `<Events>` wrapper. It also supports
filtering the output down to events of interest.

`samples/` contains four hand-built fixture files used to test all of the
above:
- `event1.xml` — benign `whoami.exe /groups`, spawned by `cmd.exe`
- `event2.xml` — `cmd.exe` spawning bare `powershell.exe`
- `event3.xml` — phishing-style chain: `WINWORD.EXE` spawning an obfuscated
  `powershell.exe -enc <base64>` download cradle (Medium integrity, different
  host/user than the other two)
- `multi_events.xml` — all three of the above wrapped in a single `<Events>`
  root, to exercise the multi-event code path

`tests/` holds a pytest suite (`test_parser.py`) that drives `parser.py` as
a subprocess, plus `tests/fixtures/` — additional XML/directory fixtures for
error and edge cases (malformed XML, wrong provider/namespace, missing
`<System>`, empty `<Events>`, mixed EventIDs, directory input scenarios)
that `samples/` doesn't cover. Run with:

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install pytest
python -m pytest
```

The repo is a git repo (`git init` + one root commit, now pushed to
`cturco1/AI-cyber-defense-ops`) with a `.gitignore` excluding `.DS_Store`,
`.venv/`, `.pytest_cache/`, and the local `.claude/settings.local.json`.

## How to use it

```bash
# Single event -> JSON object
python3 parser.py samples/event1.xml

# Multi-event file -> JSON array
python3 parser.py samples/multi_events.xml

# stdin (default when path is omitted, or pass "-" explicitly)
cat samples/event1.xml | python3 parser.py
cat samples/multi_events.xml | python3 parser.py -

# Directory of .xml files -> parsed and aggregated together, sorted by name
python3 parser.py samples/

# Filters (all case-insensitive except --integrity-level, which is an exact
# choice from High/Medium/Low/System; multiple filter types combine with AND)
python3 parser.py samples/multi_events.xml --image powershell
python3 parser.py samples/multi_events.xml --user CONDEF\\jsmith
python3 parser.py samples/multi_events.xml --integrity-level Medium

# --command-line is repeatable; multiple values are OR'd together
# (values starting with "-" need the "=" form to avoid argparse confusion)
python3 parser.py samples/multi_events.xml --command-line=-enc
python3 parser.py samples/multi_events.xml --command-line encoded --command-line=-enc

python3 parser.py --help   # full flag reference
```

Errors (missing file, malformed XML, wrong namespace/provider, no Event ID 1
events found) print `error: ...` to stderr and exit 1. Non-fatal per-event
issues (e.g. an Event ID 3 mixed into an `<Events>` file) print a
`warning: ...` to stderr and are skipped rather than aborting the whole run.
When the input is a directory, a per-file error (e.g. one malformed XML file
among several) is downgraded to the same skip-with-warning treatment rather
than aborting the other files — it only hard-fails if the *whole run* ends
up with zero valid Event ID 1 events.

## Decisions made and why

- **Sysmon/provider validation before parsing.** A file with the right root
  tag but the wrong `Provider` (e.g. Security-Auditing logs, which share the
  same generic Windows Event namespace) is rejected as "not a Sysmon event"
  rather than silently parsed with blank fields.
- **Skip vs. hard-fail per event.** Individual malformed or non-EventID-1
  events are skipped with a warning so one bad record in a large export
  doesn't kill the whole run; the run only hard-fails if *zero* valid
  Event ID 1 events remain.
- **Single object vs. array output.** Exactly one result prints as a bare
  JSON object; more than one prints as an array — matches the original spec
  ("one object per event, or array for multiple events") and keeps
  single-event usage ergonomic (no `[...]` wrapper to unwrap in scripts).
- **Filters are case-insensitive for `--image`/`--user`/`--command-line`**,
  matching Windows' own case-insensitivity for paths and domain\username.
  `--integrity-level` uses argparse `choices` for exact validation instead,
  since it's a fixed small enum.
- **Zero filter matches -> `[]` + exit 0, not an error.** This is a valid
  empty query result (grep-like), distinct from the file-level error case
  where the file has no Event ID 1 events *at all*. Scripts/pipelines can
  treat filter results uniformly without special-casing "found nothing."
- **`--command-line` is repeatable with OR semantics**, not a single
  comma-separated string — command lines routinely contain literal commas,
  so splitting on commas would be unreliable. Repeating the flag is the
  standard argparse idiom for a list of alternatives.
- **`path` defaults to stdin (`-`)** rather than being required, matching
  the Unix convention of `cat file | tool` and `tool -` both working. A
  directory is auto-detected and expanded to its `*.xml` files (sorted by
  name) rather than requiring a separate `--dir` flag.
- **Directory input reuses the per-event skip-with-warning model at the
  file level.** One bad file in a batch (malformed XML, wrong provider,
  etc.) is skipped with a warning instead of aborting the whole directory
  scan — consistent with how a single bad *event* is already handled inside
  one file. A directory containing zero `.xml` files is still a hard error,
  since that's almost certainly a mistyped path rather than "nothing to
  report."

## What's left to do

- No packaging (no `requirements.txt`/`pyproject.toml`); the script only
  uses the Python standard library, so this is optional unless you want to
  `pip install` it or add dependencies later.
- Git commit author on the pre-existing commits was auto-derived from the
  local machine (`cherylglass@Cheryls-MacBook-Pro.local`). Global git config
  is now set to `Cheryl Glass <ohmyyygoddess@gmail.com>` so future commits
  use the right identity; the old commits were intentionally left as-is
  rather than rewriting pushed history.
