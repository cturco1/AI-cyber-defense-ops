# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A Sysmon XML parser: a Python tool that extracts key fields from Sysmon Event ID 1
(Process Creation) events and outputs them as JSON (one object per event, or a JSON
array when parsing multiple events).

### Fields to extract

- EventID
- UtcTime
- Image (process path)
- CommandLine
- User
- IntegrityLevel
- ParentImage
- ParentCommandLine
- Computer
- Hashes

## Status

`parser.py` (stdlib only, no packaging) implements the extraction described above,
with `samples/` fixtures and a `tests/` pytest suite covering it end-to-end.

### Test commands

```sh
python3 -m venv .venv && source .venv/bin/activate && pip install pytest
python -m pytest              # run the full suite
python -m pytest -k <name>    # run a single test
```

### Layout

- `parser.py` — the CLI tool
- `samples/` — hand-built Sysmon XML fixtures used both for manual runs and tests
- `tests/` — pytest suite (drives `parser.py` as a subprocess); `tests/fixtures/`
  holds additional XML fixtures for error/edge-case scenarios not covered by `samples/`
