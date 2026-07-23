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

No source code, build configuration, or dependencies exist yet. This file will need
the following filled in once the project takes shape:
- Build, lint, and test commands (including how to run a single test)
- High-level architecture and directory layout
- Any conventions or constraints specific to this project
