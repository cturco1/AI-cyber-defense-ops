#!/usr/bin/env python3
import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET

SYSMON_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = {"ns": SYSMON_NS}
EXPECTED_PROVIDER = "Microsoft-Windows-Sysmon"


class SysmonFormatError(Exception):
    """Raised when a file is not a well-formed Sysmon event log."""


def _local_name(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def parse_event(event_elem):
    system = event_elem.find("ns:System", NS)
    if system is None:
        raise SysmonFormatError("<Event> is missing required <System> element")

    provider = system.find("ns:Provider", NS)
    provider_name = provider.get("Name") if provider is not None else None
    if provider_name != EXPECTED_PROVIDER:
        raise SysmonFormatError(
            f"not a Sysmon event: Provider is {provider_name!r}, "
            f"expected {EXPECTED_PROVIDER!r}"
        )

    event_id_elem = system.find("ns:EventID", NS)
    if event_id_elem is None or event_id_elem.text is None:
        raise SysmonFormatError("<System> is missing required <EventID> element")
    try:
        event_id = int(event_id_elem.text)
    except ValueError:
        raise SysmonFormatError(f"EventID is not numeric: {event_id_elem.text!r}")

    computer_elem = system.find("ns:Computer", NS)

    data = {}
    event_data = event_elem.find("ns:EventData", NS)
    if event_data is not None:
        for d in event_data.findall("ns:Data", NS):
            name = d.get("Name")
            if name is not None:
                data[name] = d.text

    return {
        "EventID": event_id,
        "UtcTime": data.get("UtcTime"),
        "Image": data.get("Image"),
        "CommandLine": data.get("CommandLine"),
        "User": data.get("User"),
        "IntegrityLevel": data.get("IntegrityLevel"),
        "ParentImage": data.get("ParentImage"),
        "ParentCommandLine": data.get("ParentCommandLine"),
        "Computer": computer_elem.text if computer_elem is not None else None,
        "Hashes": data.get("Hashes"),
    }


def matches_filters(event, args):
    if args.image and args.image.lower() not in (event["Image"] or "").lower():
        return False
    if args.user and args.user.lower() != (event["User"] or "").lower():
        return False
    if args.integrity_level and args.integrity_level != event["IntegrityLevel"]:
        return False
    if args.command_line:
        cmdline = (event["CommandLine"] or "").lower()
        if not any(term.lower() in cmdline for term in args.command_line):
            return False
    return True


def iter_input_sources(path):
    """Yield (label, source) pairs to feed to load_events().

    `source` is a path string or a file object. "-" (or no path) yields
    stdin; a directory yields each *.xml file inside it, sorted by name;
    anything else yields itself as a single file source.
    """
    if path is None or path == "-":
        yield "<stdin>", sys.stdin
        return

    if os.path.isdir(path):
        names = sorted(name for name in os.listdir(path) if name.endswith(".xml"))
        if not names:
            raise SysmonFormatError(f"no .xml files found in directory: {path}")
        for name in names:
            full = os.path.join(path, name)
            yield full, full
        return

    yield path, path


def load_events(label, source):
    try:
        tree = ET.parse(source)
    except FileNotFoundError:
        raise SysmonFormatError(f"file not found: {label}")
    except IsADirectoryError:
        raise SysmonFormatError(f"expected a file, got a directory: {label}")
    except PermissionError:
        raise SysmonFormatError(f"permission denied reading file: {label}")
    except ET.ParseError as e:
        raise SysmonFormatError(f"malformed XML: {e}")

    root = tree.getroot()

    if not root.tag.startswith(f"{{{SYSMON_NS}}}"):
        raise SysmonFormatError(
            f"not a Sysmon XML file: root element <{_local_name(root.tag)}> is "
            f"missing the expected namespace ({SYSMON_NS})"
        )

    root_name = _local_name(root.tag)
    if root_name == "Events":
        events = root.findall("ns:Event", NS)
        if not events:
            raise SysmonFormatError("<Events> root contains no <Event> elements")
    elif root_name == "Event":
        events = [root]
    else:
        raise SysmonFormatError(
            f"unexpected root element <{root_name}>; expected <Event> or <Events>"
        )

    return events


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract key fields from Sysmon Event ID 1 (Process Creation) XML events."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="-",
        help=(
            "path to a Sysmon XML file, or a directory of .xml files to parse "
            "together; omit or pass '-' to read a single XML document from "
            "stdin (default: stdin)"
        ),
    )
    parser.add_argument("--image", help="keep events whose Image contains this substring (case-insensitive)")
    parser.add_argument("--user", help="keep events whose User exactly matches this value (case-insensitive)")
    parser.add_argument(
        "--integrity-level",
        choices=["High", "Medium", "Low", "System"],
        help="keep events whose IntegrityLevel exactly matches this value",
    )
    parser.add_argument(
        "--command-line",
        action="append",
        dest="command_line",
        metavar="SUBSTR",
        help=(
            "keep events whose CommandLine contains this substring "
            "(case-insensitive); repeat to match multiple values (OR'd together), "
            "e.g. --command-line encoded --command-line=-enc"
        ),
    )
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        sources = list(iter_input_sources(args.path))
    except SysmonFormatError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    multi_source = len(sources) > 1

    results = []
    for label, source in sources:
        try:
            events = load_events(label, source)
        except SysmonFormatError as e:
            if multi_source:
                print(f"warning: skipping {label}: {e}", file=sys.stderr)
                continue
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)

        for i, event_elem in enumerate(events):
            event_ref = f"{label} event {i}" if multi_source else f"event {i}"
            try:
                parsed = parse_event(event_elem)
            except SysmonFormatError as e:
                print(f"warning: skipping {event_ref}: {e}", file=sys.stderr)
                continue

            if parsed["EventID"] != 1:
                print(
                    f"warning: skipping {event_ref}: EventID {parsed['EventID']} is "
                    "not Process Creation (1)",
                    file=sys.stderr,
                )
                continue

            results.append(parsed)

    if not results:
        suffix = " in file" if len(sources) == 1 and sources[0][0] != "<stdin>" else ""
        print(
            f"error: no Event ID 1 (Process Creation) events found{suffix}",
            file=sys.stderr,
        )
        sys.exit(1)

    filtered_results = [r for r in results if matches_filters(r, args)]

    if not filtered_results:
        print(json.dumps([], indent=2))
        return

    output = filtered_results[0] if len(filtered_results) == 1 else filtered_results
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
