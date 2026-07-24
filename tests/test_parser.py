import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
PARSER = ROOT / "parser.py"
SAMPLES = ROOT / "samples"
FIXTURES = Path(__file__).parent / "fixtures"


def run(*args):
    result = subprocess.run(
        [sys.executable, str(PARSER), *args],
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


# --- valid parsing ---------------------------------------------------------


def test_single_event_parses_to_json_object():
    code, out, err = run(str(SAMPLES / "event1.xml"))
    assert code == 0
    assert err == ""
    parsed = json.loads(out)
    assert isinstance(parsed, dict)
    assert parsed == {
        "EventID": 1,
        "UtcTime": "2024-12-01 16:05:11.850",
        "Image": r"C:\Windows\System32\whoami.exe",
        "CommandLine": "whoami  /groups",
        "User": "CONDEF\\Administrator",
        "IntegrityLevel": "High",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "ParentCommandLine": r'"C:\WINDOWS\system32\cmd.exe"',
        "Computer": "win11v.condef.local",
        "Hashes": (
            "SHA1=C23488BA47972B04F795D34B35C8257EC4B7AC9D,"
            "MD5=956692DADC5B2CEB46E9219F7A5BEFFA,"
            "SHA256=23240EF9F8B0A9A324110B1C2331DE31DC1B0E08F5359CB707E51A939AF56CD3,"
            "IMPHASH=E4464BCD92DF7AC69CCD074CB9C0EFED"
        ),
    }


def test_multi_event_parses_to_json_array():
    code, out, err = run(str(SAMPLES / "multi_events.xml"))
    assert code == 0
    assert err == ""
    parsed = json.loads(out)
    assert isinstance(parsed, list)
    assert len(parsed) == 3
    assert [e["Image"] for e in parsed] == [
        r"C:\Windows\System32\whoami.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    ]


# --- file-level errors ------------------------------------------------------


def test_missing_file_errors():
    code, out, err = run(str(SAMPLES / "does_not_exist.xml"))
    assert code == 1
    assert out == ""
    assert "error: file not found" in err


def test_directory_as_path_errors():
    code, out, err = run(str(SAMPLES))
    assert code == 1
    assert "error: expected a file, got a directory" in err


def test_malformed_xml_errors():
    code, out, err = run(str(FIXTURES / "malformed.xml"))
    assert code == 1
    assert "error: malformed XML" in err


def test_wrong_provider_errors():
    code, out, err = run(str(FIXTURES / "wrong_provider.xml"))
    assert code == 1
    assert "not a Sysmon event" in err
    assert "Microsoft-Windows-Security-Auditing" in err


def test_wrong_namespace_errors():
    code, out, err = run(str(FIXTURES / "wrong_namespace.xml"))
    assert code == 1
    assert "missing the expected namespace" in err


def test_unexpected_root_element_errors():
    code, out, err = run(str(FIXTURES / "unexpected_root.xml"))
    assert code == 1
    assert "unexpected root element <EventLog>" in err


def test_missing_system_element_errors():
    code, out, err = run(str(FIXTURES / "missing_system.xml"))
    assert code == 1
    assert "missing required <System> element" in err


def test_empty_events_root_errors():
    code, out, err = run(str(FIXTURES / "empty_events.xml"))
    assert code == 1
    assert "<Events> root contains no <Event> elements" in err


def test_all_non_process_creation_events_errors():
    code, out, err = run(str(FIXTURES / "all_non_process_creation.xml"))
    assert code == 1
    assert out == ""
    assert "no Event ID 1 (Process Creation) events found in file" in err


# --- per-event skip behavior -------------------------------------------------


def test_non_process_creation_event_is_skipped_with_warning():
    code, out, err = run(str(FIXTURES / "mixed_eventid.xml"))
    assert code == 0
    assert "warning: skipping event 1: EventID 3 is not Process Creation (1)" in err
    parsed = json.loads(out)
    assert isinstance(parsed, dict)
    assert parsed["EventID"] == 1
    assert parsed["Image"] == r"C:\Windows\System32\whoami.exe"


# --- filters -----------------------------------------------------------------


def test_image_filter_is_substring_and_case_insensitive():
    code, out, err = run(str(SAMPLES / "multi_events.xml"), "--image", "POWERSHELL")
    assert code == 0
    parsed = json.loads(out)
    assert len(parsed) == 2
    assert all("powershell.exe" in e["Image"].lower() for e in parsed)


def test_user_filter_is_exact_and_case_insensitive():
    code, out, err = run(
        str(SAMPLES / "multi_events.xml"), "--user", "condef\\jsmith"
    )
    assert code == 0
    parsed = json.loads(out)
    assert isinstance(parsed, dict)
    assert parsed["User"] == "CONDEF\\jsmith"


def test_integrity_level_filter_exact_match():
    code, out, err = run(
        str(SAMPLES / "multi_events.xml"), "--integrity-level", "Medium"
    )
    assert code == 0
    parsed = json.loads(out)
    assert isinstance(parsed, dict)
    assert parsed["IntegrityLevel"] == "Medium"


def test_integrity_level_filter_rejects_invalid_choice():
    code, out, err = run(
        str(SAMPLES / "multi_events.xml"), "--integrity-level", "Nonexistent"
    )
    assert code == 2
    assert "invalid choice" in err


def test_command_line_filter_repeatable_is_ored():
    code, out, err = run(
        str(SAMPLES / "multi_events.xml"),
        "--command-line",
        "groups",
        "--command-line=-enc",
    )
    assert code == 0
    parsed = json.loads(out)
    assert len(parsed) == 2
    assert {e["Image"].rsplit("\\", 1)[-1] for e in parsed} == {
        "whoami.exe",
        "powershell.exe",
    }


def test_filters_combine_with_and():
    code, out, err = run(
        str(SAMPLES / "multi_events.xml"),
        "--image",
        "powershell",
        "--integrity-level",
        "Medium",
    )
    assert code == 0
    parsed = json.loads(out)
    assert isinstance(parsed, dict)
    assert parsed["IntegrityLevel"] == "Medium"
    assert "powershell.exe" in parsed["Image"].lower()


def test_zero_filter_matches_returns_empty_array_not_error():
    code, out, err = run(
        str(SAMPLES / "multi_events.xml"), "--image", "doesnotexist.exe"
    )
    assert code == 0
    assert err == ""
    assert json.loads(out) == []
