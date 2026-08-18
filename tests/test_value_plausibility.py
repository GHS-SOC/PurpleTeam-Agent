"""Generated values must be telemetry a real Windows host would emit.

`unresolved` being empty means every constraint was invertible. It does not mean
the values are sensible. When several `contains` fragments land on one field they
are joined, and the join is often nonsense — yet the oracle returns MATCH,
because every fragment is literally present.

That combination is the dangerous one. A deployed rule will not fire on a mangled
value, so the run reports "nothing fired" and the report reads as a coverage gap
when the real cause is generation. First row of the failure table.

The three values below are verbatim from a real T1547.001 registry persistence
run that was caught at Stage A before it could be ingested.
"""

from __future__ import annotations

from purple_agent import tools


REAL_GARBAGE = {
    "EventID": 13,
    "Details": r"C:\Perflogs :\Users\ \Favorites",
    "TargetObject": r"C:\Users\svc_backup\AppData\Local\Temp\Common Startup "
                    r"SOFTWARE\Microsoft\Windows",
    "CommandLine": r"Microsoft\Windows\CurrentVersion\Run C:\users\Public\ "
                   r"del /s /f /q c:\ \*.bac",
}

REALISTIC = {
    "EventID": 13,
    "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater",
    "Details": r"C:\Users\svc_backup\AppData\Local\Temp\updater.exe",
    "Image": r"C:\Windows\System32\reg.exe",
    "CommandLine": r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"'
                   r' /v Updater /d "C:\Users\Public\updater.exe" /f',
}


class TestTheRealGarbageIsCaught:
    """Every one of these shipped from a live Stage A run."""

    def test_all_three_fields_are_flagged(self):
        flagged = {f["field"] for f in tools._implausible_fields(REAL_GARBAGE)}
        assert flagged == {"Details", "TargetObject", "CommandLine"}

    def test_each_flag_names_the_problem(self):
        by_field = {f["field"]: f["problem"]
                    for f in tools._implausible_fields(REAL_GARBAGE)}
        assert "drive separator with no drive letter" in by_field["Details"]
        assert "filesystem path" in by_field["TargetObject"]
        assert "more than one drive root" in by_field["CommandLine"]


class TestRealisticValuesPassCleanly:
    """A check that flags good telemetry is worse than no check — it would train
    the model to rebuild forever, and every rebuild is another oracle round."""

    def test_nothing_flagged(self):
        assert tools._implausible_fields(REALISTIC) == []

    def test_a_normal_lsass_access_event_passes(self):
        """The most-exercised event in the project. Must never trip."""
        assert tools._implausible_fields({
            "EventID": 10,
            "TargetImage": r"C:\Windows\system32\lsass.exe",
            "SourceImage": r"C:\Users\svc_backup\AppData\Local\Temp\procdump64.exe",
            "CallTrace": r"C:\Windows\SYSTEM32\ntdll.dll+9d234|"
                         r"C:\Windows\System32\dbgcore.dll+2d81e|UNKNOWN(0x1c119b)",
        }) == []

    def test_non_path_fields_are_ignored(self):
        """Hashes, GUIDs and access masks are not paths and must not be judged
        as though they were."""
        assert tools._implausible_fields({
            "GrantedAccess": "0x1410",
            "Hashes": "SHA256=" + "a" * 64,
            "ProcessGuid": "{5fa1dc8e-59b1-0000-0000-0000000017eb}",
        }) == []
