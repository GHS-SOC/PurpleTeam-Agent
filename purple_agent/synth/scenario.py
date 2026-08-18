"""Coherent host/user/process context for one run.

Detections that correlate across events fail if the events do not hang together,
and an analyst reading disjointed telemetry can tell immediately that it is
fake. One ScenarioContext is generated per run and threaded through every event,
so 4624 -> 4672 -> 4688 -> Sysmon 1 -> Sysmon 10 read as one session on one host
by one user, with a real parent/child process lineage.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .. import config


@dataclass
class ProcessIdentity:
    """One process in the scenario's lineage."""

    pid: int
    guid: str
    image: str
    command_line: str
    parent_pid: int = 0
    parent_image: str = ""


@dataclass
class ScenarioContext:
    """Shared identity for every event in a run."""

    hostname: str
    domain: str = field(default_factory=lambda: config.NETBIOS_DOMAIN)
    dns_domain: str = field(default_factory=lambda: config.DNS_DOMAIN)
    username: str = field(default_factory=lambda: config.ACTOR_USERNAME)
    user_sid: str = "S-1-5-21-1004336348-1177238915-682003330-1134"
    logon_id: str = "0x3E7A91"
    logon_guid: str = "{00000000-0000-0000-0000-000000000000}"
    session_id: int = 2
    source_ip: str = "10.4.7.31"
    started: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    _rng: random.Random = field(default_factory=random.Random, repr=False)
    _next_pid: int = field(default=0, repr=False)

    @property
    def fqdn(self) -> str:
        return f"{self.hostname}.{self.dns_domain}"

    @property
    def user_principal(self) -> str:
        return f"{self.domain}\\{self.username}"

    def new_pid(self) -> int:
        """Allocate a plausible, monotonically increasing PID."""
        if not self._next_pid:
            self._next_pid = self._rng.randrange(2000, 6000)
        self._next_pid += self._rng.randrange(4, 40) * 4
        return self._next_pid

    def new_guid(self, tag: int = 0) -> str:
        """Sysmon-style process GUID."""
        return (
            f"{{{self._rng.getrandbits(32):08x}-"
            f"{self._rng.getrandbits(16):04x}-0000-0000-"
            f"{tag:012x}}}"
        )

    def timestamp(self, offset_seconds: int = 0) -> datetime:
        return self.started + timedelta(seconds=offset_seconds)

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "fqdn": self.fqdn,
            "domain": self.domain,
            # The suffix the events actually carry -- verification builds its
            # hostname queries from this, not from config, so a run stays
            # searchable even if the configured domain changes later.
            "dns_domain": self.dns_domain,
            "username": self.username,
            "user_sid": self.user_sid,
            "logon_id": self.logon_id,
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "started": self.started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }


def new_scenario(
    hostname: str,
    username: str = "",
    domain: str = "",
    seed: int | None = None,
    minutes_ago: int = 3,
) -> ScenarioContext:
    """Build a scenario context.

    Events are stamped a few minutes in the past by default. Live Chronicle
    rules evaluate near-real-time data, so backdating past the live window means
    nothing fires -- and a future timestamp is worse, since the event may never
    fall into an evaluated window at all.
    """
    rng = random.Random(seed)
    context = ScenarioContext(hostname=hostname, _rng=rng)
    if username:
        context.username = username
    if domain:
        context.domain = domain
    context.started = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    context.logon_id = f"0x{rng.randrange(0x100000, 0xFFFFFF):X}"
    context.logon_guid = (
        f"{{{rng.getrandbits(32):08x}-{rng.getrandbits(16):04x}-"
        f"{rng.getrandbits(16):04x}-{rng.getrandbits(16):04x}-"
        f"{rng.getrandbits(48):012x}}}"
    )
    return context


# Defaults per Windows event field, filled in when a Sigma rule does not pin
# the value. Keys are (field_name) -> callable(context, event_id) -> str.
def default_fields(context: ScenarioContext, event_id: int) -> dict[str, str]:
    """Scenario-consistent defaults for an event's unpinned fields."""
    utc = context.timestamp()
    stamp = utc.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    common = {
        "RuleName": "-",
        "UtcTime": stamp,
        "User": context.user_principal,
        "SourceUser": context.user_principal,
        "TargetUser": "NT AUTHORITY\\SYSTEM",
        "SubjectUserSid": context.user_sid,
        "SubjectUserName": context.username,
        "SubjectDomainName": context.domain,
        "SubjectLogonId": context.logon_id,
        "TargetUserSid": context.user_sid,
        "TargetUserName": context.username,
        "TargetDomainName": context.domain,
        "TargetLogonId": context.logon_id,
        "LogonId": context.logon_id,
        "LogonGuid": context.logon_guid,
        "TerminalSessionId": str(context.session_id),
        "IntegrityLevel": "High",
        "CurrentDirectory": "C:\\Windows\\system32\\",
        "IpAddress": context.source_ip,
        "IpPort": "49721",
        "WorkstationName": context.hostname,
        "Workstation": context.hostname,
        "Status": "0x0",
        "TokenElevationType": "%%1936",
        "MandatoryLabel": "S-1-16-12288",
        "Signed": "true",
        "SignatureStatus": "Valid",
        "Initiated": "true",
        "Protocol": "tcp",
        "SourceIsIpv6": "false",
        "DestinationIsIpv6": "false",
        "SourceIp": context.source_ip,
        "SourceHostname": context.fqdn,
        # Network fields are typed: an unset port becomes "-" and the parser
        # aborts the event on strconv.Atoi.
        "SourcePort": "49732",
        "SourcePortName": "-",
        # Both reserved for documentation use and guaranteed never to resolve
        # to anything real: 203.0.113.0/24 is RFC 5737 TEST-NET-3, and
        # example.com is protected under RFC 2606. A synthetic C2 destination
        # must never be a domain or address someone could actually register
        # or route traffic to.
        "DestinationIp": "203.0.113.24",
        "DestinationHostname": "cdn-c2.example.com",
        "DestinationPort": "443",
        "DestinationPortName": "https",
        "QueryStatus": "0",
        "QueryName": "cdn-c2.example.com",
        "QueryResults": "type:  5 cdn-c2.example.com;::ffff:203.0.113.24;",
        # UDM requires target.file on FILE_CREATION and target.registry on
        # REGISTRY_MODIFICATION. Leaving these unset makes the parser reject the
        # whole event ("missing target.file field") after ingestion has already
        # reported success.
        "TargetFilename": (
            "C:\\Users\\svc_backup\\AppData\\Local\\Temp\\lsass_dump.dmp"
        ),
        "CreationUtcTime": stamp,
        "EventType": "SetValue",
        "TargetObject": (
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
        ),
        "Details": "DWORD (0x00000001)",
    }

    if event_id == 2:
        # Timestomping only makes sense if the two stamps differ -- an event
        # whose "previous" creation time equals the new one describes a change
        # that did not happen.
        common["PreviousCreationUtcTime"] = (
            utc - timedelta(days=402)
        ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    # EventType is what distinguishes Sysmon 12/13/14; the shared default above
    # is SetValue, which is only correct for 13.
    if event_id == 12:
        common["EventType"] = "CreateKey"
    if event_id == 14:
        common.update({
            "EventType": "RenameKey",
            "NewName": (
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater.bak"
            ),
        })
    if event_id in (23, 26):
        common.update({
            "IsExecutable": "false",
            "Archived": "true",
        })
    if event_id == 25:
        common["Type"] = "Image is replaced"
    if event_id in (4103, 4104):
        # A script block logged from the console or from downloaded code has an
        # empty Path -- that is the normal shape for the in-memory execution
        # these rules target, not a missing value.
        common.update({
            "MessageNumber": "1",
            "MessageTotal": "1",
            "ScriptBlockId": (
                f"{{{context._rng.getrandbits(32):08x}-"
                f"{context._rng.getrandbits(16):04x}-4a1c-9f3e-"
                f"{context._rng.getrandbits(48):012x}}}"
            ),
            "Path": "",
            "ScriptBlockText": "Get-Process -Name lsass",
            "UserData": "",
            "Payload": "Get-Process -Name lsass",
            "ContextInfo": (
                f"        Severity = Informational\n"
                f"        Host Name = ConsoleHost\n"
                f"        Host Version = 5.1.19041.4291\n"
                f"        Engine Version = 5.1.19041.4291\n"
                f"        User = {context.user_principal}\n"
                f"        Connected User = \n"
                f"        Shell ID = Microsoft.PowerShell\n"
            ),
        })
    if event_id == 10:
        common.update({
            "GrantedAccess": "0x1410",
            "CallTrace": (
                "C:\\Windows\\SYSTEM32\\ntdll.dll+9d234|"
                "C:\\Windows\\System32\\KERNELBASE.dll+2d81e|"
                "UNKNOWN(00000000001C119B)"
            ),
        })
    if event_id == 4672:
        common["PrivilegeList"] = (
            "SeAssignPrimaryTokenPrivilege\n\t\t\tSeTcbPrivilege\n\t\t\t"
            "SeSecurityPrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\t"
            "SeDebugPrivilege"
        )
    if event_id in (4624, 4625):
        common.update({
            "LogonType": "3",
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
            "KeyLength": "128",
            "ImpersonationLevel": "%%1833",
            "ElevatedToken": "%%1842",
            "VirtualAccount": "%%1843",
            "RestrictedAdminMode": "-",
        })
    if event_id in (4768, 4769):
        common.update({
            "ServiceName": f"MSSQLSvc/sql01.{context.dns_domain}:1433",
            "TicketOptions": "0x40810000",
            # RC4 -- the weak encryption type Kerberoasting rules key on.
            "TicketEncryptionType": "0x17",
            "PreAuthType": "2",
        })
    return common
