"""Map Sigma logsource to a concrete Windows event identity.

A Sigma rule says *what* to look for (`category: process_access`,
`TargetImage|endswith: \\lsass.exe`) but never which Windows Event ID carries
it. This table supplies that missing half.

The convenient part: for Sysmon, Sigma's field names ARE the Sysmon `EventData`
Data Name values, so the field mapping is identity. Security-channel events need
a small alias table where Sigma uses a friendlier name than the log does.

Chronicle parses the two channels under different log types --
`WINDOWS_SYSMON` and `WINEVTLOG_XML` -- so events must be grouped by channel
before ingest. Sending Sysmon XML as WINEVTLOG_XML silently yields nothing.
"""

from __future__ import annotations

from dataclasses import dataclass

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"

SYSMON_LOG_TYPE = "WINDOWS_SYSMON"
SECURITY_LOG_TYPE = "WINEVTLOG_XML"
POWERSHELL_LOG_TYPE = "POWERSHELL"

SYSMON_PROVIDER = ("Microsoft-Windows-Sysmon", "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}")
SECURITY_PROVIDER = (
    "Microsoft-Windows-Security-Auditing",
    "{54849625-5478-4994-A5BA-3E3B0328C30D}",
)
POWERSHELL_PROVIDER = (
    "Microsoft-Windows-PowerShell",
    "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
)


@dataclass(frozen=True)
class EventTemplate:
    """Everything needed to emit one Windows event of a given type."""

    event_id: int
    channel: str
    log_type: str
    provider_name: str
    provider_guid: str
    # Ordered EventData field names. Order is not cosmetic: some Chronicle
    # parsers read positionally, and real Windows events always emit this order.
    fields: tuple[str, ...]
    level: int = 4
    task: int = 0
    opcode: int = 0
    keywords: str = "0x8000000000000000"
    description: str = ""


def _sysmon(event_id: int, fields: tuple[str, ...], description: str) -> EventTemplate:
    return EventTemplate(
        event_id=event_id,
        channel=SYSMON_CHANNEL,
        log_type=SYSMON_LOG_TYPE,
        provider_name=SYSMON_PROVIDER[0],
        provider_guid=SYSMON_PROVIDER[1],
        fields=fields,
        task=event_id,
        description=description,
    )


def _powershell(
    event_id: int,
    fields: tuple[str, ...],
    task: int,
    opcode: int,
    level: int,
    description: str,
) -> EventTemplate:
    """A modern PowerShell operational-channel event (4103 / 4104).

    Separate from the classic "Windows PowerShell" channel (events 400/600/800),
    which is deliberately NOT templated: those emit unnamed `<Data>` elements
    rather than `<Data Name="...">`, so they need a different XML shape than
    winevt._render produces. Sigma addresses that shape through a single `Data`
    pseudo-field, and only 12 rules in the corpus use it.
    """
    return EventTemplate(
        event_id=event_id,
        channel=POWERSHELL_CHANNEL,
        log_type=POWERSHELL_LOG_TYPE,
        provider_name=POWERSHELL_PROVIDER[0],
        provider_guid=POWERSHELL_PROVIDER[1],
        fields=fields,
        level=level,
        task=task,
        opcode=opcode,
        keywords="0x0",
        description=description,
    )


def _security(event_id: int, fields: tuple[str, ...], task: int, description: str) -> EventTemplate:
    return EventTemplate(
        event_id=event_id,
        channel=SECURITY_CHANNEL,
        log_type=SECURITY_LOG_TYPE,
        provider_name=SECURITY_PROVIDER[0],
        provider_guid=SECURITY_PROVIDER[1],
        fields=fields,
        task=task,
        keywords="0x8020000000000000",  # Audit Success
        description=description,
    )


TEMPLATES: dict[int, EventTemplate] = {
    # --- Sysmon -----------------------------------------------------------
    1: _sysmon(
        1,
        ("RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "FileVersion",
         "Description", "Product", "Company", "OriginalFileName", "CommandLine",
         "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId",
         "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId",
         "ParentImage", "ParentCommandLine", "ParentUser"),
        "Process creation",
    ),
    2: _sysmon(
        2,
        ("RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
         "TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime", "User"),
        "File creation time changed -- timestomping",
    ),
    3: _sysmon(
        3,
        ("RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User",
         "Protocol", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname",
         "SourcePort", "SourcePortName", "DestinationIsIpv6", "DestinationIp",
         "DestinationHostname", "DestinationPort", "DestinationPortName"),
        "Network connection",
    ),
    7: _sysmon(
        7,
        ("RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "ImageLoaded",
         "FileVersion", "Description", "Product", "Company", "OriginalFileName",
         "Hashes", "Signed", "Signature", "SignatureStatus", "User"),
        "Image loaded",
    ),
    8: _sysmon(
        8,
        ("RuleName", "UtcTime", "SourceProcessGuid", "SourceProcessId",
         "SourceImage", "TargetProcessGuid", "TargetProcessId", "TargetImage",
         "NewThreadId", "StartAddress", "StartModule", "StartFunction",
         "SourceUser", "TargetUser"),
        "CreateRemoteThread",
    ),
    10: _sysmon(
        10,
        ("RuleName", "UtcTime", "SourceProcessGUID", "SourceProcessId",
         "SourceThreadId", "SourceImage", "TargetProcessGUID", "TargetProcessId",
         "TargetImage", "GrantedAccess", "CallTrace", "SourceUser", "TargetUser"),
        "Process accessed -- the LSASS-access event most credential-dumping rules key on",
    ),
    11: _sysmon(
        11,
        ("RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
         "TargetFilename", "CreationUtcTime", "User"),
        "File created",
    ),
    12: _sysmon(
        12,
        ("RuleName", "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image",
         "TargetObject", "User"),
        "Registry key or value created or deleted",
    ),
    13: _sysmon(
        13,
        ("RuleName", "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image",
         "TargetObject", "Details", "User"),
        "Registry value set",
    ),
    14: _sysmon(
        14,
        ("RuleName", "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image",
         "TargetObject", "NewName", "User"),
        "Registry key or value renamed",
    ),
    22: _sysmon(
        22,
        ("RuleName", "UtcTime", "ProcessGuid", "ProcessId", "QueryName",
         "QueryStatus", "QueryResults", "Image", "User"),
        "DNS query",
    ),
    23: _sysmon(
        23,
        ("RuleName", "UtcTime", "ProcessGuid", "ProcessId", "User", "Image",
         "TargetFilename", "Hashes", "IsExecutable", "Archived"),
        "File deleted and archived -- the anti-forensics event",
    ),
    25: _sysmon(
        25,
        ("RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "Type", "User"),
        "Process image tampered -- hollowing or herpaderping",
    ),
    26: _sysmon(
        26,
        ("RuleName", "UtcTime", "ProcessGuid", "ProcessId", "User", "Image",
         "TargetFilename", "Hashes", "IsExecutable"),
        "File deleted, logged only -- Sysmon 23 without the archive",
    ),
    # --- PowerShell operational channel -----------------------------------
    #
    # 4104 is the only Windows event that records a script's own TEXT. Every
    # other view of PowerShell -- process creation, image load, network -- sees
    # the envelope: that powershell.exe ran, with some command line. An attacker
    # who passes `-enc <base64>`, or who loads the PowerShell engine into
    # another process without spawning powershell.exe at all, leaves an envelope
    # that says nothing. 4104 sees the letter regardless, because it is emitted
    # by the engine itself as it compiles each script block.
    #
    # That is why 178 Sigma rules key on ScriptBlockText and why they cannot be
    # emulated from any other event.
    4103: _powershell(
        4103,
        ("ContextInfo", "UserData", "Payload"),
        task=106, opcode=20, level=4,
        description="PowerShell module/pipeline execution details",
    ),
    4104: _powershell(
        4104,
        ("MessageNumber", "MessageTotal", "ScriptBlockText", "ScriptBlockId", "Path"),
        task=2, opcode=15, level=3,
        description=(
            "PowerShell script block logging -- the only event carrying the "
            "script's own text"
        ),
    ),
    # --- Security channel -------------------------------------------------
    4624: _security(
        4624,
        ("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
         "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId",
         "LogonType", "LogonProcessName", "AuthenticationPackageName",
         "WorkstationName", "LogonGuid", "TransmittedServices", "LmPackageName",
         "KeyLength", "ProcessId", "ProcessName", "IpAddress", "IpPort",
         "ImpersonationLevel", "RestrictedAdminMode", "TargetOutboundUserName",
         "TargetOutboundDomainName", "VirtualAccount", "TargetLinkedLogonId",
         "ElevatedToken"),
        12544,
        "An account was successfully logged on",
    ),
    4625: _security(
        4625,
        ("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
         "TargetUserSid", "TargetUserName", "TargetDomainName", "FailureReason",
         "Status", "SubStatus", "LogonType", "LogonProcessName",
         "AuthenticationPackageName", "WorkstationName", "TransmittedServices",
         "LmPackageName", "KeyLength", "ProcessId", "ProcessName", "IpAddress",
         "IpPort"),
        12544,
        "An account failed to log on",
    ),
    4648: _security(
        4648,
        ("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
         "LogonGuid", "TargetUserName", "TargetDomainName", "TargetLogonGuid",
         "TargetServerName", "TargetInfo", "ProcessId", "ProcessName",
         "IpAddress", "IpPort"),
        12544,
        "A logon was attempted using explicit credentials",
    ),
    4672: _security(
        4672,
        ("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
         "PrivilegeList"),
        12548,
        "Special privileges assigned to new logon",
    ),
    4688: _security(
        4688,
        ("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
         "NewProcessId", "NewProcessName", "TokenElevationType", "ProcessId",
         "CommandLine", "TargetUserSid", "TargetUserName", "TargetDomainName",
         "TargetLogonId", "ParentProcessName", "MandatoryLabel"),
        13312,
        "A new process has been created",
    ),
    4689: _security(
        4689,
        ("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
         "Status", "ProcessId", "ProcessName"),
        13313,
        "A process has exited",
    ),
    4768: _security(
        4768,
        ("TargetUserName", "TargetDomainName", "TargetSid", "ServiceName",
         "ServiceSid", "TicketOptions", "Status", "TicketEncryptionType",
         "PreAuthType", "IpAddress", "IpPort", "CertIssuerName",
         "CertSerialNumber", "CertThumbprint"),
        14339,
        "A Kerberos authentication ticket (TGT) was requested",
    ),
    4769: _security(
        4769,
        ("TargetUserName", "TargetDomainName", "ServiceName", "ServiceSid",
         "TicketOptions", "TicketEncryptionType", "IpAddress", "IpPort",
         "Status", "LogonGuid", "TransmittedServices"),
        14337,
        "A Kerberos service ticket (TGS) was requested -- Kerberoasting",
    ),
    4776: _security(
        4776,
        ("PackageName", "TargetUserName", "Workstation", "Status"),
        14336,
        "The computer attempted to validate the credentials for an account",
    ),
}


# Sigma logsource category -> candidate Event IDs, most specific first.
#
# Every entry must be the event that ACTUALLY carries the category, never the
# nearest event we happen to template. A substitution is the one generation bug
# the oracle cannot catch: it evaluates the rule's field selectors against the
# fields we wrote, and neighbouring Sysmon events share field names. A
# `file_delete` rule testing only `TargetFilename` is satisfied just as happily
# by a FileCreate event, so the oracle returns MATCH, the run ingests a
# creation event, the SIEM correctly ignores it, and the report claims a
# coverage gap that does not exist. Leaving a category unmapped is strictly
# better -- `resolve_event_ids` returning () is reported as "cannot generate".
CATEGORY_EVENTS: dict[str, tuple[int, ...]] = {
    "process_access": (10,),
    "process_creation": (1, 4688),
    "image_load": (7,),
    "file_event": (11,),
    "file_change": (2,),
    "file_delete": (23, 26),
    "registry_set": (13,),
    "registry_add": (12,),
    "registry_delete": (12,),
    "registry_rename": (14,),
    # Sigma's catch-all registry category spans all three events. 13 is the
    # common case; a pinned EventType picks the right one -- see
    # `registry_event_for_type`.
    "registry_event": (13, 12, 14),
    "network_connection": (3,),
    "dns_query": (22,),
    "create_remote_thread": (8,),
    "process_tampering": (25,),
    # PowerShell. ps_script keys on ScriptBlockText (178 rules), ps_module on
    # Payload/ContextInfo (34). Both live on the operational channel and use
    # named EventData fields, so the standard emitter handles them.
    #
    # ps_classic_start / ps_classic_provider_start (12 rules) are deliberately
    # absent: the classic "Windows PowerShell" channel emits unnamed <Data>
    # elements, which winevt._render cannot produce. Mapping them here would
    # emit a 4104 in their place -- the substitution this table exists to
    # prevent.
    "ps_script": (4104,),
    "ps_module": (4103,),
}

# Sysmon splits registry activity across three events that are otherwise
# near-identical, and the EventType value is the ONLY thing separating them:
# 12 covers key/value create and delete, 13 is always SetValue, 14 is renames.
# A 13 carrying "CreateKey" cannot occur on a real host -- but it satisfies a
# rule's `EventType: CreateKey` selector, so the oracle passes it.
REGISTRY_EVENT_TYPES: dict[str, int] = {
    "createkey": 12,
    "deletekey": 12,
    "createvalue": 12,
    "deletevalue": 12,
    "setvalue": 13,
    "renamekey": 14,
    "renamevalue": 14,
}

# Sigma logsource service (product: windows) -> candidate Event IDs.
#
# No "system" entry: `service: system` covers the System channel (Service
# Control Manager events like 7045/7036/7040), none of which this project
# templates. It used to point at 4688 -- Security-channel process creation,
# a different channel entirely, and exactly the substitution the comment
# above CATEGORY_EVENTS warns against. Every service:system rule in the
# corpus pins an explicit EventID anyway, so resolve_event_ids' explicit
# branch already returns () for all of them today -- but a future rule
# relying on service:system alone, with no explicit EventID, would have
# silently generated a process-creation event for a service-install rule.
SERVICE_EVENTS: dict[str, tuple[int, ...]] = {
    "security": (4688, 4624, 4672),
}

# The channel a Sigma `service` value implies -- used only to validate an
# EXPLICIT EventID a rule pinned (see resolve_event_ids), not to pick a
# default. SERVICE_EVENTS' tuples are representative defaults, not exhaustive
# lists of every event on that channel, so membership there is the wrong test
# for "is this explicit id even on the right channel."
SERVICE_CHANNELS: dict[str, str] = {
    "security": SECURITY_CHANNEL,
}

# Sigma field aliases for Security-channel events. Sysmon needs none -- Sigma
# uses the Sysmon names verbatim.
FIELD_ALIASES: dict[str, str] = {
    "Image": "NewProcessName",
    "ParentImage": "ParentProcessName",
    "User": "SubjectUserName",
    "ProcessCommandLine": "CommandLine",
    "LogonId": "SubjectLogonId",
}


def _channels_for_category(category: str) -> set[str]:
    """The channel(s) a mapped category's candidate events actually live on.

    Some categories span more than one channel on purpose -- process_creation
    is (1, 4688), Sysmon and Security both -- so this is a set, not a single
    value.
    """
    return {
        TEMPLATES[eid].channel
        for eid in CATEGORY_EVENTS.get(category.lower(), ())
        if eid in TEMPLATES
    }


def resolve_event_ids(category: str, service: str = "", explicit: int = 0) -> tuple[int, ...]:
    """Candidate Event IDs for a Sigma logsource. Empty when unmappable.

    An explicit id the rule pinned is authoritative and never falls back: a rule
    selecting on `EventID: 4728` wants a 4728 event, and quietly emitting a 4688
    instead would produce telemetry that cannot trip the rule -- reported later
    as a coverage gap that is really a generation bug.
    """
    if explicit:
        template = TEMPLATES.get(explicit)
        if template is None:
            return ()
        # Event IDs are only unique within a channel -- "EventID: 1" means
        # Sysmon process-creation on the Sysmon channel and something else
        # entirely on Application, BITS-Client, or Security-Mitigations. When
        # the logsource names a category or service we map, the explicit id's
        # own channel must be one that category/service implies: "service:
        # security, EventID: 4104" is internally contradictory (4104 is
        # PowerShell, not Security).
        #
        # When category/service names something we do NOT map, trust nothing:
        # Sigma has dozens of `service` channels (bits-client,
        # security-mitigations, printservice, ...) this project only
        # templates three of (Sysmon, Security, PowerShell), and an
        # unrecognised service is far more likely to be one of those other
        # real, distinct channels than a synonym for one we do template.
        # "service: bits-client, EventID: 3" pins a BITS-Client event that has
        # nothing to do with Sysmon's own EventID 3 (network connection) --
        # trusting the number alone produces the exact cross-channel
        # substitution the module docstring above CATEGORY_EVENTS warns
        # about. Only a logsource with NEITHER a category NOR a service at
        # all has no channel signal to check, and falls back to trusting the
        # explicit id alone.
        if not category and not service:
            return (explicit,)
        category_known = bool(category) and category.lower() in CATEGORY_EVENTS
        service_known = bool(service) and service.lower() in SERVICE_CHANNELS
        channel_matches = (
            category_known and template.channel in _channels_for_category(category)
        ) or (
            service_known and template.channel == SERVICE_CHANNELS[service.lower()]
        )
        return (explicit,) if channel_matches else ()
    if category and category.lower() in CATEGORY_EVENTS:
        return CATEGORY_EVENTS[category.lower()]
    if service and service.lower() in SERVICE_EVENTS:
        return SERVICE_EVENTS[service.lower()]
    return ()


def resolve_field(event_id: int, sigma_field: str) -> str:
    """Map a Sigma field name to the event's EventData name.

    Aliases apply only to Security-channel events, and only when the alias
    target is actually a field of that event -- Sysmon uses Sigma's names
    directly, and rewriting them there would break every rule.
    """
    template = TEMPLATES.get(event_id)
    if template is None:
        return sigma_field
    if sigma_field in template.fields:
        return sigma_field
    if template.channel == SECURITY_CHANNEL:
        alias = FIELD_ALIASES.get(sigma_field)
        if alias and alias in template.fields:
            return alias
    return sigma_field


def registry_event_for_type(event_type: str) -> int:
    """Sysmon event that emits a given registry EventType. 0 when unrecognised.

    Used both to route (`registry_event` cannot say which of 12/13/14 a rule
    means, but its EventType can) and to refuse: an event carrying an EventType
    it never emits is impossible telemetry the oracle would still call a MATCH.
    """
    return REGISTRY_EVENT_TYPES.get(str(event_type).strip().lower(), 0)


def template_for(event_id: int) -> EventTemplate | None:
    return TEMPLATES.get(event_id)


def supported_events() -> list[dict]:
    """Summary of every supported event type, for the agent's tool output."""
    return [
        {
            "event_id": t.event_id,
            "channel": t.channel,
            "log_type": t.log_type,
            "description": t.description,
            "fields": list(t.fields),
        }
        for t in sorted(TEMPLATES.values(), key=lambda t: (t.channel, t.event_id))
    ]
