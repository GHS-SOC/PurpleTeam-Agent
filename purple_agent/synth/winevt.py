"""Emit Windows Event XML.

The model decides *what* the attack looks like; this module decides *how* the
XML is written. That split is deliberate: malformed or schema-wrong XML is
dropped silently by Chronicle parsers, and you do not find out until an ingest
and detection cycle has already burned. Keeping the envelope here means the
model cannot get it wrong.

Owned here: the schema namespace, Provider name and GUID, Channel, EventID,
Version, Level, Task, Opcode, Keywords, TimeCreated, EventRecordID, Execution
PID/TID, Computer, Security UserID, and the ordered `<Data Name="...">` list.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any
from xml.sax.saxutils import escape, quoteattr

from . import mapping
from .scenario import ScenarioContext, default_fields

SCHEMA = "http://schemas.microsoft.com/win/2004/08/events/event"

_record_counter = itertools.count(80001)

# Fields Chronicle coerces to an integer. Filling these with the usual "-"
# placeholder makes the parser abort the whole event:
#
#   filter mutate failed: convert failure: field "SourcePort":
#   strconv.Atoi: parsing "-": invalid syntax
#
# The event is then dropped silently -- ingestion still returns success, and the
# only symptom is that nothing ever appears in UDM. So unset numeric fields get
# "0", never "-".
_NUMERIC_FIELDS = frozenset({
    "ProcessId", "ParentProcessId", "SourceProcessId", "TargetProcessId",
    "SourceThreadId", "NewThreadId", "TerminalSessionId",
    "SourcePort", "DestinationPort", "IpPort", "KeyLength", "LogonType",
    "EventType",
    # PowerShell 4104 chunking counters -- a script block too large for one
    # event is split across N of them.
    "MessageNumber", "MessageTotal",
})

# Same failure mode, different type: Chronicle validates hash length, so a
# malformed placeholder aborts the event.
#   field backstory.File.sha256 "..." too long for type HASH (66 bytes, max 64)
_SHA256_PLACEHOLDER = (
    "5E3F1B4A2C9D8E7F6A5B4C3D2E1F0A9B8C7D6E5F4A3B2C1D0E9F8A7B6C5D4E3F"
)
_MD5_PLACEHOLDER = "9F2A4C7E1B8D5A3F6C0E9B4D7A2F5C81"
_SHA1_PLACEHOLDER = "3B7F2A9C5E1D8B4A6F0C3E7D9A2B5F8C1D4E6A0B"


def _empty_value(name: str, template: "mapping.EventTemplate") -> str:
    """Placeholder for a field the caller did not set.

    Typed fields cannot take the generic "-" -- see _NUMERIC_FIELDS.
    """
    if name in _NUMERIC_FIELDS:
        return "0"
    return "-"


@dataclass
class GeneratedEvent:
    """One synthesised event, in both XML and field form."""

    event_id: int
    channel: str
    log_type: str
    xml: str
    # Flat field view, so the Sigma oracle can evaluate the event without
    # re-parsing the XML it just produced.
    fields: dict[str, str] = field(default_factory=dict)
    offset_seconds: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "channel": self.channel,
            "log_type": self.log_type,
            "offset_seconds": self.offset_seconds,
            "fields": self.fields,
        }


def build_event(
    event_id: int,
    context: ScenarioContext,
    overrides: dict[str, Any] | None = None,
    offset_seconds: int = 0,
) -> GeneratedEvent:
    """Build one event, filling unpinned fields from the scenario.

    Raises ValueError for an unsupported event id -- a silently-skipped event
    would show up later as a missing detection with no explanation.
    """
    template = mapping.template_for(event_id)
    if template is None:
        raise ValueError(
            f"event id {event_id} is not supported. "
            f"Supported: {sorted(mapping.TEMPLATES)}"
        )

    values = default_fields(context, event_id)
    values.update(_process_defaults(template, context))

    for key, value in (overrides or {}).items():
        resolved = mapping.resolve_field(event_id, key)
        values[resolved] = "" if value is None else str(value)

    # Sysmon 12, 13 and 14 differ only by EventType -- 13 emits SetValue and
    # nothing else, 14 only renames. An event carrying an EventType it never
    # emits is telemetry no real host can produce, and the oracle cannot catch
    # it: it compares the string it was handed against the string the rule
    # asked for, returns MATCH, and the resulting miss reads as a coverage gap.
    # The plan is model-editable, so this is checked at build time, not plan
    # time.
    if "EventType" in template.fields:
        owner = mapping.registry_event_for_type(values.get("EventType", ""))
        if owner and owner != event_id:
            raise ValueError(
                f"EventType {values['EventType']!r} is only emitted by Sysmon "
                f"event {owner}, not {event_id}. Build event {owner} instead."
            )

    when = context.timestamp(offset_seconds)
    # Keep UtcTime consistent with the header when an offset shifts the event.
    if "UtcTime" in template.fields and not (overrides or {}).get("UtcTime"):
        values["UtcTime"] = when.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    ordered = {
        name: values.get(name, _empty_value(name, template)) for name in template.fields
    }

    # Header values live in <System>, not <EventData>, but Sigma rules routinely
    # select on them (`EventID: 4624`, `Channel: Security`). Expose them in the
    # flat view so the oracle can evaluate those rules, while keeping them out
    # of the EventData block where they do not belong.
    flat = {
        **ordered,
        "EventID": str(template.event_id),
        "Channel": template.channel,
        "Provider_Name": template.provider_name,
        "Computer": context.fqdn,
    }

    return GeneratedEvent(
        event_id=event_id,
        channel=template.channel,
        log_type=template.log_type,
        xml=_render(template, context, ordered, when),
        fields=flat,
        offset_seconds=offset_seconds,
    )


def _process_defaults(
    template: mapping.EventTemplate, context: ScenarioContext
) -> dict[str, str]:
    """Allocate a coherent process lineage for events that carry one."""
    parent_pid = context.new_pid()
    child_pid = context.new_pid()
    # Sysmon 8/10's "target" is a different process from both -- CreateRemoteThread
    # and ProcessAccess act ON a target, they don't spawn it as a child. Allocated
    # once, up front, so TargetProcessId and TargetProcessGuid/TargetProcessGUID
    # agree: new_guid() encodes its argument into the GUID's own tag segment, and
    # SourceProcessGuid/TargetProcessGuid pairing that with the WRONG pid produced
    # a guid whose tag never matched the pid sitting right next to it in the same
    # event -- a lineage no real host emits, and a marker for something being
    # synthetic more distinctive than the intended one.
    target_pid = context.new_pid()
    values: dict[str, str] = {}

    for name in template.fields:
        if name in ("ProcessId", "NewProcessId", "SourceProcessId"):
            values[name] = str(child_pid)
        elif name in ("ParentProcessId",):
            values[name] = str(parent_pid)
        elif name == "TargetProcessId":
            values[name] = str(target_pid)
        elif name in ("ProcessGuid", "SourceProcessGuid", "SourceProcessGUID"):
            values[name] = context.new_guid(child_pid)
        elif name in ("TargetProcessGuid", "TargetProcessGUID"):
            values[name] = context.new_guid(target_pid)
        elif name == "ParentProcessGuid":
            values[name] = context.new_guid(parent_pid)
        elif name == "SourceThreadId":
            values[name] = str(child_pid + 1068)
        elif name == "NewThreadId":
            values[name] = str(child_pid + 2044)
        elif name in ("Image", "NewProcessName", "SourceImage"):
            values[name] = "C:\\Windows\\System32\\cmd.exe"
        elif name in ("ParentImage", "ParentProcessName"):
            values[name] = "C:\\Windows\\explorer.exe"
        elif name == "TargetImage":
            values[name] = "C:\\Windows\\system32\\lsass.exe"
        elif name == "CommandLine":
            values[name] = "C:\\Windows\\System32\\cmd.exe"
        elif name == "ParentCommandLine":
            values[name] = "C:\\Windows\\explorer.exe"
        elif name == "Hashes":
            values[name] = (
                f"MD5={_MD5_PLACEHOLDER},SHA256={_SHA256_PLACEHOLDER}"
            )
    return values


def _render(
    template: mapping.EventTemplate,
    context: ScenarioContext,
    fields: dict[str, str],
    when,
) -> str:
    """Serialise to Windows Event XML."""
    # Windows renders 100ns precision; parsers are tolerant but real logs look
    # like this and cheap realism costs nothing.
    system_time = when.strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"

    data = "".join(
        f"<Data Name={quoteattr(name)}>{escape(str(value))}</Data>"
        for name, value in fields.items()
    )

    return (
        f'<Event xmlns="{SCHEMA}">'
        "<System>"
        f'<Provider Name={quoteattr(template.provider_name)} '
        f'Guid={quoteattr(template.provider_guid)}/>'
        f"<EventID>{template.event_id}</EventID>"
        "<Version>5</Version>"
        f"<Level>{template.level}</Level>"
        f"<Task>{template.task}</Task>"
        f"<Opcode>{template.opcode}</Opcode>"
        f"<Keywords>{template.keywords}</Keywords>"
        f'<TimeCreated SystemTime="{system_time}"/>'
        f"<EventRecordID>{next(_record_counter)}</EventRecordID>"
        "<Correlation/>"
        f'<Execution ProcessID="{context.new_pid()}" ThreadID="{context.new_pid()}"/>'
        f"<Channel>{escape(template.channel)}</Channel>"
        f"<Computer>{escape(context.fqdn)}</Computer>"
        '<Security UserID="S-1-5-18"/>'
        "</System>"
        f"<EventData>{data}</EventData>"
        "</Event>"
    )


def group_by_log_type(events: list[GeneratedEvent]) -> dict[str, list[str]]:
    """Group raw XML by Chronicle log type.

    Sysmon and Security-channel events parse under different log types, so they
    need separate `import_logs` calls. Sending one as the other silently yields
    no parsed events.
    """
    grouped: dict[str, list[str]] = {}
    for event in events:
        grouped.setdefault(event.log_type, []).append(event.xml)
    return grouped
