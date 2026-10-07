from __future__ import annotations

import hashlib
import json
import logging
import re
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .artifacts import conversion_scope, existing_artifact_path, report_directory, portable_artifact, write_json_artifact
from jsonschema import Draft202012Validator

from . import __version__
from .catalog import (
    NATIVE_XDR_TABLES,
    query_column_renames,
    query_has_mixed_time_semantics,
)
from .columns import projected_columns
from .content_paths import content_path, yaml_files
from .parser_bindings import normalize_parser_bindings
from .report import write_transformation_report

SCHEMA_VERSION = "1.0.0"
XDR_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema" / "xdr-detection.schema.json"
INITIAL_XDR_VERSION = "3.1.0"
XDR_VERSION_PATTERN = r"3\.[1-9][0-9]*\.(?:0|[1-9][0-9]*)"
SOURCE_ID_PATTERN = r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
DETECTION_API_VERSION = "2026-06-01-preview"
ENTITY_CONFIRMATION_PREFIX = "Entity confirmation required:"
REQUIRED_ASSET_COLLECTIONS = frozenset({"hosts", "accounts", "mailboxes", "ips"})
SUPPORTED_SEVERITIES = frozenset({"informational", "low", "medium", "high"})
SEARCH_REVIEW_REASON = "search queries should be replaced with explicit tables"
BLOCKING_KQL_PATTERNS = {
    r"\bworkspace\s*\(": "cross-workspace queries require manual redesign",
}
REVIEW_KQL_PATTERNS = {
    r"\bexternaldata\s*\(": "externaldata availability must be verified by runtime validation",
    r"\bunion\s+isfuzzy\s*=\s*true\b": "isfuzzy unions can still fail semantic binding in Advanced Hunting",
    r"\b_[Ii]m_[A-Za-z0-9_]+\s*\(": "ASIM parser availability must be verified in Advanced Hunting",
}

ENTITY_MAP: dict[str, tuple[str, dict[str, str | None]]] = {
    "Host": (
        "hosts",
        {
            "HostName": "nameColumn",
            "NetBiosName": "netBiosNameColumn",
            "NTDomain": "ntDomainColumn",
            "DnsDomain": "dnsDomainColumn",
            "DeviceId": "deviceIdColumn",
        },
    ),
    "Account": (
        "accounts",
        {
            "Name": "nameColumn",
            "NTDomain": "ntDomainColumn",
            "DnsDomain": "dnsDomainColumn",
            "UPNSuffix": "upnSuffixColumn",
            "Upn": "upnColumn",
            "Sid": "sidColumn",
            "AadUserId": "aadUserIdColumn",
        },
    ),
    "IP": ("ips", {"Address": "addressColumn"}),
    "URL": ("urls", {"Url": "addressColumn"}),
    "AzureResource": ("azureResources", {"ResourceId": "resourceIdColumn"}),
    "CloudApplication": ("cloudApplications", {"AppId": "appIdColumn", "Name": "nameColumn"}),
    "Mailbox": ("mailboxes", {"MailboxPrimaryAddress": "primaryAddressColumn"}),
    "DNS": ("dns", {"DomainName": "domainNameColumn"}),
    "File": ("files", {"Name": "nameColumn"}),
    "FileHash": ("files", {}),
    "MailCluster": ("mailClusters", {"Query": "queryColumn", "Source": "sourceColumn"}),
    "RegistryValue": ("registryValues", {"Name": "valueNameColumn"}),
    "SecurityGroup": (
        "securityGroups",
        {
            "DistinguishedName": "distinguishedNameColumn",
            "SID": "sidColumn",
            "ObjectGuid": "objectIdColumn",
        },
    ),
    # Sentinel process identifiers are not the hashes accepted by Graph.
    "Process": ("processes", {}),
    "MailMessage": (
        "mailMessages",
        {
            "NetworkMessageId": "networkMessageIdColumn",
            "Recipient": "recipientColumn",
            "Sender": "senderColumn",
            "P1Sender": "senderColumn",
            "P2Sender": "senderColumn",
            "Subject": "subjectColumn",
        },
    ),
}

ACCOUNT_IDENTITIES = (
    frozenset({"upnColumn"}),
    frozenset({"aadUserIdColumn"}),
    frozenset({"sidColumn"}),
    frozenset({"nameColumn", "upnSuffixColumn"}),
    frozenset({"nameColumn", "ntDomainColumn"}),
    frozenset({"nameColumn", "dnsDomainColumn"}),
)
ACCOUNT_UPN_ALIASES = frozenset(
    {
        "accountupn",
        "caller",
        "initiatingprocessaccountupn",
        "targetuserupn",
        "userprincipalname",
    }
)
INFERRED_ENTITY_ALIASES: dict[str, tuple[str, ...]] = {
    "accountUpn": (
        "AccountUpn",
        "AccountUPN",
        "UserPrincipalName",
        "InitiatingProcessAccountUpn",
        "TargetUserUpn",
    ),
    "accountId": ("AadUserId", "AccountObjectId", "UserObjectId", "EntraUserId"),
    "accountSid": ("AccountSid", "UserSid"),
    "deviceId": ("DeviceId",),
    "hostName": ("DeviceName", "HostName", "DvcHostname", "Computer"),
    "ip": (
        "CallerIpAddress",
        "DestinationIP",
        "IPAddress",
        "IpAddress",
        "LocalIP",
        "RemoteIP",
        "SourceIP",
    ),
    "url": ("RemoteUrl", "URL", "Url"),
    "resource": ("_ResourceId", "AzureResourceId", "ResourceId"),
}


class XdrYamlDumper(yaml.SafeDumper):
    pass


def _represent_string(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


XdrYamlDumper.add_representer(str, _represent_string)


@dataclass(frozen=True)
class ConversionResult:
    source: Path
    output: Path
    display_name: str
    status: str
    review_required: bool
    review_reasons: tuple[str, ...]
    warnings: tuple[str, ...]
    errors: tuple[str, ...]
    informational: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": str(self.source),
            "output": str(self.output),
            "displayName": self.display_name,
            "status": self.status,
            "reviewRequired": self.review_required,
            "reviewReasons": list(self.review_reasons),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "informational": list(self.informational),
        }


def configure_logging(solution: str | Path | None = None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if solution:
        log_directory = report_directory(solution, create=True)
        class PublicFormatter(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                return portable_artifact(solution, super().format(record), destination=log_directory)

        handler = logging.FileHandler(
            log_directory / "sentinel-xdr-migration.log", encoding="utf-8"
        )
        handler.setFormatter(PublicFormatter("%(asctime)s %(levelname)s %(message)s"))
        handlers.append(handler)
    logger = logging.getLogger()
    for previous in list(logger.handlers):
        if getattr(previous, "_sentinel_xdr_handler", False):
            logger.removeHandler(previous)
            previous.close()
    logger.setLevel(logging.INFO)
    for handler in handlers:
        handler._sentinel_xdr_handler = True
        if handler.formatter is None:
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:72] or "custom-detection"


def iso_duration(value: Any, default: str = "PT1H") -> tuple[str, str | None]:
    text = str(value or "").strip().lower()
    iso = text.upper()
    if re.fullmatch(
        r"P(?:(?:\d+D)(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?|T(?:\d+H)?(?:\d+M)?(?:\d+S)?)",
        iso,
    ):
        return iso, None
    match = re.fullmatch(r"(\d+)\s*([smhd])", text)
    if not match:
        return default, f"unrecognized queryFrequency {value!r}; defaulted to {default}"
    amount, unit = match.groups()
    return {
        "s": f"PT{amount}S",
        "m": f"PT{amount}M",
        "h": f"PT{amount}H",
        "d": f"P{amount}D",
    }[unit], None


def solution_paths(solution: str | Path) -> tuple[Path, Path, Path]:
    root = Path(solution).expanduser().resolve()
    analytic = root / "Analytic Rules"
    output = root / "XDR Detections"
    if not root.is_dir():
        raise ValueError(f"solution path does not exist: {root}")
    if not analytic.is_dir():
        legacy_analytic = root / "Analytics Rules"
        if legacy_analytic.is_dir():
            analytic = legacy_analytic
        else:
            raise ValueError(
                f"solution has no 'Analytic Rules' or 'Analytics Rules' folder: {root}"
            )
    return root, analytic, output


def load_config(output_dir: Path, explicit: str | Path | None = None) -> dict[str, Any]:
    path = (
        Path(explicit).expanduser().resolve()
        if explicit
        else existing_artifact_path(output_dir.parent, "migration-config.yaml")
    )
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as handle:
        value = yaml.safe_load(handle) or {}
    if not isinstance(value, dict):
        raise ValueError(f"migration config must contain a YAML object: {path}")
    return value


def analytic_rule_files(solution: str | Path) -> list[Path]:
    _, analytic, _ = solution_paths(solution)
    return yaml_files(analytic)


def xdr_detection_files(output: Path) -> list[Path]:
    return list(
        path
        for path in yaml_files(output)
        if path.name.lower() not in {"migration-config.yaml", "migration-config.yml"}
    )


def inspect_solution(solution: str | Path) -> dict[str, Any]:
    root, analytic, output = solution_paths(solution)
    files = analytic_rule_files(root)
    return {
        "solution": str(root),
        "analyticRulesDirectory": str(analytic),
        "xdrDetectionsDirectory": str(output),
        "analyticRuleCount": len(files),
        "analyticRules": [path.relative_to(analytic).as_posix() for path in files],
        "existingXdrDetectionCount": len(xdr_detection_files(output)) if output.exists() else 0,
    }


def _replace_code_segment(segment: str, pattern: re.Pattern[str], mappings: dict[str, str]) -> str:
    pieces = re.split(r"""('(?:''|[^'])*'|"(?:\\"|[^"])*")""", segment)
    for index in range(0, len(pieces), 2):
        pieces[index] = pattern.sub(lambda match: mappings[match.group(0)], pieces[index])
    return "".join(pieces)


def _token_replace(query: str, mappings: dict[str, str]) -> str:
    if not mappings:
        return query
    pattern = re.compile(
        r"\b(?:" + "|".join(re.escape(source) for source in sorted(mappings, key=len, reverse=True)) + r")\b"
    )
    output = []
    for line in query.splitlines(keepends=True):
        code, separator, comment = line.partition("//")
        output.append(_replace_code_segment(code, pattern, mappings))
        if separator:
            output.append(separator + comment)
    return "".join(output)


def _configured_column_mappings(config: dict[str, Any]) -> dict[str, str]:
    mappings: dict[str, str] = {}
    configured = config.get("columnMappings") or {}
    if configured and all(isinstance(value, str) for value in configured.values()):
        mappings.update({str(key): str(value) for key, value in configured.items()})
    else:
        for value in configured.values():
            if isinstance(value, dict):
                mappings.update({str(key): str(target) for key, target in value.items()})
    return mappings


def convert_query(query: str, config: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    warnings: list[str] = []
    errors: list[str] = []
    converted = query.strip()

    source_mappings: dict[str, str] = {}
    source_mappings.update(
        {str(k): str(v) for k, v in (config.get("functionMappings") or {}).items()}
    )
    source_mappings.update(
        {str(k): str(v) for k, v in (config.get("tableMappings") or {}).items()}
    )
    converted = _token_replace(converted, source_mappings)

    column_mappings: dict[str, str] = query_column_renames(converted)
    column_mappings.update(_configured_column_mappings(config))
    converted = _token_replace(converted, column_mappings)
    converted = "\n".join(line.rstrip() for line in converted.splitlines())
    converted = re.sub(r";\s*\Z", "", converted)

    for pattern, message in BLOCKING_KQL_PATTERNS.items():
        if re.search(pattern, converted, re.IGNORECASE):
            errors.append(message)
    for pattern, message in REVIEW_KQL_PATTERNS.items():
        if re.search(pattern, converted, re.IGNORECASE):
            warnings.append(message)
    if _has_search_operator(converted):
        warnings.append(SEARCH_REVIEW_REASON)
    if query_has_mixed_time_semantics(converted):
        warnings.append(
            "query mixes native Defender and Sentinel workload tables; "
            "time columns were preserved and require runtime validation"
        )

    return converted, warnings, errors


def _valid_account(fields: dict[str, str]) -> bool:
    present = set(fields)
    return any(required <= present for required in ACCOUNT_IDENTITIES)


def _find_column(columns: set[str] | None, aliases: tuple[str, ...]) -> str | None:
    if columns is None:
        return None
    lookup = {column.lower(): column for column in columns}
    return next((lookup[alias.lower()] for alias in aliases if alias.lower() in lookup), None)


def _repair_account(
    fields: dict[str, str],
    source_fields: dict[str, str],
    columns: set[str] | None,
    warnings: list[str],
) -> dict[str, str]:
    if _valid_account(fields):
        return fields
    name_column = fields.get("nameColumn") or source_fields.get("Name")
    if name_column and name_column.lower() in ACCOUNT_UPN_ALIASES:
        warnings.append(
            f"Account.Name column `{name_column}` was mapped as a complete UPN identity"
        )
        return {"upnColumn": name_column}
    if "nameColumn" in fields:
        for target, aliases in (
            ("upnSuffixColumn", ("UPNSuffix", "AccountUPNSuffix", "UserDomain")),
            ("ntDomainColumn", ("NTDomain", "AccountNTDomain")),
            ("dnsDomainColumn", ("DnsDomain", "AccountDnsDomain")),
        ):
            column = _find_column(columns, aliases)
            if column:
                warnings.append(
                    f"Account mapping was completed with projected column `{column}`"
                )
                return {**fields, target: column}
    for target, aliases in (
        ("upnColumn", INFERRED_ENTITY_ALIASES["accountUpn"]),
        ("aadUserIdColumn", INFERRED_ENTITY_ALIASES["accountId"]),
        ("sidColumn", INFERRED_ENTITY_ALIASES["accountSid"]),
    ):
        column = _find_column(columns, aliases)
        if column:
            warnings.append(
                f"Account mapping was repaired from projected column `{column}`"
            )
            return {target: column}
    if name_column and (columns is None or name_column in columns):
        warnings.append(
            f"{ENTITY_CONFIRMATION_PREFIX} `{name_column}` was provisionally mapped "
            "to Account.upnColumn. Confirm that the source always emits a complete "
            "UPN; otherwise project an Entra user ID, SID, or account name plus domain"
        )
        return {"upnColumn": name_column}
    warnings.append("Account mapping is incomplete and was removed")
    return {}


def _infer_entities(
    columns: set[str] | None,
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    if columns is None:
        return {}, []
    output: dict[str, list[dict[str, Any]]] = {}
    for collection, identifier, field, aliases in (
        ("accounts", "account1", "upnColumn", INFERRED_ENTITY_ALIASES["accountUpn"]),
        ("hosts", "host1", "deviceIdColumn", INFERRED_ENTITY_ALIASES["deviceId"]),
        ("ips", "ip1", "addressColumn", INFERRED_ENTITY_ALIASES["ip"]),
        ("urls", "url1", "addressColumn", INFERRED_ENTITY_ALIASES["url"]),
        (
            "azureResources",
            "azureResource1",
            "resourceIdColumn",
            INFERRED_ENTITY_ALIASES["resource"],
        ),
    ):
        column = _find_column(columns, aliases)
        if column:
            output[collection] = [{"id": identifier, field: column}]
    host_name = _find_column(columns, INFERRED_ENTITY_ALIASES["hostName"])
    if host_name:
        host = output.setdefault("hosts", [{"id": "host1"}])[0]
        host["nameColumn"] = host_name
    warnings = (
        ["No valid source mapping survived; inferred entities from projected columns"]
        if output
        else []
    )
    return output, warnings


def _tokens(query: str) -> list[str]:
    """Tokenize only for conservative local proofs, never to rewrite KQL."""
    tokens = re.findall(
        r"//[^\n]*|/\*[\s\S]*?\*/|```[\s\S]*?```"
        r"|@'(?:''|[^'])*'|@\"(?:\"\"|[^\"])*\""
        r"|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\""
        r"|[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?[smhd]?|>=|<=|==|!=|[^\s]",
        query,
    )
    return [
        "'" + token[1:-1] + "'" if token.startswith('"') else token
        for token in tokens
        if not token.startswith(("//", "/*"))
    ]


def _has_search_operator(query: str) -> bool:
    """Recognize search at query boundaries, not in comments or literal text."""
    tokens = _tokens(query)
    for index, token in enumerate(tokens):
        if token.lower() != "search":
            continue
        if index and tokens[index - 1] not in {"|", ";", "(", "{", "="}:
            continue
        # A bare table/column named search is not an operator with a predicate.
        if index + 1 >= len(tokens):
            continue
        operand = tokens[index + 1]
        if re.fullmatch(
            r"and|or|between|matches|has(?:_cs|_any|_all|prefix(?:_cs)?|suffix(?:_cs)?)?"
            r"|(?:contains|startswith|endswith)(?:_cs)?",
            operand,
            re.IGNORECASE,
        ):
            continue
        if re.match(r"[\w'\"@`(*\[]", operand):
            return True
    return False


def _pipeline_parts(query: str) -> list[list[str]] | None:
    """Split a single-table pipeline, rejecting branches and local definitions."""
    tokens = _tokens(query)
    parts: list[list[str]] = [[]]
    depth = 0
    for token in tokens:
        if token == ";":
            return None
        if token == "|":
            if depth:
                return None
            parts.append([])
        else:
            parts[-1].append(token)
        if token in {"(", "[", "{"}:
            depth += 1
        elif token in {")", "]", "}"}:
            depth -= 1
        if depth < 0:
            return None
    if depth or len(parts[0]) != 1 or not re.fullmatch(r"\w+", parts[0][0]):
        return None
    return parts


def _expression_items(tokens: list[str]) -> list[list[str]]:
    items: list[list[str]] = [[]]
    depth = 0
    for token in tokens:
        if token == "," and not depth:
            items.append([])
            continue
        items[-1].append(token)
        if token in {"(", "[", "{"}:
            depth += 1
        elif token in {")", "]", "}"}:
            depth -= 1
    return items


def _summarize_groups(part: list[str]) -> list[list[str]] | None:
    depth = 0
    for index, token in enumerate(part):
        if token == "by" and not depth:
            return _expression_items(part[index + 1:])
        if token in {"(", "[", "{"}:
            depth += 1
        elif token in {")", "]", "}"}:
            depth -= 1
    return None


def _native_pipeline_table(query: str) -> str | None:
    """Recognize a native surface without claiming column or time equivalence."""
    parts = _pipeline_parts(query)
    if not parts or parts[0][0] not in NATIVE_XDR_TABLES:
        return None
    if any(not part or part[0] not in {"where", "extend", "project", "summarize"} for part in parts[1:]):
        return None
    return parts[0][0]


def _linear_facts(
    query: str, *, allow_aggregation: bool = False,
) -> tuple[list[list[str]], set[str] | None, dict[str, list[str]]] | None:
    """Prove local column facts; aggregation is opt-in for identity proofs only."""
    parts = _pipeline_parts(query)
    if not parts:
        return None
    columns: set[str] | None = None
    assignments: dict[str, list[str]] = {}
    for part in parts[1:]:
        if part and part[0] == "summarize" and allow_aggregation:
            groups = _summarize_groups(part)
            if not groups:
                return None
            preserved = {item[0] for item in groups if len(item) == 1}
            if columns is not None and not preserved <= columns:
                return None
            # Only bare grouping keys preserve identity. Aggregate outputs and
            # computed keys cannot establish an equivalent source identity.
            columns = preserved
            assignments = {key: value for key, value in assignments.items() if key in preserved}
            continue
        if not part or part[0] not in {"where", "extend", "project"}:
            return None
        if part[0] == "where":
            continue
        items = _expression_items(part[1:])
        projected: set[str] = set()
        for item in items:
            if not item or not re.fullmatch(r"[A-Za-z_]\w*", item[0]):
                return None
            if len(item) != 1 and (len(item) < 3 or item[1] != "="):
                return None
            if len(item) == 1 and columns is not None and item[0] not in columns:
                return None
            projected.add(item[0])
            if len(item) > 1:
                assignments[item[0]] = item[2:]
        if part[0] == "project":
            columns = projected
            assignments = {key: value for key, value in assignments.items() if key in columns}
        elif columns is not None:
            columns.update(projected)
    return parts, columns, assignments


def _host_full_name_preserved(
    source_fields: dict[str, str], fields: dict[str, str], query: str,
) -> bool:
    full = source_fields.get("FullName")
    name = fields.get("nameColumn")
    domain = fields.get("dnsDomainColumn")
    facts = _linear_facts(query, allow_aggregation=True)
    if not full or not name or not domain or not facts:
        return False
    parts, columns, assignments = facts
    if columns is not None and not {full, name, domain} <= columns:
        return False
    for part in parts[1:]:
        if part[0] == "summarize" and [full] not in (_summarize_groups(part) or []):
            return False
        if part[0] == "project" and [full] not in _expression_items(part[1:]):
            return False
    # Reject reassigned identities, including assignments later projected away.
    for column in (full, name, domain):
        count = sum(
            part[index:index + 2] == [column, "="]
            for part in parts[1:] for index in range(len(part) - 1)
        )
        if count != (0 if column == full else 1):
            return False
    expected_name = _tokens(
        f"iff({full} has '.', substring({full}, 0, indexof({full}, '.')), {full})"
    )
    expected_domain = _tokens(
        f"iff({full} has '.', substring({full}, indexof({full}, '.') + 1), '')"
    )
    return assignments.get(name) == expected_name and assignments.get(domain) == expected_domain


SCHEDULE_REFERENCE = "https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules#lookback"
NATIVE_LOOKBACK_SECONDS = {3600: 14400, 10800: 43200, 43200: 172800, 86400: 2592000}


def _duration_seconds(value: Any) -> int | None:
    duration, error = iso_duration(value)
    if error:
        return None
    match = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", duration)
    if not match or not any(match.groups()):
        return None
    seconds = sum(int(part or 0) * scale for part, scale in zip(match.groups(), (86400, 3600, 60, 1)))
    return seconds if seconds > 0 else None


def _event_window(query: str, time_column: str) -> tuple[int | None, str | None]:
    facts = _linear_facts(query)
    if not facts:
        return None, "query shape or time filters cannot be proven by the conservative assessor"
    parts, _, assignments = facts
    if time_column in assignments:
        return None, "event time is reassigned"
    windows: list[int] = []
    time_tokens = {"Timestamp", "TimeGenerated", "ago", "now", "datetime", "ingestion_time"}
    for part in parts[1:]:
        if part[0] == "where" and time_tokens.intersection(part):
            if not (
                len(part) == 7 and part[1] == time_column and part[2] in {">", ">="}
                and part[3:5] == ["ago", "("] and part[-1] == ")"
            ):
                return None, "time filter or ingestion-time basis is ambiguous"
            seconds = _duration_seconds(part[5])
            if seconds is None:
                return None, "time filter duration is unknown"
            windows.append(seconds)
        elif part[0] != "where" and {"ago", "now", "datetime", "ingestion_time"}.intersection(part):
            return None, "time expressions outside a simple event-time predicate require review"
    if not windows:
        return None, "no explicit event-time bound proves equivalence to Defender ingestion-time evaluation"
    return min(windows), None


def assess_schedule(
    doc: dict[str, Any], source_query: str, target_query: str, frequency: str,
) -> tuple[list[str], list[str]]:
    source_frequency = _duration_seconds(doc.get("queryFrequency"))
    source_period = _duration_seconds(doc.get("queryPeriod"))
    target_frequency = _duration_seconds(frequency)
    source_table = _native_pipeline_table(source_query)
    target_table = _native_pipeline_table(target_query)
    native = target_table is not None
    target_period = NATIVE_LOOKBACK_SECONDS.get(target_frequency) if native else None
    summary = (
        f"Schedule assessment: source frequency={doc.get('queryFrequency') or 'unknown'}, "
        f"lookback={doc.get('queryPeriod') or 'unknown'}; target frequency={frequency}, "
        f"native lookback={str(target_period) + 's' if target_period else 'unknown/unconfigured'}"
    )
    reason = None
    if str(doc.get("kind") or "").lower() == "nrt":
        reason = "source NRT timing is not preserved by the emitted scheduled frequency"
    elif source_frequency is None or source_period is None:
        reason = "source frequency or lookback is unknown"
    elif source_frequency != target_frequency:
        reason = "source and target frequencies differ"
    elif not native or source_table is None:
        reason = "mixed, Sentinel-only, or unknown query surface; no custom lookback is configured in the payload"
    elif source_table != target_table:
        reason = "source and target native tables differ; time-basis equivalence is unverified"
    elif target_period is None:
        reason = "target frequency has no documented native fixed lookback"
    elif source_period != target_period:
        reason = "source and native lookbacks differ; an event-time filter alone does not configure the target ingestion lookback"
    if reason:
        return [f"{summary}; {reason}. See {SCHEDULE_REFERENCE}"], []
    source_time = "TimeGenerated" if "TimeGenerated" in _tokens(source_query) else "Timestamp"
    source_bound, source_issue = _event_window(source_query, source_time)
    target_bound, target_issue = _event_window(target_query, "Timestamp")
    if source_issue or target_issue:
        reason = source_issue or target_issue
        if source_period != target_period:
            reason = f"source and native lookbacks differ; {reason}"
        return [f"{summary}; {reason}. See {SCHEDULE_REFERENCE}"], []
    source_effective = min(source_period, source_bound)
    target_effective = min(target_period, target_bound)
    summary += f"; effective event windows source={source_effective}s, target={target_effective}s"
    if source_effective != target_effective:
        return [f"{summary}; effective lookbacks differ. See {SCHEDULE_REFERENCE}"], []
    return [], [
        f"{summary}; frequency and explicit event-time window are preserved. "
        f"Ingestion delays, initial runs and alert deduplication still require runtime qualification. See {SCHEDULE_REFERENCE}"
    ]


def convert_entities(
    doc: dict[str, Any],
    query: str,
    column_mappings: dict[str, str] | None = None,
    *,
    informational: list[str] | None = None,
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    output: dict[str, list[dict[str, Any]]] = {}
    warnings: list[str] = []
    counters: dict[str, int] = {}
    columns = projected_columns(query)
    facts = _linear_facts(query)
    if facts and facts[1] is not None:
        columns = facts[1]
    information = informational if informational is not None else []

    for entity in doc.get("entityMappings") or []:
        entity_type = str(entity.get("entityType") or "")
        if entity_type not in ENTITY_MAP:
            warnings.append(f"converter cannot map {entity_type or 'Unknown entity'} from the source identifiers")
            continue
        collection, identifiers = ENTITY_MAP[entity_type]
        fields: dict[str, str] = {}
        source_fields: dict[str, str] = {}
        unsupported: list[str] = []
        for mapping in entity.get("fieldMappings") or []:
            identifier = str(mapping.get("identifier") or "")
            source_column = str(mapping.get("columnName") or "")
            column = (column_mappings or {}).get(source_column, source_column)
            if identifier and column:
                source_fields[identifier] = column
            target = identifiers.get(identifier)
            if target and column and (columns is None or column in columns):
                if target in fields and fields[target] != column:
                    warnings.append(
                        f"converter cannot map {entity_type}.{identifier} column `{column}` "
                        f"without replacing conflicting {target} column `{fields[target]}`"
                    )
                else:
                    fields[target] = column
            elif target and column:
                warnings.append(
                    f"{entity_type}.{identifier} column `{column}` is not produced by the query"
                )
            elif identifier:
                unsupported.append(identifier)
        if entity_type == "FileHash":
            algorithm_column = source_fields.get("Algorithm", "")
            value_column = source_fields.get("Value", "")
            algorithm = facts[2].get(algorithm_column) if facts else None
            target = {"'SHA1'": "sha1Column", "'SHA256'": "sha256Column"}.get(
                algorithm[0].upper() if algorithm and len(algorithm) == 1 else ""
            )
            if target and value_column and columns is not None and value_column in columns:
                fields[target] = value_column
                unsupported = [value for value in unsupported if value not in {"Algorithm", "Value"}]
                information.append(
                    f"FileHash.Algorithm `{algorithm_column}` is the query-proven constant "
                    f"{algorithm[0]}; FileHash.Value `{value_column}` is represented by files.{target}"
                )
            else:
                warnings.append(
                    "converter cannot map FileHash.Algorithm/Value: requires a query-proven "
                    "constant SHA1 or SHA256 algorithm and an available hash value column; "
                    "MD5, unknown algorithms and linked file/process references are not inferred"
                )
                unsupported = [value for value in unsupported if value not in {"Algorithm", "Value"}]
        if entity_type == "Account" and not _valid_account(fields):
            fields = _repair_account(fields, source_fields, columns, warnings)
        for identifier in unsupported:
            if entity_type == "Host" and identifier == "FullName" and _host_full_name_preserved(source_fields, fields, query):
                information.append(
                    f"Host.FullName `{source_fields['FullName']}` is safely represented by retained "
                    f"nameColumn `{fields['nameColumn']}` and dnsDomainColumn `{fields['dnsDomainColumn']}`; "
                    "the query explicitly decomposes that same full name. No fullNameColumn is emitted"
                )
            elif entity_type == "Account" and identifier == "FullName" and source_fields.get(identifier) in (
                fields.get("upnColumn"), fields.get("nameColumn") if _valid_account(fields) else None,
            ):
                information.append(
                    f"Account.FullName `{source_fields[identifier]}` is retained by an equivalent account mapping"
                )
            else:
                warnings.append(
                    f"converter cannot map {entity_type}.{identifier} to a documented Custom Detection field; "
                    "this source identifier is not represented"
                )
        if fields:
            counters[collection] = counters.get(collection, 0) + 1
            identifier = collection[:-1] if collection.endswith("s") else collection
            output.setdefault(collection, []).append(
                {"id": f"{identifier}{counters[collection]}", **fields}
            )
    if not output:
        inferred, inference_warnings = _infer_entities(columns)
        output.update(inferred)
        warnings.extend(inference_warnings)
    return output, warnings


def _techniques(values: list[str] | None) -> list[dict[str, Any]]:
    grouped: dict[str, set[str]] = {}
    for raw in values or []:
        value = str(raw).strip()
        if not value:
            continue
        base = value.split(".", 1)[0]
        grouped.setdefault(base, set())
        if "." in value:
            grouped[base].add(value)
    result = []
    for base, subtechniques in grouped.items():
        item: dict[str, Any] = {"technique": base}
        if subtechniques:
            item["subTechniques"] = sorted(subtechniques)
        result.append(item)
    return result


def build_xdr_document(source: Path, solution_root: Path, config: dict[str, Any]) -> dict[str, Any]:
    with source.open(encoding="utf-8-sig") as handle:
        doc = yaml.safe_load(handle) or {}
    if not isinstance(doc, dict):
        raise ValueError(f"analytic rule must contain a YAML object: {source}")

    source_query = str(doc.get("query") or "")
    converted_query, query_warnings, errors = convert_query(source_query, config)
    if "requiredDataConnectors" in doc:
        with XDR_SCHEMA_PATH.open(encoding="utf-8") as handle:
            connector_schema = json.load(handle)["properties"]["requiredDataConnectors"]
        errors.extend(
            f"requiredDataConnectors{''.join(f'[{part!r}]' for part in error.path)}: {error.message}"
            for error in Draft202012Validator(connector_schema).iter_errors(doc["requiredDataConnectors"])
        )
    warnings = list(query_warnings)
    informational: list[str] = []
    review_reasons = list(query_warnings)
    try:
        converted_query, parser_warnings = normalize_parser_bindings(converted_query, solution_root)
        warnings.extend(parser_warnings)
    except ValueError as exc:
        errors.append(str(exc))
    is_nrt = str(doc.get("kind") or "").lower() == "nrt"
    frequency, frequency_warning = iso_duration(
        doc.get("queryFrequency") or ("PT1H" if is_nrt else None)
    )
    if frequency_warning:
        warnings.append(frequency_warning)
        review_reasons.append(frequency_warning)
    query_period = str(doc.get("queryPeriod") or "").strip()
    schedule_warnings, schedule_information = assess_schedule(
        doc, source_query, converted_query, frequency,
    )
    warnings.extend(schedule_warnings)
    informational.extend(schedule_information)
    source_id = str(doc.get("id") or "")
    rule_override = (config.get("ruleOverrides") or {}).get(source_id) or {}

    entity_information: list[str] = []
    mappings, mapping_warnings = convert_entities(
        doc,
        converted_query,
        _configured_column_mappings(config),
        informational=entity_information,
    )
    configured_entity_mappings = rule_override.get("entityMappings")
    if configured_entity_mappings is not None:
        if not isinstance(configured_entity_mappings, dict):
            errors.append(
                "configured ruleOverrides entityMappings must contain an object"
            )
        else:
            mappings = configured_entity_mappings
            mapping_warnings.append(
                "entity mappings were resolved by the configured per-rule override"
            )
    else:
        informational.extend(entity_information)
    entity_review_reasons = [
        warning
        for warning in mapping_warnings
        if warning.startswith(ENTITY_CONFIRMATION_PREFIX)
    ]
    if entity_review_reasons and REQUIRED_ASSET_COLLECTIONS.intersection(
        mappings
    ) - {"accounts"}:
        mappings.pop("accounts", None)
        mapping_warnings = [
            warning
            for warning in mapping_warnings
            if not warning.startswith(ENTITY_CONFIRMATION_PREFIX)
        ]
        mapping_warnings.append(
            "Unconfirmed generic Account.Name mapping was omitted because another "
            "required Host, Mailbox, or IP asset is available"
        )
        entity_review_reasons = []
    warnings.extend(mapping_warnings)
    review_reasons.extend(entity_review_reasons)

    source_tactics = [str(value) for value in doc.get("tactics") or [] if value]
    source_relevant = [
        str(value) for value in doc.get("relevantTechniques") or [] if value
    ]
    tactics = list(source_tactics)
    relevant = list(source_relevant)
    if len(tactics) > 1:
        selected_tactic = rule_override.get("tactic")
        selected_techniques = rule_override.get("techniques")
        if selected_tactic:
            tactics = [str(selected_tactic)]
            relevant = [str(value) for value in selected_techniques or [] if value]
            warnings.append(
                "multiple source tactics were resolved by the configured per-rule override"
            )
        else:
            reason = (
                "Custom Detections support one tactic; configure ruleOverrides."
                f"{source_id}.tactic and techniques"
            )
            warnings.append(reason)
            review_reasons.append(reason)
            tactics = [tactics[0]]
            relevant = []
    if not mappings:
        errors.append("no supported entity mappings were produced")
    elif not REQUIRED_ASSET_COLLECTIONS.intersection(mappings):
        errors.append("a Host, Account, Mailbox, or IP mapping is required")

    if not source_id:
        errors.append("source analytic rule has no id")
    elif not re.fullmatch(SOURCE_ID_PATTERN, source_id):
        errors.append("source analytic rule id must be a full hyphenated GUID")

    accepted_review_reasons = {
        str(value)
        for value in rule_override.get("acceptedReviewReasons") or []
        if value
    }
    unknown_acceptances = accepted_review_reasons.difference(review_reasons)
    if unknown_acceptances:
        errors.extend(
            "configured acceptedReviewReasons entry does not match a current review "
            f"reason: {reason}"
            for reason in sorted(unknown_acceptances)
        )
    review_reasons = [
        reason for reason in review_reasons if reason not in accepted_review_reasons
    ]

    display_name = str(doc.get("name") or source.stem)
    detection_id = source_id
    severity = str(doc.get("severity") or "Medium").lower()
    if severity not in SUPPORTED_SEVERITIES:
        warnings.append(f"unsupported severity {severity!r}; changed to medium")
        severity = "medium"

    tactic_payload: list[dict[str, Any]] = []
    if tactics:
        tactic = {"tactic": tactics[0]}
        technique_payload = _techniques(relevant)
        if technique_payload:
            tactic["techniques"] = technique_payload
        tactic_payload.append(tactic)

    alert: dict[str, Any] = {
        "title": display_name[:120],
        "description": str(doc.get("description") or display_name).strip()[:600],
        "severity": severity,
        "entityMappings": mappings,
    }
    if tactic_payload:
        alert["tactics"] = tactic_payload

    blocking_review_reasons = [
        reason
        for reason in review_reasons
        if not reason.startswith(ENTITY_CONFIRMATION_PREFIX)
    ]
    status = "needsReview" if errors or blocking_review_reasons else "converted"
    relative_source = source.relative_to(solution_root).as_posix()
    return {
        "schemaVersion": SCHEMA_VERSION,
        "version": INITIAL_XDR_VERSION,
        "kind": "CustomDetection",
        "resourceType": "Microsoft.Security/detectionRules",
        "apiVersion": DETECTION_API_VERSION,
        **(
            {"requiredDataConnectors": deepcopy(doc["requiredDataConnectors"])}
            if "requiredDataConnectors" in doc
            else {}
        ),
        "contentProvenance": {
            "source": {
                "platform": "Microsoft Sentinel",
                "kind": "AnalyticsRule",
                "id": source_id,
                "path": relative_source,
                "version": str(doc.get("version") or ""),
                "querySha256": hashlib.sha256(source_query.encode("utf-8")).hexdigest(),
                "schedule": {
                    "queryFrequency": str(doc.get("queryFrequency") or ""),
                    "queryPeriod": query_period,
                },
            },
            "conversion": {
                "tool": "sentinel-to-xdr-migration",
                "version": __version__,
                "status": status,
                "reviewRequired": bool(errors or review_reasons),
                "reviewReasons": review_reasons,
                "requiredWorkloads": ["sentinel"],
                "warnings": warnings,
                "informational": informational,
                "errors": errors,
                "originalTactics": source_tactics,
                "originalTechniques": source_relevant,
                **(
                    {"acceptedReviewReasons": sorted(accepted_review_reasons)}
                    if accepted_review_reasons
                    else {}
                ),
            },
        },
        "properties": {
            "id": detection_id,
            "displayName": display_name[:120],
            "status": "disabled",
            "queryCondition": {"queryText": converted_query},
            "schedule": {"frequency": frequency},
            "detectionAction": {"alertTemplate": alert},
        },
    }


def xdr_version_error(version: Any) -> str | None:
    if isinstance(version, str) and re.fullmatch(XDR_VERSION_PATTERN, version):
        return None
    return (
        f"XDR top-level version {version!r} must be a major.minor.patch release "
        ">= 3.1.0 and < 4.0.0. For older files without version, reconvert with "
        "--overwrite (initial version 3.1.0), or explicitly author the XDR version. "
        "Do not change contentProvenance.source.version."
    )


def is_sentinel_derived(document: dict[str, Any]) -> bool:
    provenance = document.get("contentProvenance") or {}
    source = provenance.get("source") or {}
    conversion = provenance.get("conversion") or {}
    return (
        source.get("platform") == "Microsoft Sentinel"
        and source.get("kind") == "AnalyticsRule"
    ) or conversion.get("tool") == "sentinel-to-xdr-migration"


def _existing_identity_error(
    document: Any, source_id: str, source_path: str, source_name: str,
) -> str | None:
    if not isinstance(document, dict):
        return "existing output is not an XDR document; resolve the output identity conflict"
    provenance = document.get("contentProvenance") or {}
    if not isinstance(provenance, dict):
        return "existing output has malformed provenance; resolve the output identity conflict"
    source = provenance.get("source") or {}
    conversion = provenance.get("conversion") or {}
    properties = document.get("properties") or {}
    if not all(isinstance(value, dict) for value in (source, conversion, properties)):
        return "existing output has malformed identity fields; resolve the output identity conflict"
    if (
        document.get("kind") != "CustomDetection"
        or document.get("resourceType") != "Microsoft.Security/detectionRules"
        or source.get("platform") != "Microsoft Sentinel"
        or source.get("kind") != "AnalyticsRule"
        or source.get("id") != source_id
        or str(source.get("path") or "").replace("\\", "/") != source_path
    ):
        return (
            "existing XDR output belongs to a different source rule or has conflicting "
            "provenance; resolve the output identity conflict before reconverting"
        )
    detection_id = properties.get("id")
    if detection_id == source_id:
        return None
    legacy_ids = {
        f"xdr-{slugify(name)}-{source_id[:8]}"
        for name in (str(properties.get("displayName") or ""), source_name)
        if name
    }
    if (
        conversion.get("tool") == "sentinel-to-xdr-migration"
        and isinstance(detection_id, str)
        and detection_id in legacy_ids
    ):
        return None
    return (
        f"existing Custom Detection id {detection_id!r} is not the source GUID or a "
        "generated legacy name ID; reconcile this custom identity explicitly before "
        "reconversion, even with --overwrite"
    )


def validate_document(document: dict[str, Any]) -> list[str]:
    with XDR_SCHEMA_PATH.open(encoding="utf-8") as handle:
        schema = json.load(handle)
    errors = [
        f"schema: {error.message}"
        for error in Draft202012Validator(schema).iter_errors(document)
    ]
    version_error = xdr_version_error(document.get("version"))
    if version_error:
        errors.append(version_error)
    if document.get("schemaVersion") != SCHEMA_VERSION:
        errors.append(f"schemaVersion must be {SCHEMA_VERSION}")
    if document.get("kind") != "CustomDetection":
        errors.append("kind must be CustomDetection")
    if document.get("resourceType") != "Microsoft.Security/detectionRules":
        errors.append("resourceType must be Microsoft.Security/detectionRules")
    provenance = document.get("contentProvenance") or {}
    source = provenance.get("source") or {}
    conversion = provenance.get("conversion") or {}
    properties = document.get("properties") or {}
    if is_sentinel_derived(document):
        if not isinstance(source.get("id"), str) or not re.fullmatch(SOURCE_ID_PATTERN, source["id"]):
            errors.append("contentProvenance.source.id must be a full hyphenated Sentinel template GUID")
        if properties.get("id") != source.get("id"):
            errors.append(
                "Sentinel-derived properties.id must equal contentProvenance.source.id "
                "exactly; review and reconvert generated legacy IDs with --overwrite "
                "(local artifacts only, not deployed rule migration)"
            )
    for field in ("platform", "kind", "id", "path", "querySha256"):
        if not source.get(field):
            errors.append(f"contentProvenance.source.{field} is required")
    if conversion.get("status") not in {"converted", "needsReview"}:
        errors.append("contentProvenance.conversion.status is invalid")
    if conversion.get("errors"):
        errors.extend(f"conversion: {value}" for value in conversion["errors"])
    if properties.get("status") != "disabled":
        errors.append("properties.status must be disabled")
    query = ((properties.get("queryCondition") or {}).get("queryText") or "")
    if not query:
        errors.append("properties.queryCondition.queryText is required")
    alert = ((properties.get("detectionAction") or {}).get("alertTemplate") or {})
    mappings = alert.get("entityMappings") or {}
    if not mappings:
        errors.append("alertTemplate.entityMappings is required")
    if not REQUIRED_ASSET_COLLECTIONS.intersection(mappings):
        errors.append("at least one Host, Account, Mailbox, or IP mapping is required")
    if len(alert.get("tactics") or []) > 1:
        errors.append("at most one tactic is supported")
    return errors


def convert_solution(
    solution: str | Path,
    *,
    overwrite: bool = False,
    config_path: str | Path | None = None,
    rule_id: str | None = None,
) -> dict[str, Any]:
    root, analytic, output = solution_paths(solution)
    sources = analytic_rule_files(root)
    existing_outputs = xdr_detection_files(output)
    existing_by_source: dict[str, list[Path]] = {}
    existing_by_id: dict[str, list[Path]] = {}
    existing_documents: dict[Path, Any] = {}
    identified_outputs: set[Path] = set()
    for path in existing_outputs:
        try:
            existing = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
            existing_documents[path] = existing
            provenance = (existing.get("contentProvenance") or {}).get("source") or {}
            detection_id = str((existing.get("properties") or {}).get("id") or "")
            if detection_id:
                existing_by_id.setdefault(detection_id.casefold(), []).append(path)
            for key in (str(provenance.get("id") or "").casefold(), str(provenance.get("path") or "").replace("\\", "/")):
                if key:
                    existing_by_source.setdefault(key, []).append(path)
                    identified_outputs.add(path)
        except (AttributeError, OSError, yaml.YAMLError):
            continue
    config = load_config(output, config_path)
    results: list[ConversionResult] = []
    excluded_rule_ids = config.get("excludedRuleIds") or {}
    if not isinstance(excluded_rule_ids, dict):
        raise ValueError("excludedRuleIds must contain an object of rule IDs and reasons")

    source_documents: dict[Path, dict[str, Any]] = {}
    sources_by_id: dict[str, list[Path]] = {}
    for source in sources:
        with source.open(encoding="utf-8-sig") as handle:
            source_document = yaml.safe_load(handle) or {}
        if not isinstance(source_document, dict):
            raise ValueError(f"analytic rule must contain a YAML object: {source}")
        source_documents[source] = source_document
        source_id = str(source_document.get("id") or "")
        if source_id:
            sources_by_id.setdefault(source_id.casefold(), []).append(source)

    selected_sources = sources
    if rule_id is not None:
        if not isinstance(rule_id, str) or not re.fullmatch(SOURCE_ID_PATTERN, rule_id):
            raise ValueError("--rule-id must be a full hyphenated Sentinel template GUID")
        selected_sources = sources_by_id.get(rule_id.casefold(), [])
        if len(selected_sources) != 1:
            raise ValueError(
                f"--rule-id {rule_id!r} must match exactly one source analytic rule; "
                f"found {len(selected_sources)} (unknown or duplicate source ID)"
            )
        if any(str(key).casefold() == rule_id.casefold() for key in excluded_rule_ids):
            raise ValueError("--rule-id selects an excluded rule; reconcile excludedRuleIds explicitly")

    # Selection is checked before creating Logs, output directories, or removing exclusions.
    reports = report_directory(root, create=True)
    output.mkdir(parents=True, exist_ok=True)
    for source in selected_sources:
        target = content_path(output, source.relative_to(analytic))
        source_document = source_documents[source]
        source_id = str(source_document.get("id") or "")
        source_path = source.relative_to(root).as_posix()
        identity_error = None
        if len(sources_by_id.get(source_id.casefold(), [])) > 1:
            identity_error = f"duplicate source analytic rule id {source_id!r}; reconcile source identities before conversion"
        id_collisions = set(existing_by_id.get(source_id.casefold(), [])) - {target}
        if id_collisions:
            identity_error = (
                f"Custom Detection id {source_id!r} is already used by another output; "
                "review and explicitly relocate or reconcile it before conversion "
                "(even with --overwrite): "
                + ", ".join(path.relative_to(root).as_posix() for path in sorted(id_collisions))
            )
        existing_document = existing_documents.get(target)
        if isinstance(existing_document, dict):
            existing_properties = existing_document.get("properties") or {}
            previous_id = str(existing_properties.get("id") or "") if isinstance(existing_properties, dict) else ""
            if previous_id and len(existing_by_id.get(previous_id.casefold(), [])) > 1:
                identity_error = f"duplicate existing Custom Detection id {previous_id!r}; reconcile output identities before conversion"
        if not identity_error and target.exists():
            identity_error = _existing_identity_error(
                existing_document, source_id, source_path,
                str(source_document.get("name") or source.stem),
            )
        if identity_error:
            results.append(ConversionResult(
                source, target, str(source_document.get("name") or source.stem),
                "conflict", True, (identity_error,), (), (identity_error,),
            ))
            continue
        alternate_outputs = set(
            existing_by_source.get(source_id.casefold(), [])
            + existing_by_source.get(source_path, [])
        ) - {target}
        # A legacy flattened file must not become a second detection for this source.
        legacy_target = output / source.name
        if (
            target != legacy_target
            and legacy_target.exists()
            and legacy_target not in identified_outputs
        ):
            alternate_outputs.add(legacy_target)
        if alternate_outputs:
            error = (
                "existing detection at a different path; review and explicitly relocate "
                "or reconcile it before conversion (even with --overwrite): "
                + ", ".join(path.relative_to(root).as_posix() for path in sorted(alternate_outputs))
            )
            results.append(ConversionResult(
                source, target, str(source_document.get("name") or source.stem),
                "conflict", True, (error,), (), (error,),
            ))
            continue
        exclusion_reason = excluded_rule_ids.get(source_id)
        if exclusion_reason is not None:
            if target.exists():
                if not overwrite:
                    results.append(
                        ConversionResult(
                            source,
                            target,
                            str(source_document.get("name") or source.stem),
                            "conflict",
                            True,
                            ("excluded output exists; rerun with --overwrite to remove it",),
                            (),
                            ("excluded output exists; rerun with --overwrite to remove it",),
                        )
                    )
                    continue
                target.unlink()
            results.append(
                ConversionResult(
                    source,
                    target,
                    str(source_document.get("name") or source.stem),
                    "excluded",
                    False,
                    (),
                    (f"excluded from Custom Detections: {exclusion_reason}",),
                    (),
                )
            )
            continue
        document = build_xdr_document(source, root, config)
        if target.exists():
            if isinstance(existing_document, dict) and "version" in existing_document:
                error = xdr_version_error(existing_document["version"])
                if error:
                    results.append(
                        ConversionResult(
                            source, target, document["properties"]["displayName"],
                            "conflict", True, (error,), (), (error,),
                        )
                    )
                    continue
                document["version"] = existing_document["version"]
            previous_id = existing_document["properties"]["id"]
            identity_change = (
                (existing_document.get("contentProvenance") or {}).get("conversion") or {}
            ).get("identityChange")
            if previous_id != source_id:
                identity_change = {
                    "previousId": previous_id,
                    "currentId": source_id,
                    "scope": "local-artifact-only",
                }
            if isinstance(identity_change, dict) and identity_change.get("currentId") == source_id:
                conversion = document["contentProvenance"]["conversion"]
                conversion["identityChange"] = identity_change
                conversion["warnings"].append(
                    f"Local detection ID changed from {identity_change.get('previousId')!r} "
                    f"to originating Sentinel template ID {source_id!r}. No cloud rules "
                    "were updated, deleted, or migrated. Review existing deployed rules "
                    "and reconcile their identities before any separately approved deployment."
                )
        rendered = yaml.dump(
            document,
            Dumper=XdrYamlDumper,
            sort_keys=False,
            allow_unicode=False,
            width=120,
        )
        if target.exists() and not overwrite:
            existing = target.read_text(encoding="utf-8")
            if existing != rendered:
                results.append(
                    ConversionResult(
                        source,
                        target,
                        document["properties"]["displayName"],
                        "conflict",
                        True,
                        ("output exists with different content; rerun with --overwrite",),
                        (),
                        ("output exists with different content; rerun with --overwrite",),
                    )
                )
                continue
        if not target.exists() or target.read_text(encoding="utf-8") != rendered:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(rendered, encoding="utf-8", newline="\n")
        conversion = document["contentProvenance"]["conversion"]
        results.append(
            ConversionResult(
                source,
                target,
                document["properties"]["displayName"],
                conversion["status"],
                bool(conversion["reviewRequired"]),
                tuple(conversion["reviewReasons"]),
                tuple(conversion["warnings"]),
                tuple(conversion["errors"]),
                tuple(conversion.get("informational") or []),
            )
        )

    reports = report_directory(root, create=True)
    transformation_report = reports / "transformation-report.html"
    manifest_path = reports / "manifest.json"
    summary = {
        "solution": str(root),
        "scope": {
            "kind": "rule" if rule_id is not None else "solution",
            "ruleIds": (
                [source_documents[source]["id"] for source in selected_sources]
                if rule_id is not None else []
            ),
            "sourceTotal": len(sources),
            "selectedTotal": len(selected_sources),
        },
        "outputDirectory": str(output),
        "reportDirectory": str(reports),
        "manifest": str(manifest_path),
        "transformationReport": str(transformation_report),
        "total": len(results),
        "converted": sum(result.status == "converted" for result in results),
        "excluded": sum(result.status == "excluded" for result in results),
        "needsReview": sum(result.status == "needsReview" for result in results),
        "reviewRequired": sum(result.review_required for result in results),
        "deploymentReady": sum(
            result.status == "converted" and not result.review_required for result in results
        ),
        "conflicts": sum(result.status == "conflict" for result in results),
        "results": [
            {
                **result.as_dict(),
                "sourceRelativePath": result.source.relative_to(root).as_posix(),
                "outputRelativePath": result.output.relative_to(root).as_posix(),
            }
            for result in results
        ],
    }
    write_json_artifact(root, manifest_path, summary)
    if rule_id is not None:
        from .workflow import invalidate_scoped_completion

        invalidate_scoped_completion(root)
    write_transformation_report(portable_artifact(root, summary), transformation_report)
    return summary


def validate_solution(solution: str | Path) -> dict[str, Any]:
    root, _, output = solution_paths(solution)
    files = xdr_detection_files(output) if output.exists() else []
    results = []
    results_by_id: dict[str, list[dict[str, Any]]] = {}
    for path in files:
        detection_id = None
        try:
            with path.open(encoding="utf-8-sig") as handle:
                document = yaml.safe_load(handle) or {}
            errors = validate_document(document)
            detection_id = (document.get("properties") or {}).get("id")
        except (OSError, yaml.YAMLError, ValueError) as exc:
            errors = [str(exc)]
        result = {"file": str(path), "valid": not errors, "errors": errors}
        results.append(result)
        if isinstance(detection_id, str) and detection_id:
            results_by_id.setdefault(detection_id.casefold(), []).append(result)
    for detection_id, duplicates in results_by_id.items():
        if len(duplicates) > 1:
            for result in duplicates:
                result["errors"].append(f"duplicate Custom Detection id {detection_id!r}")
                result["valid"] = False
    return {
        "solution": str(root),
        "conversionScope": conversion_scope(root),
        "total": len(results),
        "valid": sum(item["valid"] for item in results),
        "invalid": sum(not item["valid"] for item in results),
        "results": results,
    }


def runtime_validation_plan(solution: str | Path) -> dict[str, Any]:
    root, _, output = solution_paths(solution)
    plan = []
    for path in xdr_detection_files(output):
        with path.open(encoding="utf-8-sig") as handle:
            document = yaml.safe_load(handle) or {}
        source_path = content_path(root, document["contentProvenance"]["source"]["path"])
        with source_path.open(encoding="utf-8-sig") as handle:
            source = yaml.safe_load(handle) or {}
        plan.append(
            {
                "detection": path.relative_to(output).as_posix(),
                "sourceRule": str(source_path),
                "sentinelQuery": str(source.get("query") or ""),
                "advancedHuntingQuery": document["properties"]["queryCondition"]["queryText"],
            }
        )
    return {
        "solution": str(root),
        "instructions": (
            "Run sentinelQuery and advancedHuntingQuery through the Microsoft Sentinel "
            "the configured runtime providers. Record execution errors and compare output entities."
        ),
        "rules": plan,
    }
