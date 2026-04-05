#!/usr/bin/env python3
"""
log_loki.py — Collecte temps réel de TOUS les fichiers logs TTCS depuis Loki
=============================================================================
Version finale — Toutes les fonctions incluant collect_all_nodes()

Fixes :
  - Fix 1 : spaCy warning affiché une seule fois
  - Fix 2 : Retry sur Loki 500 temporaire
  - Fix 3 : Cache streams TTL 60s
  - Fix 4 : Heartbeats ignorés
  - Fix 5 : collect_all_nodes() — collecte synchrone complète

Fichiers traités (29 fichiers sur 6 noeuds) :
  jambala  (CCN) : application.log, applog.Alarm, applog.Error
  ttaf1    (AF)  : application.log, named.run
  ttair6   (AIR) : application.log
  ttocc1   (OCC) : application.log, Alarm.log, CDR_archived.log,
                   HealthMonitor.log, Notification.log,
                   SERVER.Business.log, messages
  ttsdp17a (SDP) : application.log, INAP.log, TTErrors.log, TTMonitor.log,
                   tterrors.log, ttlog, ttmesg.log, audit.log, ecm.log,
                   messages, sm.alarm.log, ss7trace.log,
                   SOG_REPORT_ttsdp17_default.log.0,
                   PSC-CIPDiameter_8.1_A_1.stat.1
  ttvs3a   (VS)  : application.log, Voucher.log

Dépendances :
    pip install requests spacy
    python -m spacy download en_core_web_sm
"""

import re
import time
import threading
import logging
from datetime import datetime, timezone
from collections import deque

import requests

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration Loki
# ---------------------------------------------------------------------------
LOKI_URL        = "http://127.0.0.1:3100"
LOKI_QUERY_URL  = f"{LOKI_URL}/loki/api/v1/query_range"
LOKI_LABELS_URL = f"{LOKI_URL}/loki/api/v1/label/node/values"
LOKI_SERIES_URL = f"{LOKI_URL}/loki/api/v1/series"

POLL_INTERVAL = 5     # secondes entre chaque poll
POLL_WINDOW   = 10    # fenêtre de récupération
LOKI_LIMIT    = 200   # max lignes par requête par fichier
BUFFER_SIZE   = 1000  # max événements par noeud

# Buffer mémoire : { node -> deque([event, ...]) }
LOG_BUFFER: dict[str, deque] = {}
# Curseur timestamp par stream (node, filename)
_LAST_TS: dict[tuple, int] = {}
_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Mapping fichier → catégorie
# ---------------------------------------------------------------------------
FILENAME_CATEGORY = {
    "applog.Alarm":        "alarm",
    "applog.Error":        "error",
    "Alarm.log":           "alarm",
    "sm.alarm.log":        "alarm",
    "TTErrors.log":        "tt_error",
    "tterrors.log":        "tt_error",
    "TTMonitor.log":       "tt_monitor",
    "ttlog":               "tt_log",
    "ttmesg.log":          "tt_message",
    "INAP.log":            "inap",
    "ss7trace.log":        "ss7",
    "ecm.log":             "ecm",
    "audit.log":           "audit",
    "messages":            "syslog",
    "HealthMonitor.log":   "health_monitor",
    "CDR_archived.log":    "cdr",
    "Notification.log":    "notification",
    "SERVER.Business.log": "business",
    "named.run":           "dns",
    "Voucher.log":         "voucher",
    "application.log":     "application",
}

HIGH_PRIORITY_FILES = {
    "applog.Alarm", "applog.Error", "Alarm.log",
    "sm.alarm.log", "TTErrors.log", "tterrors.log",
    "INAP.log", "ecm.log", "HealthMonitor.log",
}

# ---------------------------------------------------------------------------
# Mapping sévérité
# ---------------------------------------------------------------------------
ERICSSON_SEV = {
    "1": "CRITICAL", "2": "CRITICAL",
    "3": "WARNING",  "4": "WARNING",
    "5": "INFO",
}
LEVEL_MAP = {
    "CRITICAL": "CRITICAL", "CRIT": "CRITICAL",
    "ERROR":    "ERROR",    "ERR":  "ERROR",
    "WARNING":  "WARNING",  "WARN": "WARNING",
    "MAJOR":    "WARNING",  "MINOR":"WARNING",
    "INFO":     "INFO",     "NOTICE":"INFO",
    "DEBUG":    "DEBUG",
}
ROLE_PATTERNS = {
    "ccn": "CCN", "jambala": "CCN",
    "air": "AIR", "sdp": "SDP",
    "vs":  "VS",  "occ": "OCC", "af": "AF",
}

# ---------------------------------------------------------------------------
# Mots-clés NLP
# ---------------------------------------------------------------------------
CRITICAL_KW = [
    "fail", "failure", "timeout", "refuse", "loss", "crash",
    "rollback", "conflict", "unreachable", "down", "error",
    "alarm", "critical", "abort", "disconnect", "lost",
]
WARNING_KW = [
    "slow", "delay", "retry", "degrade", "martian",
    "notice", "warning", "high", "exceed",
]
SEV_RANK = {"NORMAL": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}


# ===========================================================================
# HELPERS
# ===========================================================================

def _guess_role(node_name: str) -> str:
    name_lower = node_name.lower()
    for pat, role in ROLE_PATTERNS.items():
        if pat in name_lower:
            return role
    return "UNKNOWN"

def _ts_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _parse_ts(ts_str: str) -> str:
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%b %d %H:%M:%S",
        "%d %b %H:%M:%S",
        "%Y %b %d  %H:%M:%S:%f",
        "%Y-%m-%dT%H:%M:%SZ",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return _ts_now()

def _extract_int(text: str, key: str) -> int | None:
    m = re.search(rf'{key}[=:\s]+(\d+)', text, re.I)
    return int(m.group(1)) if m else None

def _get_filename_category(filename: str) -> str:
    basename = filename.split("/")[-1]
    for key, cat in FILENAME_CATEGORY.items():
        if basename == key or basename.startswith(key.split(".")[0]):
            return cat
    return "unknown"


# ===========================================================================
# FACTORY
# ===========================================================================

def _make_event(ts: str, node: str, level: str, category: str,
                message: str, filename: str,
                specific_problem: str | None = None,
                managed_object: str | None = None,
                probable_cause: str | None = None,
                notification_id: str | None = None,
                alarm_id: str | None = None,
                duration_ms: int | None = None,
                count: int | None = None) -> dict:
    return {
        "timestamp":        ts,
        "node":             node,
        "role":             _guess_role(node),
        "level":            level,
        "category":         category,
        "filename":         filename.split("/")[-1],
        "filepath":         filename,
        "message":          message,
        "specific_problem": specific_problem,
        "managed_object":   managed_object,
        "probable_cause":   probable_cause,
        "notification_id":  notification_id,
        "alarm_id":         alarm_id,
        "duration_ms":      duration_ms,
        "count":            count,
        "nlp_severity":     level,
        "keywords":         [],
        "entities":         [],
    }


# ===========================================================================
# PARSERS
# ===========================================================================

# Format 1 : TelORB Alarm
_F1 = re.compile(
    r'(?P<sev_code>\d+)\s+\[.*?\]\s+Alarm:.*?'
    r'nodeName=(?P<node>\w+);.*?'
    r'i_notificationId=(?P<notif_id>\d+);.*?'
    r'vc_eventTime=(?P<ts>[\d\- :]+);.*?'
    r's_probableCause=(?P<cause>\d+);'
    r's_perceivedSeverity=(?P<sev>\d+);'
    r'specificProblem=(?P<specific>[^;]+);.*?'
    r'managedObjectClass=(?P<moc>[^;]+);',
    re.DOTALL
)
_F1_AID = re.compile(r'alarmId=\{([^}]+)\}')

def _parse_telorb_alarm(raw: str, node: str, filename: str) -> dict | None:
    m = _F1.search(raw)
    if not m:
        return None
    level    = ERICSSON_SEV.get(m.group("sev"), "WARNING")
    specific = m.group("specific").strip()
    moc      = m.group("moc").strip()
    aid_m    = _F1_AID.search(raw)
    clean    = re.sub(r'\b\d{10,}\b', 'ID', f"Alarm {moc}: {specific}")
    return _make_event(
        ts=_parse_ts(m.group("ts")), node=m.group("node") or node,
        level=level, category="alarm", message=clean, filename=filename,
        specific_problem=specific, managed_object=moc,
        probable_cause=m.group("cause"), notification_id=m.group("notif_id"),
        alarm_id=aid_m.group(1) if aid_m else None,
    )

# Format 2 : OCC Alarm
_F2 = re.compile(
    r'\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+'
    r'(?P<cat>OCC\.\w+|OS\.\w+)\s*\|?\s*'
    r'(?P<alarm_type>Alarm\.\w+)?\s*\|?\s*'
    r'(?P<count>\d+)?\s*\|?\s*\w*\s*\|?\s*'
    r'(?P<status>Normal|Warning|Critical|Major|Minor)?'
)

def _parse_occ_alarm(raw: str, node: str, filename: str) -> dict | None:
    m = _F2.search(raw)
    if not m:
        return None
    status     = m.group("status") or "Normal"
    alarm_type = m.group("alarm_type") or ""
    cat        = m.group("cat") or "OCC"
    count      = int(m.group("count")) if m.group("count") else 0
    level = (
        "CRITICAL" if "Critical" in alarm_type or "Critical" in status else
        "WARNING"  if "Major"    in alarm_type or "Warning"  in status else
        "INFO"
    )
    return _make_event(
        ts=_parse_ts(m.group("ts")), node=node,
        level=level, category="occ_alarm",
        message=f"{cat} {alarm_type} status={status} count={count}",
        filename=filename, count=count,
        specific_problem=f"{alarm_type} {status}" if level != "INFO" else None,
    )

# Format 3 : INFO structuré
_F3 = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    r'\s+(?P<level>INFO|WARNING|ERROR|CRITICAL|DEBUG)\s+'
    r'\[(?P<svc>\w+)\]\s+(?P<msg>.+)'
)

def _parse_info_structured(raw: str, node: str, filename: str) -> dict | None:
    m = _F3.search(raw)
    if not m:
        return None
    msg = m.group("msg").strip()
    return _make_event(
        ts=_parse_ts(m.group("ts")), node=node,
        level=LEVEL_MAP.get(m.group("level").upper(), "INFO"),
        category=_get_filename_category(filename),
        message=msg, filename=filename,
        managed_object=m.group("svc"),
        duration_ms=_extract_int(msg, "durationMs"),
        count=_extract_int(msg, "written") or _extract_int(msg, "ok"),
    )

# Format 4 : TimesTen Errors
_F4_TT = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)'
    r'\s+(?P<level>Error|Warning|Info|Critical):\s*'
    r'\s*(?P<pid>\d+):\s+(?P<msg>.+)'
)

def _parse_tt_error(raw: str, node: str, filename: str) -> dict | None:
    m = _F4_TT.search(raw)
    if not m:
        return None
    level = LEVEL_MAP.get(m.group("level").capitalize(), "INFO")
    return _make_event(
        ts=_parse_ts(m.group("ts").split(".")[0]), node=node,
        level=level, category="tt_error",
        message=m.group("msg").strip(), filename=filename,
        specific_problem=m.group("msg").strip()
        if level in ("ERROR", "CRITICAL") else None,
    )

# Format 5 : INAP/HLR
_F5_HLR = re.compile(
    r'\[(?P<ts>\d{6}:\d{6})\]\s+Id:\s*(?P<conn_id>\d+)\s+'
    r"Sent command '(?P<cmd>[^']+)'"
    r"\s+to\s+(?P<dest>[\d.:]+)"
    r"\s+Received answer:\s+'(?P<resp>[^']+)'"
)
_F5_INAP = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    r'.*?(?P<level>ERROR|WARNING|INFO|CRITICAL)\s+(?P<msg>.+)'
)

def _parse_inap_ss7(raw: str, node: str, filename: str) -> dict | None:
    m = _F5_HLR.search(raw)
    if m:
        resp  = m.group("resp").strip()
        level = "INFO" if resp == "RESP:0;" else "ERROR"
        cmd   = re.sub(r'MSISDN,\d+', 'MSISDN,XXXXX', m.group("cmd"))
        raw_ts = m.group("ts")
        try:
            d = raw_ts[:6]; t = raw_ts[7:]
            ts_str = f"20{d[:2]}-{d[2:4]}-{d[4:6]} {t[:2]}:{t[2:4]}:{t[4:6]}"
        except Exception:
            ts_str = _ts_now()
        return _make_event(
            ts=_parse_ts(ts_str), node=node,
            level=level, category="inap",
            message=f"HLR {cmd} → {resp}", filename=filename,
            notification_id=m.group("conn_id"),
            specific_problem=None if level == "INFO" else f"HLR error: {resp}",
        )
    m = _F5_INAP.search(raw)
    if m:
        return _make_event(
            ts=_parse_ts(m.group("ts")), node=node,
            level=LEVEL_MAP.get(m.group("level"), "INFO"),
            category="inap", message=m.group("msg").strip(),
            filename=filename,
        )
    return None

# Format 6 : ECM
_F6_ECM   = re.compile(r'>>(?P<level>NOTICE|WARNING|ERROR)<<\s+(?P<comp>\S+)\s+\S+\s+(?P<node>\S+):\d+')
_F6_STATE = re.compile(r'ECM state changed to (?P<state>\w+)')

def _parse_ecm(raw: str, node: str, filename: str) -> dict | None:
    m = _F6_ECM.search(raw)
    if m:
        return _make_event(
            ts=_ts_now(), node=m.group("node") or node,
            level=LEVEL_MAP.get(m.group("level").upper(), "INFO"),
            category="ecm",
            message=f"ECM {m.group('comp')} {m.group('level')}",
            filename=filename,
            specific_problem=f"ECM state: {m.group('level')}",
            managed_object=m.group("comp"),
        )
    m = _F6_STATE.search(raw)
    if m:
        state = m.group("state")
        return _make_event(
            ts=_ts_now(), node=node,
            level="WARNING" if state != "ACTIVE" else "INFO",
            category="ecm",
            message=f"ECM state changed to {state}",
            filename=filename,
        )
    return None

# Format 7 : Audit
_F7 = re.compile(r'type=(?P<type>USER_\w+)\s+msg=audit\([\d.:]+\):\s+(?P<msg>.+)')

def _parse_audit(raw: str, node: str, filename: str) -> dict | None:
    m = _F7.search(raw)
    if not m:
        return None
    msg = re.sub(r'\b\d{10,}\b', 'ID',
                 re.sub(r'addr=[\d.]+', 'addr=X.X.X.X', m.group("msg")))
    return _make_event(
        ts=_ts_now(), node=node, level="INFO",
        category="audit",
        message=f"Audit {m.group('type')}: {msg[:100]}",
        filename=filename,
    )

# Format 8 : Syslog/messages
_F8_KERN   = re.compile(r'(?P<ts>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<node>\S+)\s+kernel:\s+(?P<msg>.+)')
_F8_SYSLOG = re.compile(r'(?P<ts>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<node>\S+)\s+(?P<svc>\S+):\s+(?P<msg>.+)')

def _parse_syslog(raw: str, node: str, filename: str) -> dict | None:
    m = _F8_KERN.search(raw)
    if m:
        msg   = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'X.X.X.X', m.group("msg"))
        level = "WARNING" if any(k in msg.lower() for k in ["martian","error","fail"]) else "INFO"
        return _make_event(
            ts=_parse_ts(m.group("ts")), node=m.group("node") or node,
            level=level, category="kernel",
            message=f"kernel: {msg}", filename=filename,
            specific_problem=msg if level == "WARNING" else None,
        )
    m = _F8_SYSLOG.search(raw)
    if m:
        return _make_event(
            ts=_parse_ts(m.group("ts")), node=m.group("node") or node,
            level="INFO", category="syslog",
            message=f"{m.group('svc')}: {m.group('msg').strip()}",
            filename=filename,
        )
    return None

# Format 9 : SS7/SCTP
_F9_SCTP = re.compile(r'\d+\s+\w+\s+\d{2}:\d{2}:\d{2}\s*:\s*(?P<msg>Sctp .+)')
_F9_SS7  = re.compile(r'(?P<ts>\d{4} \w+ \d+\s+\d{2}:\d{2}:\d{2}:\d+)\s+\d+:\d+\s+(?P<msg>.+)')

def _parse_ss7_sctp(raw: str, node: str, filename: str) -> dict | None:
    m = _F9_SCTP.search(raw)
    if m:
        return _make_event(
            ts=_ts_now(), node=node, level="INFO",
            category="sctp",
            message=re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                           'X.X.X.X', m.group("msg")),
            filename=filename,
        )
    m = _F9_SS7.search(raw)
    if m:
        return _make_event(
            ts=_ts_now(), node=node, level="INFO",
            category="ss7", message=m.group("msg").strip(),
            filename=filename,
        )
    return None

# Format 10 : sm.alarm.log
_F10 = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    r'.*?(?P<level>CRITICAL|ERROR|WARNING|INFO)\s*(?P<msg>.+)'
)

def _parse_sm_alarm(raw: str, node: str, filename: str) -> dict | None:
    m = _F10.search(raw)
    if not m:
        return None
    return _make_event(
        ts=_parse_ts(m.group("ts")), node=node,
        level=LEVEL_MAP.get(m.group("level").upper(), "INFO"),
        category="sm_alarm", message=m.group("msg").strip(),
        filename=filename,
    )

# Format 11 : HealthMonitor
_F11 = re.compile(
    r'\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+'
    r'(?P<component>\S+)\s+(?P<status>Normal|Warning|Critical|Failed|OK)'
)

def _parse_health_monitor(raw: str, node: str, filename: str) -> dict | None:
    m = _F11.search(raw)
    if not m:
        return None
    status = m.group("status")
    level  = (
        "CRITICAL" if status in ("Critical", "Failed") else
        "WARNING"  if status == "Warning" else
        "INFO"
    )
    return _make_event(
        ts=_parse_ts(m.group("ts")), node=node,
        level=level, category="health_monitor",
        message=f"{m.group('component')} {status}",
        filename=filename,
        specific_problem=f"{m.group('component')} {status}" if level != "INFO" else None,
    )

# Format 12 : Voucher
_F12 = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    r'\s+(?P<level>INFO|WARNING|ERROR|CRITICAL)\s+\[VS\]\s+(?P<msg>.+)'
)

def _parse_voucher(raw: str, node: str, filename: str) -> dict | None:
    m = _F12.search(raw)
    if not m:
        return None
    msg = m.group("msg").strip()
    return _make_event(
        ts=_parse_ts(m.group("ts")), node=node,
        level=LEVEL_MAP.get(m.group("level").upper(), "INFO"),
        category="voucher", message=msg, filename=filename,
        count=_extract_int(msg, "ok") or _extract_int(msg, "processed"),
    )

# Format 13 : DNS BIND
_F13 = re.compile(
    r'(?P<ts>\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d+)'
    r'\s+(?P<level>error|warning|info|notice|critical):\s+(?P<msg>.+)'
)

def _parse_dns(raw: str, node: str, filename: str) -> dict | None:
    m = _F13.search(raw)
    if not m:
        return None
    return _make_event(
        ts=_ts_now(), node=node,
        level=LEVEL_MAP.get(m.group("level").upper(), "INFO"),
        category="dns", message=m.group("msg").strip(),
        filename=filename,
    )

# Format 14 : Heartbeat
_F14 = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    r'\s+(?P<node>\S+)\s+(?P<role>\w+)\s+heartbeat'
)

def _parse_heartbeat(raw: str, node: str, filename: str) -> dict | None:
    m = _F14.search(raw)
    if not m:
        return None
    return _make_event(
        ts=_parse_ts(m.group("ts")), node=m.group("node"),
        level="INFO", category="heartbeat",
        message=f"{m.group('node')} {m.group('role')} heartbeat OK",
        filename=filename,
    )

# Format 15 : Business/Notification générique
_F15 = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    r'\s+(?P<level>\w+)\s+(?P<msg>.+)'
)

def _parse_business(raw: str, node: str, filename: str) -> dict | None:
    m = _F15.search(raw)
    if not m:
        return None
    level = LEVEL_MAP.get(m.group("level").upper(), "INFO")
    if m.group("level").upper() not in LEVEL_MAP:
        return None
    return _make_event(
        ts=_parse_ts(m.group("ts")), node=node,
        level=level, category=_get_filename_category(filename),
        message=m.group("msg").strip(), filename=filename,
    )


# ===========================================================================
# DISPATCHER
# ===========================================================================

FILE_PARSERS: dict[str, list] = {
    "applog.Alarm":        [_parse_telorb_alarm, _parse_info_structured],
    "applog.Error":        [_parse_telorb_alarm, _parse_info_structured, _parse_business],
    "Alarm.log":           [_parse_occ_alarm, _parse_info_structured],
    "sm.alarm.log":        [_parse_sm_alarm, _parse_info_structured],
    "TTErrors.log":        [_parse_tt_error, _parse_info_structured],
    "tterrors.log":        [_parse_tt_error, _parse_info_structured],
    "TTMonitor.log":       [_parse_tt_error, _parse_info_structured],
    "ttmesg.log":          [_parse_tt_error, _parse_info_structured],
    "ttlog":               [_parse_tt_error, _parse_info_structured],
    "INAP.log":            [_parse_inap_ss7],
    "ss7trace.log":        [_parse_ss7_sctp, _parse_inap_ss7],
    "ecm.log":             [_parse_ecm, _parse_info_structured],
    "audit.log":           [_parse_audit],
    "messages":            [_parse_syslog],
    "HealthMonitor.log":   [_parse_health_monitor, _parse_occ_alarm],
    "CDR_archived.log":    [_parse_info_structured, _parse_business],
    "Notification.log":    [_parse_info_structured, _parse_business],
    "SERVER.Business.log": [_parse_business, _parse_info_structured],
    "named.run":           [_parse_dns, _parse_syslog],
    "Voucher.log":         [_parse_voucher, _parse_info_structured],
    "application.log":     [_parse_info_structured, _parse_heartbeat, _parse_business],
}

FALLBACK_PARSERS = [
    _parse_info_structured,
    _parse_heartbeat,
    _parse_business,
    _parse_syslog,
]


def parse_log_line(raw: str, node: str, filename: str) -> dict | None:
    """Parse une ligne selon le fichier source."""
    basename = filename.split("/")[-1]
    parsers  = None
    for key, plist in FILE_PARSERS.items():
        if basename == key or basename.startswith(key.split(".")[0]):
            parsers = plist
            break
    if parsers is None:
        parsers = FALLBACK_PARSERS

    for parser in parsers:
        try:
            result = parser(raw, node, filename)
            if result:
                return result
        except Exception as e:
            log.debug("Parser %s failed on %s: %s", parser.__name__, basename, e)

    if len(raw.strip()) > 5:
        return _make_event(
            ts=_ts_now(), node=node, level="INFO",
            category=_get_filename_category(filename),
            message=raw.strip()[:200], filename=filename,
        )
    return None


# ===========================================================================
# spaCy — FIX 1 : warning une seule fois
# ===========================================================================

_nlp               = None
_nlp_warning_shown = False
_nlp_loaded        = False


def _get_nlp():
    global _nlp, _nlp_warning_shown, _nlp_loaded
    if _nlp_loaded:
        return _nlp
    try:
        import spacy
        _nlp = spacy.load("en_core_web_sm")
        _nlp_loaded = True
        log.info("spaCy chargé (en_core_web_sm)")
    except Exception:
        _nlp_loaded = True
        if not _nlp_warning_shown:
            log.warning(
                "spaCy non disponible — NLP désactivé. "
                "Installer : pip install spacy && "
                "python -m spacy download en_core_web_sm"
            )
            _nlp_warning_shown = True
    return _nlp


def _enrich_with_spacy(event: dict) -> dict:
    nlp = _get_nlp()
    if not nlp or not event.get("message"):
        return event
    doc    = nlp(event["message"])
    lemmas = [t.lemma_.lower() for t in doc if not t.is_stop and t.is_alpha]
    nlp_sev = (
        "CRITICAL" if any(k in lemmas for k in CRITICAL_KW) else
        "WARNING"  if any(k in lemmas for k in WARNING_KW)  else
        "NORMAL"
    )
    event["nlp_severity"] = max(
        [event["level"], nlp_sev],
        key=lambda s: SEV_RANK.get(s, 0)
    )
    event["keywords"] = [k for k in CRITICAL_KW + WARNING_KW if k in lemmas]
    event["entities"] = [(e.text, e.label_) for e in doc.ents]
    return event


# ===========================================================================
# COLLECTE LOKI
# ===========================================================================

def _fetch_loki_nodes(retries: int = 3) -> list[str]:
    """FIX 2 : retry sur erreurs 500 temporaires."""
    for attempt in range(retries):
        try:
            r = requests.get(LOKI_LABELS_URL, timeout=10)
            r.raise_for_status()
            return r.json().get("data", [])
        except Exception as e:
            log.warning("Loki nodes fetch failed (tentative %d/%d): %s",
                        attempt + 1, retries, e)
            if attempt < retries - 1:
                time.sleep(2)
    log.error("Loki inaccessible après %d tentatives", retries)
    return []


def _fetch_loki_streams(node: str) -> list[dict]:
    """Retourne tous les streams disponibles pour un noeud."""
    try:
        now_ns   = int(time.time() * 1e9)
        start_ns = now_ns - int(3600 * 1e9)
        r = requests.get(LOKI_SERIES_URL, params={
            "match[]": f'{{node="{node}"}}',
            "start":   start_ns,
            "end":     now_ns,
        }, timeout=10)
        r.raise_for_status()
        return r.json().get("data", [])
    except Exception as e:
        log.warning("Loki series failed for node=%s: %s", node, e)
        return []


def _fetch_new_logs_for_file(node: str, filename: str,
                              duration_sec: int = None) -> list[str]:
    """Récupère les nouvelles lignes d'un fichier — curseur glissant."""
    now_ns   = int(time.time() * 1e9)
    key      = (node, filename)

    if duration_sec:
        start_ns = now_ns - int(duration_sec * 1e9)
    else:
        start_ns = _LAST_TS.get(key, now_ns - int(POLL_WINDOW * 1e9)) + 1

    try:
        r = requests.get(LOKI_QUERY_URL, params={
            "query": f'{{node="{node}",filename="{filename}"}}',
            "start": start_ns,
            "end":   now_ns,
            "limit": LOKI_LIMIT,
        }, timeout=10)
        r.raise_for_status()

        raw_lines = []
        max_ts    = start_ns

        for stream in r.json().get("data", {}).get("result", []):
            for ts_ns_str, line in stream.get("values", []):
                ts_ns = int(ts_ns_str)
                raw_lines.append(line)
                if ts_ns > max_ts:
                    max_ts = ts_ns

        if raw_lines and not duration_sec:
            _LAST_TS[key] = max_ts

        return raw_lines

    except Exception as e:
        log.debug("Loki fetch failed node=%s file=%s: %s",
                  node, filename.split("/")[-1], e)
        return []


def _store_events(node: str, events: list[dict]):
    """Stocke les événements dans le buffer thread-safe."""
    with _LOCK:
        if node not in LOG_BUFFER:
            LOG_BUFFER[node] = deque(maxlen=BUFFER_SIZE)
        for e in events:
            LOG_BUFFER[node].append(e)


# ===========================================================================
# COLLECTE SYNCHRONE — FIX 5
# ===========================================================================

def collect_all_nodes(duration_sec: int = 120) -> dict:
    """
    FIX 5 : Collecte SYNCHRONE de tous les noeuds depuis Loki.
    Appelle directement Loki sans passer par le thread de polling.
    Remplit LOG_BUFFER immédiatement.
    Retourne : {"node": [events], ...}
    """
    result = {}

    # Récupérer tous les noeuds
    nodes = _fetch_loki_nodes(retries=3)
    if not nodes:
        log.warning("collect_all_nodes: aucun noeud trouvé dans Loki")
        return result

    now_ns   = int(time.time() * 1e9)
    start_ns = now_ns - int(duration_sec * 1e9)

    for node in nodes:
        # Récupérer les streams du noeud
        streams = _fetch_loki_streams(node)
        if not streams:
            continue

        # Trier — fichiers haute priorité en premier
        def _priority(s):
            fname = s.get("filename", "").split("/")[-1]
            return 0 if fname in HIGH_PRIORITY_FILES else 1

        streams_sorted = sorted(streams, key=_priority)
        node_events    = []

        for stream in streams_sorted:
            filename = stream.get("filename", "")
            if not filename:
                continue

            try:
                r = requests.get(LOKI_QUERY_URL, params={
                    "query": f'{{node="{node}",filename="{filename}"}}',
                    "start": start_ns,
                    "end":   now_ns,
                    "limit": LOKI_LIMIT,
                }, timeout=10)
                r.raise_for_status()

                for s in r.json().get("data", {}).get("result", []):
                    for ts_ns_str, line in s.get("values", []):
                        event = parse_log_line(line, node, filename)
                        if event is None:
                            continue
                        if event["category"] == "heartbeat":
                            continue
                        event = _enrich_with_spacy(event)
                        node_events.append(event)

            except Exception as e:
                log.debug("collect_all_nodes fetch node=%s file=%s: %s",
                          node, filename.split("/")[-1], e)

        if node_events:
            _store_events(node, node_events)
            result[node] = node_events

            critical = [e for e in node_events
                        if e.get("nlp_severity") in ("CRITICAL", "ERROR")]
            if critical:
                log.warning(
                    "🔴 Loki sync [%s] : %d events | %d critiques | fichiers: %s",
                    node, len(node_events), len(critical),
                    list({e.get("filename", "?") for e in critical})
                )
            else:
                log.info("Loki sync [%s] : %d events", node, len(node_events))
        else:
            log.debug("Loki sync [%s] : aucun événement", node)

    return result


# ===========================================================================
# THREAD DE POLLING — FIX 3 : cache streams TTL 60s
# ===========================================================================

_polling_active = False
_polling_thread = None

_STREAMS_CACHE: dict[str, list] = {}
_STREAMS_LAST_UPDATE = 0.0
_STREAMS_TTL = 60


def _refresh_streams_cache(nodes: list[str]):
    global _STREAMS_LAST_UPDATE
    now = time.time()
    if now - _STREAMS_LAST_UPDATE < _STREAMS_TTL:
        return
    for node in nodes:
        streams = _fetch_loki_streams(node)
        _STREAMS_CACHE[node] = streams
        log.info("Streams [%s] : %d fichiers", node, len(streams))
    _STREAMS_LAST_UPDATE = now


def _polling_worker():
    """Thread de polling — toutes les 5s, tous les fichiers."""
    log.info("Polling Loki démarré — intervalle=%ds", POLL_INTERVAL)
    _get_nlp()  # initialiser spaCy une seule fois

    while _polling_active:
        cycle_start = time.time()
        try:
            nodes = _fetch_loki_nodes(retries=3)
            if nodes:
                _refresh_streams_cache(nodes)
                for node in nodes:
                    streams = _STREAMS_CACHE.get(node, []) or _fetch_loki_streams(node)

                    def _priority(s):
                        fname = s.get("filename", "").split("/")[-1]
                        return 0 if fname in HIGH_PRIORITY_FILES else 1

                    all_events = []
                    for stream in sorted(streams, key=_priority):
                        filename = stream.get("filename", "")
                        if not filename:
                            continue
                        for raw in _fetch_new_logs_for_file(node, filename):
                            event = parse_log_line(raw, node, filename)
                            if event is None or event["category"] == "heartbeat":
                                continue
                            event = _enrich_with_spacy(event)
                            all_events.append(event)

                    if all_events:
                        _store_events(node, all_events)
                        critical = [e for e in all_events
                                    if e.get("nlp_severity") in ("CRITICAL", "ERROR")]
                        if critical:
                            log.warning("🔴 [%s] %d critiques | %s",
                                        node, len(critical),
                                        list({e["filename"] for e in critical}))
        except Exception as e:
            log.error("Erreur cycle polling: %s", e)

        elapsed    = time.time() - cycle_start
        sleep_time = max(0, POLL_INTERVAL - elapsed)
        time.sleep(sleep_time)

    log.info("Polling Loki arrêté")


def start_polling():
    """Démarre le thread de polling (idempotent)."""
    global _polling_active, _polling_thread
    if _polling_active and _polling_thread and _polling_thread.is_alive():
        return
    _polling_active = True
    _polling_thread = threading.Thread(
        target=_polling_worker, name="loki-polling", daemon=True,
    )
    _polling_thread.start()
    log.info("Thread polling Loki démarré")


def stop_polling():
    global _polling_active
    _polling_active = False
    if _polling_thread:
        _polling_thread.join(timeout=10)


def is_polling_active() -> bool:
    return (
        _polling_active and
        _polling_thread is not None and
        _polling_thread.is_alive()
    )


# ===========================================================================
# API PUBLIQUE
# ===========================================================================

def get_log_signals(node: str, last_n: int = 50) -> list:
    with _LOCK:
        return list(LOG_BUFFER.get(node, []))[-last_n:]


def get_critical_signals(node: str) -> list:
    return [
        e for e in get_log_signals(node)
        if e.get("nlp_severity") in ("CRITICAL", "ERROR")
        or e.get("level") in ("CRITICAL", "ERROR")
    ]


def get_alarm_signals(node: str) -> list:
    return [
        e for e in get_log_signals(node)
        if e.get("category") in ("alarm", "occ_alarm", "sm_alarm")
    ]


def get_signals_by_file(node: str, filename: str) -> list:
    basename = filename.split("/")[-1]
    return [e for e in get_log_signals(node) if e.get("filename") == basename]


def get_all_nodes_summary() -> dict:
    with _LOCK:
        summary = {}
        for node, buf in LOG_BUFFER.items():
            events   = list(buf)
            critical = [e for e in events
                        if e.get("nlp_severity") in ("CRITICAL", "ERROR")]
            warning  = [e for e in events if e.get("nlp_severity") == "WARNING"]

            files_breakdown = {}
            for e in events:
                fname = e.get("filename", "unknown")
                if fname not in files_breakdown:
                    files_breakdown[fname] = {"total": 0, "critical": 0}
                files_breakdown[fname]["total"] += 1
                if e.get("nlp_severity") in ("CRITICAL", "ERROR"):
                    files_breakdown[fname]["critical"] += 1

            summary[node] = {
                "total":           len(events),
                "critical_count":  len(critical),
                "warning_count":   len(warning),
                "files_monitored": len(files_breakdown),
                "files_breakdown": files_breakdown,
                "last_event":      events[-1]["timestamp"] if events else None,
                "last_critical":   critical[-1]["message"] if critical else None,
            }
        return summary


# ===========================================================================
# MAIN
# ===========================================================================
if __name__ == "__main__":
    import json
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    print("=== Polling Loki — TOUS les fichiers (5s) — Ctrl+C pour arrêter ===")
    start_polling()

    try:
        while True:
            time.sleep(15)
            print("\n=== Résumé buffer ===")
            summary = get_all_nodes_summary()
            if not summary:
                print("  (buffer vide — en attente)")
                continue
            for node, s in summary.items():
                print(f"\n📡 {node:<12} — {s['total']:>4} events "
                      f"| 🔴 {s['critical_count']:>3} critiques "
                      f"| 📁 {s['files_monitored']} fichiers")
                for fname, fs in sorted(s["files_breakdown"].items()):
                    if fs["total"] > 0:
                        crit = f"🔴 {fs['critical']}" if fs["critical"] else ""
                        print(f"   {fname:<40} total={fs['total']:<4} {crit}")
    except KeyboardInterrupt:
        stop_polling()
        print("\nArrêté.")
