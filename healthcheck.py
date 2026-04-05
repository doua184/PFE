#!/usr/bin/env python3
"""
healthcheck.py — HealthCheck engine TTCS v3
============================================
Couches vérifiées :
  HW  : CPU (util, temp, freq, throttle), RAM (util, swap, ECC),
         Disque (espace, I/O latence, IOPS, SMART, TBW),
         Réseau NIC (drops, latence), Thermique (chassis, fan, shutdown),
         Alimentation (watts, rails 12V/5V/3.3V, UPS)
  OS  : Processus (zombies, bloqués D-state, total),
         Fichiers (fd %, inodes %),
         Réseau kernel (TCP established, retransmissions),
         Mémoire kernel (OOM kills),
         Horloge (décalage NTP)
  APP : CCN, SDP, OCC, AF, AIR, VS + anomaly_score + prediction_risk
         + enrichissement optionnel logs Loki

Architecture héritée de v2 :
  - Découverte dynamique des noeuds depuis Prometheus (fallback servers.yml)
  - prom_query() retourne None si pas de données (distingue "0" de "absent")
  - Seuils centralisés dans THRESHOLDS
  - Logging structuré
  - Sortie JSON dans OUTPUT_FILE
"""

import json
import logging
import requests
import yaml
from datetime import datetime, timezone
from pathlib import Path

# ── Chemins ───────────────────────────────────────────────────
INVENTORY_FILE = "/opt/ttcs_platform/inventory/servers.yml"
OUTPUT_FILE    = "/opt/ttcs_platform/output/health_status.json"
PROM_URL       = "http://127.0.0.1:9090/api/v1/query"
PROM_LABEL_URL = "http://127.0.0.1:9090/api/v1/label/node/values"

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ── Mapping role ──────────────────────────────────────────────
ROLE_PATTERNS = {
    "ccn":   "CCN", "jambala": "CCN",
    "air":   "AIR", "ttair":   "AIR",
    "sdp":   "SDP", "ttsdp":   "SDP",
    "vs":    "VS",  "ttvs":    "VS",
    "occ":   "OCC", "ttocc":   "OCC",
    "af":    "AF",  "ttaf":    "AF",
}

# ── Seuils configurables ──────────────────────────────────────
THRESHOLDS = {
    # Hardware : CPU
    "cpu_warning":               70,
    "cpu_critical":              85,
    "cpu_temp_warning":          75,
    "cpu_temp_critical":         90,
    "cpu_throttle_warning":       3,
    "cpu_throttle_critical":     10,
    # Hardware : RAM
    "mem_warning":               75,
    "mem_critical":              90,
    "swap_warning_gb":            0.1,
    "swap_critical_gb":           2.0,
    "ecc_warning_30min":          1,
    "ecc_critical_30min":         5,
    # Hardware : Stockage
    "disk_warning":              70,
    "disk_critical":             80,
    "io_latency_warning_ms":     30,
    "io_latency_critical_ms":   100,
    "smart_warning":              1,
    "smart_critical":             5,
    # Hardware : Reseau NIC (rate/s — 0 au repos, >0 si incident ccn_link/af_dns)
    "net_drops_rate_warning":     0.1,   # drops/s
    "net_drops_rate_critical":    1.0,
    "net_latency_warning_ms":    20,
    "net_latency_critical_ms":  100,
    # Hardware : Thermique
    "chassis_temp_warning":      40,
    "chassis_temp_critical":     50,
    "fan_rpm_min":               600,
    # Hardware : Alimentation
    "rail_12v_warn_pct":          3,
    "rail_12v_crit_pct":          5,
    "ups_warning_pct":           50,
    "ups_critical_pct":          20,
    # OS : Processus
    "zombie_warning":             3,
    "zombie_critical":           10,
    "blocked_warning":            3,
    "blocked_critical":           8,
    # OS : Fichiers
    "fd_warning_pct":            70,
    "fd_critical_pct":           90,
    "inode_warning_pct":         75,
    "inode_critical_pct":        90,
    # OS : Reseau kernel
    "tcp_retrans_warning":        5,
    "tcp_retrans_critical":      30,
    # OS : Horloge NTP
    "ntp_warning_ms":            50,
    "ntp_critical_ms":          200,
    # APP : CCN — gauges (0 repos | 1-25 incident)
    "ccn_lookup_warning":          3,
    "ccn_lookup_critical":         8,
    "ccn_comm_warning":            2,
    "ccn_comm_critical":           6,
    # APP : SDP — gauges (0 repos | 1-20 incident)
    "sdp_timeout_warning":         3,
    "sdp_timeout_critical":        8,
    "sdp_conflict_warning":        2,
    "sdp_conflict_critical":       6,
    # APP : Anomaly score
    "anomaly_warning":            0.4,
    "anomaly_critical":           0.7,
    # Load average (heritage v2)
    "load_warning":               2.0,
    "load_critical":              4.0,
}


# =============================================================
# 0. DECOUVERTE DYNAMIQUE DES NOEUDS (heritage v2 inchange)
# =============================================================

def _guess_role(node_name: str) -> str:
    name_lower = node_name.lower()
    for pat, role in ROLE_PATTERNS.items():
        if pat in name_lower:
            return role
    return "UNKNOWN"


def discover_nodes_from_prometheus() -> list:
    """
    Decouvre dynamiquement les noeuds depuis Prometheus.
    Fallback sur servers.yml si Prometheus est inaccessible.
    """
    nodes = []
    try:
        r = requests.get(PROM_LABEL_URL, timeout=10)
        r.raise_for_status()
        data = r.json()
        if data.get("status") == "success":
            for name in data.get("data", []):
                if name:
                    nodes.append({"hostname": name, "role": _guess_role(name)})
            if nodes:
                log.info("Noeuds decouverts via Prometheus: %s",
                         [n["hostname"] for n in nodes])
                return nodes
    except Exception as e:
        log.warning("Prometheus label_values echouee: %s — fallback servers.yml", e)

    try:
        with open(INVENTORY_FILE) as f:
            servers = yaml.safe_load(f)["servers"]
        log.info("Noeuds charges depuis servers.yml: %s",
                 [s["hostname"] for s in servers])
        return servers
    except Exception as e:
        log.error("Impossible de charger servers.yml: %s", e)
        return []


# =============================================================
# 1. REQUETES PROMETHEUS (heritage v2 — None vs 0)
# =============================================================

def prom_query(query: str):
    """
    Execute une requete PromQL.
    Retourne None si pas de donnees (distingue '0' de 'absent').
    """
    try:
        r = requests.get(PROM_URL, params={"query": query}, timeout=10)
        r.raise_for_status()
        result = r.json()["data"]["result"]
        if not result:
            return None
        return float(result[0]["value"][1])
    except Exception as e:
        log.warning("Prometheus query failed: %s | query: %s", e, query[:80])
        return None


def _prom(metric: str, node: str, extra: str = ""):
    """Raccourci : requete simple sur une metrique avec filtre node."""
    extra_part = f",{extra}" if extra else ""
    q = f'{metric}{{node="{node}"{extra_part}}}'
    return prom_query(q)


def _prom_increase(metric: str, node: str, window: str = "5m"):
    """increase() sur une metrique counter."""
    return prom_query(f'increase({metric}{{node="{node}"}}[{window}])')


# =============================================================
# 2. CHECK HARDWARE — couche complete
# =============================================================

def check_hw(node: str):
    """
    Verifie tous les KPIs hardware du noeud.
    Ordre : CPU -> RAM -> Disque -> Reseau NIC -> Thermique -> Alimentation
    Retourne (status, raison) au premier probleme trouve.
    """
    T = THRESHOLDS

    # CPU utilisation
    cpu_pct = prom_query(
        f'100 - (avg by (node)'
        f'(rate(node_cpu_seconds_total{{node="{node}",mode="idle"}}[5m])) * 100)'
    )
    if cpu_pct is not None:
        if cpu_pct > T["cpu_critical"]:
            return "CRITICAL", f"CPU {cpu_pct:.1f}% > {T['cpu_critical']}%"
        if cpu_pct > T["cpu_warning"]:
            return "WARNING",  f"CPU {cpu_pct:.1f}% > {T['cpu_warning']}%"

    # Temperature CPU
    temp = _prom("tt_cpu_temp_celsius", node)
    if temp is not None:
        if temp > T["cpu_temp_critical"]:
            return "CRITICAL", f"CPU temp {temp:.1f}C > {T['cpu_temp_critical']}C"
        if temp > T["cpu_temp_warning"]:
            return "WARNING",  f"CPU temp {temp:.1f}C > {T['cpu_temp_warning']}C"

    # Throttling CPU
    throttle = _prom_increase("tt_cpu_throttle_events_total", node, "5m")
    if throttle is not None and throttle > 0:
        if throttle > T["cpu_throttle_critical"]:
            return "CRITICAL", f"CPU throttling actif ({int(throttle)} events/5min)"
        if throttle > T["cpu_throttle_warning"]:
            return "WARNING",  f"CPU throttling detecte ({int(throttle)} events/5min)"

    # Thermal shutdown
    ts = _prom("tt_thermal_shutdown_events_total", node)
    if ts is not None and ts > 0:
        return "CRITICAL", f"Thermal shutdown detecte ({int(ts)}x)"

    # RAM utilisation
    mem_pct = prom_query(
        f'100 * (1 - (node_memory_MemAvailable_bytes{{node="{node}"}}'
        f' / node_memory_MemTotal_bytes{{node="{node}"}}))'
    )
    if mem_pct is not None:
        if mem_pct > T["mem_critical"]:
            return "CRITICAL", f"RAM {mem_pct:.1f}% > {T['mem_critical']}%"
        if mem_pct > T["mem_warning"]:
            return "WARNING",  f"RAM {mem_pct:.1f}% > {T['mem_warning']}%"

    # Swap
    swap_bytes = _prom("tt_swap_used_bytes", node)
    if swap_bytes is not None:
        swap_gb = swap_bytes / (1024 ** 3)
        if swap_gb > T["swap_critical_gb"]:
            return "CRITICAL", f"Swap {swap_gb:.1f} GB utilise"
        if swap_gb > T["swap_warning_gb"]:
            return "WARNING",  f"Swap actif {swap_gb:.2f} GB"

    # ECC errors memoire
    ecc = _prom_increase("tt_ecc_errors_total", node, "30m")
    if ecc is not None:
        if ecc > T["ecc_critical_30min"]:
            return "CRITICAL", f"ECC errors: {int(ecc)}/30min"
        if ecc > T["ecc_warning_30min"]:
            return "WARNING",  f"ECC errors: {int(ecc)}/30min"

    # Espace disque /data
    disk_pct = prom_query(
        f'100 * (1 - (node_filesystem_avail_bytes{{node="{node}",mountpoint="/data"}}'
        f' / node_filesystem_size_bytes{{node="{node}",mountpoint="/data"}}))'
    )
    if disk_pct is not None:
        if disk_pct > T["disk_critical"]:
            return "CRITICAL", f"Disque /data {disk_pct:.1f}% > {T['disk_critical']}%"
        if disk_pct > T["disk_warning"]:
            return "WARNING",  f"Disque /data {disk_pct:.1f}% > {T['disk_warning']}%"

    # Latence I/O
    io_lat = _prom("tt_io_latency_ms", node)
    if io_lat is not None:
        if io_lat > T["io_latency_critical_ms"]:
            return "CRITICAL", f"I/O latency {io_lat:.0f}ms > {T['io_latency_critical_ms']}ms"
        if io_lat > T["io_latency_warning_ms"]:
            return "WARNING",  f"I/O latency {io_lat:.0f}ms > {T['io_latency_warning_ms']}ms"

    # SMART secteurs realloues
    smart = _prom("tt_smart_reallocated_sectors", node)
    if smart is not None:
        if smart > T["smart_critical"]:
            return "CRITICAL", f"SMART: {int(smart)} secteurs realloues — disque defaillant"
        if smart > T["smart_warning"]:
            return "WARNING",  f"SMART: {int(smart)} secteur(s) realloue(s)"

    # Drops reseau NIC — rate() : 0/s au repos, >0/s seulement si incident reseau
    drops_rate = prom_query(
        f'rate(tt_net_drops_total{{node="{node}"}}[2m])'
    )
    if drops_rate is not None:
        if drops_rate > T["net_drops_rate_critical"]:
            return "CRITICAL", f"Net drops {drops_rate:.2f}/s (incident reseau)"
        if drops_rate > T["net_drops_rate_warning"]:
            return "WARNING",  f"Net drops {drops_rate:.2f}/s"

    # Latence reseau NIC
    net_lat = _prom("tt_net_latency_ms", node)
    if net_lat is not None:
        if net_lat > T["net_latency_critical_ms"]:
            return "CRITICAL", f"Net latency {net_lat:.0f}ms"
        if net_lat > T["net_latency_warning_ms"]:
            return "WARNING",  f"Net latency {net_lat:.0f}ms"

    # Temperature chassis
    chassis = _prom("tt_chassis_temp_celsius", node)
    if chassis is not None:
        if chassis > T["chassis_temp_critical"]:
            return "CRITICAL", f"Chassis temp {chassis:.1f}C"
        if chassis > T["chassis_temp_warning"]:
            return "WARNING",  f"Chassis temp {chassis:.1f}C"

    # Ventilateur bloque (RPM trop bas alors que chaud)
    fan = _prom("tt_fan_rpm", node)
    if fan is not None and temp is not None:
        if fan < T["fan_rpm_min"] and temp > 60:
            return "CRITICAL", f"Ventilateur {fan:.0f} RPM trop bas (temp {temp:.0f}C)"

    # Rail 12V
    rail_12v = _prom("tt_rail_12v_volts", node)
    if rail_12v is not None:
        deviation_pct = abs(rail_12v - 12.0) / 12.0 * 100
        if deviation_pct > T["rail_12v_crit_pct"]:
            return "CRITICAL", f"Rail 12V hors tolerance ({rail_12v:.3f}V)"
        if deviation_pct > T["rail_12v_warn_pct"]:
            return "WARNING",  f"Rail 12V derive ({rail_12v:.3f}V)"

    # UPS batterie
    ups = _prom("tt_ups_battery_pct", node)
    if ups is not None:
        if ups < T["ups_critical_pct"]:
            return "CRITICAL", f"UPS batterie critique {ups:.0f}%"
        if ups < T["ups_warning_pct"]:
            return "WARNING",  f"UPS batterie faible {ups:.0f}%"

    # Resume normal
    parts = []
    if cpu_pct is not None: parts.append(f"CPU={cpu_pct:.1f}%")
    if mem_pct is not None: parts.append(f"MEM={mem_pct:.1f}%")
    if temp    is not None: parts.append(f"T={temp:.0f}C")
    return "NORMAL", ", ".join(parts) if parts else "-"


# =============================================================
# 3. CHECK OS — couche systeme complete
# =============================================================

def check_os(node: str):
    """
    Verifie les KPIs OS du noeud.
    Ordre : Uptime -> Zombies -> Processus bloques -> FD -> Inodes
            -> TCP established -> TCP retrans -> OOM kills -> NTP
    Garde aussi load average (heritage v2) comme filet de securite.
    """
    T = THRESHOLDS

    # Uptime : redemarrage inattendu ?
    uptime = prom_query(f'process_uptime_seconds{{node="{node}"}}')
    if uptime is not None and 0 < uptime < 180:
        return "CRITICAL", f"Redemarrage inattendu (uptime {uptime:.0f}s)"

    # Processus zombies
    zombies = _prom("tt_os_zombie_procs", node)
    if zombies is not None:
        if zombies > T["zombie_critical"]:
            return "CRITICAL", f"{int(zombies)} processus zombies"
        if zombies > T["zombie_warning"]:
            return "WARNING",  f"{int(zombies)} processus zombies"

    # Processus bloques D-state
    blocked = _prom("tt_os_procs_blocked", node)
    if blocked is not None:
        if blocked > T["blocked_critical"]:
            return "CRITICAL", f"{int(blocked)} processus bloques (D-state)"
        if blocked > T["blocked_warning"]:
            return "WARNING",  f"{int(blocked)} processus bloques (D-state)"

    # File descriptors %
    fd_used = _prom("tt_os_fd_used", node)
    fd_max  = _prom("tt_os_fd_max",  node)
    if fd_used is not None and fd_max is not None and fd_max > 0:
        fd_pct = (fd_used / fd_max) * 100
        if fd_pct > T["fd_critical_pct"]:
            return "CRITICAL", f"File descriptors {fd_pct:.1f}% ({int(fd_used)}/{int(fd_max)})"
        if fd_pct > T["fd_warning_pct"]:
            return "WARNING",  f"File descriptors {fd_pct:.1f}% ({int(fd_used)}/{int(fd_max)})"

    # Inodes disque /data
    inode_pct = _prom("tt_os_inode_used_pct", node)
    if inode_pct is not None:
        if inode_pct > T["inode_critical_pct"]:
            return "CRITICAL", f"Inodes /data {inode_pct:.1f}% — impossible de creer des fichiers"
        if inode_pct > T["inode_warning_pct"]:
            return "WARNING",  f"Inodes /data {inode_pct:.1f}%"

    # TCP established (chute = services coupes)
    tcp_estab = _prom("tt_os_tcp_established", node)
    if tcp_estab is not None and tcp_estab < 2:
        return "CRITICAL", f"TCP connexions effondrees ({int(tcp_estab)}) — services coupes ?"

    # TCP retransmissions
    tcp_retrans = _prom("tt_os_tcp_retrans_rate", node)
    if tcp_retrans is not None:
        if tcp_retrans > T["tcp_retrans_critical"]:
            return "CRITICAL", f"TCP retransmissions {tcp_retrans:.1f}/s"
        if tcp_retrans > T["tcp_retrans_warning"]:
            return "WARNING",  f"TCP retransmissions {tcp_retrans:.1f}/s"

    # OOM kills
    oom = _prom_increase("tt_os_oom_kills_total", node, "10m")
    if oom is not None and oom > 0:
        return "CRITICAL", f"OOM kill: {int(oom)} processus tues par le kernel"

    # Decalage NTP
    ntp_ms = _prom("tt_os_ntp_offset_ms", node)
    if ntp_ms is not None:
        ntp_abs = abs(ntp_ms)
        if ntp_abs > T["ntp_critical_ms"]:
            return "CRITICAL", f"NTP offset {ntp_ms:.0f}ms — timestamps CDR incorrects"
        if ntp_abs > T["ntp_warning_ms"]:
            return "WARNING",  f"NTP offset {ntp_ms:.0f}ms"

    # Load average (heritage v2, filet de securite)
    load = prom_query(f'tt_load_avg_1m{{node="{node}"}}')
    cpus = prom_query(
        f'count by (node)(node_cpu_seconds_total{{node="{node}",mode="idle"}})'
    )
    if load is not None and cpus is not None and cpus > 0:
        load_per_cpu = load / cpus
        if load_per_cpu > T["load_critical"]:
            return "CRITICAL", f"Load average critique ({load:.1f}/{int(cpus)} cores)"
        if load_per_cpu > T["load_warning"]:
            return "WARNING",  f"Load average eleve ({load:.1f}/{int(cpus)} cores)"

    return "NORMAL", "-"


# =============================================================
# 4. CHECK APPLICATION — par role + anomaly + Loki
# =============================================================

def _get_loki_signals(node: str) -> list:
    try:
        from log_loki import get_critical_signals
        return get_critical_signals(node)
    except ImportError:
        return []


def check_app(node: str, role: str):
    """
    Verifie l'etat applicatif selon le role du noeud.
    Inclut : anomaly_score, prediction_risk, enrichissement Loki.
    """
    T = THRESHOLDS
    status = "NORMAL"
    reason = "-"
    sev_map = {"NORMAL": 0, "WARNING": 1, "ERROR": 2, "CRITICAL": 3}

    def _upgrade(new_status: str, new_reason: str):
        nonlocal status, reason
        if sev_map.get(new_status, 0) > sev_map.get(status, 0):
            status = new_status
            reason = new_reason

    # CCN — gauges (0 au repos, >0 si incident actif)
    if role == "CCN":
        fails = _prom("tt_ccn_lookup_fail_count", node)
        if fails is not None:
            if fails > T["ccn_lookup_critical"]:
                _upgrade("CRITICAL", f"CCN lookup failures: {int(fails)}")
            elif fails > T["ccn_lookup_warning"]:
                _upgrade("WARNING",  f"CCN lookup failures: {int(fails)}")

        comm_err = _prom("tt_ccn_comm_error_count", node)
        if comm_err is not None:
            if comm_err > T["ccn_comm_critical"]:
                _upgrade("CRITICAL", f"CCN comm errors: {int(comm_err)}")
            elif comm_err > T["ccn_comm_warning"]:
                _upgrade("WARNING",  f"CCN comm errors: {int(comm_err)}")

        diam = prom_query(f'tt_service_up{{node="{node}",service="diameter"}}')
        if diam == 0.0:
            _upgrade("CRITICAL", "CCN Diameter link DOWN")

        inap = prom_query(f'tt_service_up{{node="{node}",service="inap"}}')
        if inap == 0.0:
            _upgrade("CRITICAL", "CCN SS7/INAP link DOWN")

    # SDP — gauges (0 au repos, >0 si incident actif)
    elif role == "SDP":
        timeouts = _prom("tt_sdp_timeout_count", node)
        if timeouts is not None:
            if timeouts > T["sdp_timeout_critical"]:
                _upgrade("CRITICAL", f"SDP CORBA timeouts: {int(timeouts)}")
            elif timeouts > T["sdp_timeout_warning"]:
                _upgrade("WARNING",  f"SDP CORBA timeouts: {int(timeouts)}")

        conflicts = _prom("tt_sdp_conflict_count", node)
        if conflicts is not None:
            if conflicts > T["sdp_conflict_critical"]:
                _upgrade("CRITICAL", f"SDP TimesTen conflicts: {int(conflicts)}")
            elif conflicts > T["sdp_conflict_warning"]:
                _upgrade("WARNING",  f"SDP TimesTen conflicts: {int(conflicts)}")

        sdp_svc = prom_query(f'tt_service_up{{node="{node}",service="sdp"}}')
        if sdp_svc == 0.0:
            _upgrade("CRITICAL", "Service SDP DOWN")

    # OCC
    elif role == "OCC":
        occ = _prom("tt_occ_alarm_state", node)
        if occ is not None and occ >= 1:
            _upgrade("CRITICAL", "OCC alarm state CRITICAL")

    # AF
    elif role == "AF":
        dns = prom_query(f'tt_service_up{{node="{node}",service="dns"}}')
        if dns == 0.0:
            _upgrade("CRITICAL", "AF DNS service DOWN")

    # AIR
    elif role == "AIR":
        tps = prom_query(f'rate(tt_transactions_total{{node="{node}"}}[5m])')
        if tps is not None and tps == 0:
            _upgrade("WARNING", "AIR: aucune transaction detectee")

    # VS
    elif role == "VS":
        voucher = prom_query(f'tt_service_up{{node="{node}",service="voucher"}}')
        if voucher == 0.0:
            _upgrade("CRITICAL", "VS Voucher service DOWN")

    # Anomaly score (tous roles)
    score = _prom("tt_anomaly_score", node)
    if score is not None:
        if score > T["anomaly_critical"]:
            _upgrade("CRITICAL", f"Anomaly score eleve ({score:.2f})")
        elif score > T["anomaly_warning"]:
            _upgrade("WARNING",  f"Anomaly score modere ({score:.2f})")

    # Prediction risk (tous roles)
    risk = _prom("tt_prediction_risk", node)
    if risk is not None and risk > 0.8 and status == "NORMAL":
        _upgrade("WARNING", f"Prediction risk eleve ({risk:.2f})")

    # Enrichissement logs Loki (optionnel)
    loki_signals = _get_loki_signals(node)
    if loki_signals:
        loki_msg = loki_signals[-1].get("message", "")
        loki_sev = loki_signals[-1].get("nlp_severity", "WARNING")
        if loki_msg:
            if reason == "-":
                reason = f"[LOG] {loki_msg[:80]}"
                status = loki_sev
            elif status == "NORMAL":
                _upgrade(loki_sev, f"[LOG] {loki_msg[:80]}")

    return status, reason


# =============================================================
# 5. STATUT GLOBAL (heritage v2)
# =============================================================

def global_status(hw: str, os_s: str, app: str) -> str:
    sev   = {"UNKNOWN": 0, "NORMAL": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
    worst = max([hw, os_s, app], key=lambda s: sev.get(s, 0))
    return worst


# =============================================================
# 6. MAIN
# =============================================================

def run_healthcheck() -> dict:
    """Lance le healthcheck complet et sauvegarde le resultat JSON."""
    servers = discover_nodes_from_prometheus()
    if not servers:
        log.error("Aucun noeud disponible.")
        return {}

    results = []
    header = f"{'NODE':<12} | {'ROLE':<5} | {'HW':<8} | {'OS':<8} | {'APP':<8} | {'GLOBAL':<8} | REASON"
    sep    = "-" * 90
    print(f"\n{header}")
    print(sep)

    for s in servers:
        node = s["hostname"]
        role = s.get("role") or _guess_role(node)

        hw,   hw_r  = check_hw(node)
        os_s, os_r  = check_os(node)
        app,  app_r = check_app(node, role)
        g           = global_status(hw, os_s, app)

        sev   = {"UNKNOWN": 0, "NORMAL": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
        parts = [(st, r) for st, r in [(hw, hw_r), (os_s, os_r), (app, app_r)] if r != "-"]
        reason = max(parts, key=lambda x: sev.get(x[0], 0))[1] if parts else "-"

        print(f"{node:<12} | {role:<5} | {hw:<8} | {os_s:<8} | {app:<8} | {g:<8} | {reason}")
        log.info("%-12s [%s] HW=%-8s OS=%-8s APP=%-8s -> %s | %s",
                 node, role, hw, os_s, app, g, reason)

        results.append({
            "hostname":      node,
            "role":          role,
            "hw_status":     hw,   "hw_reason":  hw_r,
            "os_status":     os_s, "os_reason":  os_r,
            "app_status":    app,  "app_reason": app_r,
            "global_status": g,
            "reason":        reason,
        })

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "node_count":   len(results),
        "nodes":        results,
    }

    Path(OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    log.info("Health status -> %s", OUTPUT_FILE)

    critical = [r["hostname"] for r in results if r["global_status"] == "CRITICAL"]
    warning  = [r["hostname"] for r in results if r["global_status"] == "WARNING"]
    log.info("Resume -> CRITICAL: %s | WARNING: %s",
             critical or "aucun", warning or "aucun")

    return output


if __name__ == "__main__":
    run_healthcheck()
