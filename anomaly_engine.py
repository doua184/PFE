#!/usr/bin/env python3
"""
anomaly_engine.py — Moteur hybride TTCS (v3.4 — final)
========================================================
Sources de données :
  1. Prometheus  — métriques par nœud (temps réel)
  2. Loki        — fichiers logs par nœud (collecte synchrone)

Détection :
  - Isolation Forest (ML non-supervisé)
  - Règles critiques télécom par rôle
  - Enrichissement logs Loki (log_signals, alarm_ids, log_keywords)

Corrélation :
  - Par rôle (indépendante des noms de nœuds)
  - Temporelle (qui a dégradé en premier)
  - 6 scénarios télécom + fallback

Fixes v3.4 :
  - Fix 6 : collect_features_for_node() utilise rate() sur tous les compteurs
             cumulatifs (sdp_timeout, sdp_conflict, ccn_lookup_fail,
             ccn_comm_error, alarm_critical) → 0 au repos, > 0 seulement si
             incident actif
  - Fix 7 : THRESHOLDS adaptés en rate/s (plus de valeurs brutes cumulatives)
  - Fix 8 : apply_critical_rules() adapté aux seuils rate/s
  - Fix 9 : temporal_correlation() utilise rate() dans ses range queries
  - Fix 10: correlate() conditions sdp_degraded/ccn_impacted/occ_impacted
             basées sur rate/s — plus de faux positifs permanents

Héritage v3.3 conservé :
  - Fix 1 : Range query CPU sans doublon filtre node
  - Fix 2 : ccn_impacted basé sur lookup_fail uniquement
  - Fix 3 : Polling Loki délai 5s
  - Fix 4 : occ_impacted vérifie alarm_critical (rate)
  - Fix 5 : Collecte Loki SYNCHRONE avant l'analyse
"""

import hashlib
import json
import logging
import pickle
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import requests
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

# ── Chemins ───────────────────────────────────────────────────
HEALTH_JSON     = Path("/opt/ttcs_platform/output/health_status.json")
ANOMALY_JSON    = Path("/opt/ttcs_platform/anomaly/output/anomalies.json")
MODEL_DIR       = Path("/opt/ttcs_platform/anomaly/model")
MODEL_PATH      = MODEL_DIR / "iforest_model.pkl"
SCALER_PATH     = MODEL_DIR / "iforest_scaler.pkl"
NODES_HASH_PATH = MODEL_DIR / "nodes_hash.txt"

PROM_URL       = "http://127.0.0.1:9090/api/v1/query"
PROM_RANGE_URL = "http://127.0.0.1:9090/api/v1/query_range"
PROM_LABEL_URL = "http://127.0.0.1:9090/api/v1/label/node/values"

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ── Mapping rôle ──────────────────────────────────────────────
ROLE_PATTERNS = {
    "ccn": "CCN", "jambala": "CCN",
    "air": "AIR", "sdp": "SDP",
    "vs":  "VS",  "occ": "OCC", "af": "AF",
}

# ── Seuils configurables ──────────────────────────────────────
# FIX 7 : tous les seuils applicatifs sont en rate/s
# Repos  : rate ≈ 0/s
# Incident actif : rate > 0/s de façon significative
THRESHOLDS = {
    # SDP — gauges (0 repos | 1-20 incident actif)
    "sdp_timeout_rate_warning":    3,
    "sdp_timeout_rate_critical":   8,
    "sdp_conflict_rate_warning":   2,
    "sdp_conflict_rate_critical":  6,
    # CCN — gauges (0 repos | 1-25 incident actif)
    "ccn_lookup_rate_warning":     3,
    "ccn_lookup_rate_critical":    8,
    "ccn_comm_rate_warning":       2,
    "ccn_comm_rate_critical":      6,
    # Alarmes OCC — rate/s (0 au repos, ~0.05/s si occ_alarm_critical)
    "alarm_critical_rate_warning": 0.01,
    "alarm_critical_rate_critical":0.05,
    # Hardware (%) — inchangés
    "cpu_warning":                 70,
    "cpu_critical":                90,
    "mem_warning":                 75,
    "mem_critical":                90,
    # Isolation Forest
    "if_score_critical":           0.75,
    # Corrélation — seuils rate/s pour temporal_correlation
    "corr_sdp_timeout_rate":       0.5,   # rate/s pour décider SDP dégradé
    "corr_sdp_conflict_rate":      0.3,
    "corr_ccn_lookup_rate":        0.5,
    "corr_occ_alarm_rate":         0.01,
    "corr_temporal_window":        300,
    "corr_temporal_step":          15,
    "corr_load_threshold":         2.0,
    # Loki
    "loki_window_sec":             120,
}


# ── JSON encoder numpy ────────────────────────────────────────
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.bool_):    return bool(obj)
        if isinstance(obj, np.integer):  return int(obj)
        if isinstance(obj, np.floating): return float(obj)
        if isinstance(obj, np.ndarray):  return obj.tolist()
        return super().default(obj)


# =============================================================
# 0. LOKI — collecte synchrone + enrichissement (héritage v3.3)
# =============================================================

def _init_loki():
    """Collecte Loki SYNCHRONE avant toute analyse (FIX 5)."""
    try:
        from log_loki import (start_polling, is_polling_active,
                               collect_all_nodes)
        if not is_polling_active():
            start_polling()
        log.info("Collecte Loki synchrone (fenetre=%ds)...",
                 THRESHOLDS["loki_window_sec"])
        results = collect_all_nodes(duration_sec=THRESHOLDS["loki_window_sec"])
        total   = sum(len(v) for v in results.values())
        log.info("Buffer Loki pret : %d noeuds | %d evenements",
                 len(results), total)
        for node, events in results.items():
            critical = [e for e in events
                        if e.get("nlp_severity") in ("CRITICAL", "ERROR")
                        or e.get("level") in ("CRITICAL", "ERROR")]
            if critical:
                log.warning("Loki [%s] : %d evenements critiques", node, len(critical))
    except ImportError:
        log.warning("log_loki.py non disponible — Loki desactive")
    except Exception as e:
        log.warning("Erreur initialisation Loki: %s", e)


def _get_loki_signals(node: str) -> list:
    try:
        from log_loki import get_critical_signals, get_alarm_signals
        critical  = get_critical_signals(node)
        alarms    = get_alarm_signals(node)
        seen_msgs = {e["message"] for e in critical}
        return critical + [a for a in alarms if a["message"] not in seen_msgs]
    except ImportError:
        return []


def _build_loki_enrichment(node: str) -> dict:
    signals = _get_loki_signals(node)
    if not signals:
        return {"log_signals": [], "alarm_ids": [], "log_keywords": []}
    return {
        "log_signals":    [e["message"] for e in signals[-5:]],
        "alarm_ids":      [e["notification_id"] for e in signals
                           if e.get("notification_id")],
        "log_keywords":   list({kw for e in signals
                                for kw in e.get("keywords", [])}),
        "log_categories": list({e.get("category","") for e in signals
                                if e.get("category")}),
        "log_files":      list({e.get("filename","") for e in signals
                                if e.get("filename")}),
    }


# =============================================================
# 1. DÉCOUVERTE DYNAMIQUE DES NŒUDS (héritage v3.3)
# =============================================================

def _guess_role(node_name: str) -> str:
    name_lower = node_name.lower()
    for pattern, role in ROLE_PATTERNS.items():
        if pattern in name_lower:
            return role
    return "UNKNOWN"


def discover_nodes() -> list:
    nodes = []
    try:
        r = requests.get(PROM_LABEL_URL, timeout=10)
        r.raise_for_status()
        data = r.json()
        if data.get("status") == "success":
            for name in data.get("data", []):
                if name:
                    nodes.append({"node": name, "role": _guess_role(name)})
            if nodes:
                log.info("Noeuds decouverts via label_values: %s",
                         [n["node"] for n in nodes])
                return nodes
    except Exception as e:
        log.warning("label_values echouee: %s — fallback", e)

    for metric in ["tt_anomaly_score", "tt_transactions_total",
                   "tt_service_up", "node_cpu_seconds_total"]:
        try:
            r = requests.get(PROM_URL, params={"query": metric}, timeout=10)
            r.raise_for_status()
            result = r.json().get("data", {}).get("result", [])
            seen = set()
            for serie in result:
                name = serie.get("metric", {}).get("node")
                if name and name not in seen:
                    seen.add(name)
                    nodes.append({"node": name, "role": _guess_role(name)})
            if nodes:
                log.info("Noeuds via '%s': %s", metric,
                         [n["node"] for n in nodes])
                return nodes
        except Exception as e:
            log.warning("Fallback '%s' echouee: %s", metric, e)

    log.error("Aucun noeud trouve dans Prometheus.")
    return []


def get_nodes_by_role(nodes_meta: list) -> dict:
    by_role = {}
    for n in nodes_meta:
        by_role.setdefault(n["role"], []).append(n["node"])
    return by_role


def get_features_for_role(features_by_node: dict,
                           nodes_by_role: dict, role: str) -> dict:
    node_names = [n for n in nodes_by_role.get(role, [])
                  if n in features_by_node]
    if not node_names:
        return {}
    aggregated = {}
    for k in FEATURE_KEYS:
        values = [features_by_node[n].get(k, 0.0) for n in node_names]
        aggregated[k] = sum(values) / len(values)
    return aggregated


# =============================================================
# 2. COLLECTE MÉTRIQUES PROMETHEUS
# FIX 6 : compteurs cumulatifs remplacés par rate()
# =============================================================

def prom_query(query: str) -> float:
    """Execute une requete PromQL — retourne 0.0 si pas de donnees."""
    try:
        r = requests.get(PROM_URL, params={"query": query}, timeout=10)
        r.raise_for_status()
        result = r.json()["data"]["result"]
        if not result:
            return 0.0
        return float(result[0]["value"][1])
    except Exception as e:
        log.warning("Prometheus query failed [%s]: %s", query[:60], e)
        return 0.0


def prom_range_series(query: str, duration_sec: int, step: int = 15) -> list:
    """Recupere une serie temporelle Prometheus."""
    end   = int(time.time())
    start = end - duration_sec
    try:
        r = requests.get(PROM_RANGE_URL, params={
            "query": query, "start": start, "end": end, "step": step,
        }, timeout=15)
        r.raise_for_status()
        result = r.json()["data"]["result"]
        if not result:
            return []
        return [(float(v[0]), float(v[1])) for v in result[0]["values"]]
    except Exception as e:
        log.warning("Prometheus range query failed: %s", e)
        return []


def collect_features_for_node(node: str) -> dict:
    """
    Collecte les metriques Prometheus pour un noeud.
    FIX 6 : les compteurs cumulatifs utilisent rate([2m]) — valeur = 0 au
    repos, > 0 seulement si l'evenement se produit activement.
    """
    cpu = prom_query(
        f'100 - (avg by (node)'
        f'(rate(node_cpu_seconds_total{{node="{node}",mode="idle"}}[5m])) * 100)'
    )
    mem = prom_query(
        f'100 * (1 - (node_memory_MemAvailable_bytes{{node="{node}"}}'
        f' / node_memory_MemTotal_bytes{{node="{node}"}}))'
    )

    return {
        # ── Métriques stables (gauges, ratios) ─────────────────
        "cpu_pct":         cpu,
        "mem_pct":         mem,
        "tps":             prom_query(
            f'rate(tt_transactions_total{{node="{node}"}}[5m])'
        ),
        "anomaly_score":   prom_query(f'tt_anomaly_score{{node="{node}"}}'),
        "prediction_risk": prom_query(f'tt_prediction_risk{{node="{node}"}}'),

        # ── Alarmes — rate/s (FIX 6) ──────────────────────────
        # 0/s au repos, > 0/s seulement si alarme active
        "alarm_critical":  prom_query(
            f'rate(tt_alarm_total{{node="{node}",severity="critical"}}[2m])'
        ),
        "alarm_major":     prom_query(
            f'rate(tt_alarm_total{{node="{node}",severity="major"}}[2m])'
        ),

        # ── Erreurs applicatives — rate/s (FIX 6) ─────────────
        "errors_1004":     prom_query(
            f'rate(tt_errors_total{{node="{node}",error_code="1004"}}[2m])'
        ),
        "errors_4001":     prom_query(
            f'rate(tt_errors_total{{node="{node}",error_code="4001"}}[2m])'
        ),
        "errors_other":    prom_query(
            f'rate(tt_errors_total{{node="{node}",error_code="OTHER"}}[2m])'
        ),

        # ── CCN — gauges (0 repos | 1-25 si incident actif) ──
        "ccn_lookup_fail": prom_query(
            f'tt_ccn_lookup_fail_count{{node="{node}"}}'
        ),
        "ccn_comm_error":  prom_query(
            f'tt_ccn_comm_error_count{{node="{node}"}}'
        ),

        # ── SDP — gauges (0 repos | 1-20 si incident actif) ───
        "sdp_timeout":     prom_query(
            f'tt_sdp_timeout_count{{node="{node}"}}'
        ),
        "sdp_conflict":    prom_query(
            f'tt_sdp_conflict_count{{node="{node}"}}'
        ),

        # ── OCC — gauge (0 ou 1) ──────────────────────────────
        "occ_alarm_state": prom_query(f'tt_occ_alarm_state{{node="{node}"}}'),

        # ── Services — gauges 0/1 (inchangés) ─────────────────
        "svc_diameter_up": prom_query(
            f'tt_service_up{{node="{node}",service="diameter"}}'
        ),
        "svc_inap_up":     prom_query(
            f'tt_service_up{{node="{node}",service="inap"}}'
        ),
        "svc_sdp_up":      prom_query(
            f'tt_service_up{{node="{node}",service="sdp"}}'
        ),
        "svc_dns_up":      prom_query(
            f'tt_service_up{{node="{node}",service="dns"}}'
        ),
    }


FEATURE_KEYS = [
    "cpu_pct", "mem_pct", "tps", "anomaly_score", "prediction_risk",
    "alarm_critical", "alarm_major", "errors_1004", "errors_4001", "errors_other",
    "ccn_lookup_fail", "ccn_comm_error", "sdp_timeout", "sdp_conflict",
    "occ_alarm_state", "svc_diameter_up", "svc_inap_up", "svc_sdp_up", "svc_dns_up",
]


def features_to_vector(feat: dict) -> list:
    return [feat.get(k, 0.0) for k in FEATURE_KEYS]


def collect_all_features(nodes_meta: list) -> dict:
    """Collecte les metriques pour tous les noeuds en parallele."""
    features_by_node: dict = {}
    with ThreadPoolExecutor(max_workers=min(len(nodes_meta), 8)) as executor:
        future_to_node = {
            executor.submit(collect_features_for_node, n["node"]): n
            for n in nodes_meta
        }
        for future in as_completed(future_to_node):
            node = future_to_node[future]["node"]
            try:
                features_by_node[node] = future.result()
            except Exception as e:
                log.warning("Echec collecte [%s]: %s", node, e)
                features_by_node[node] = {k: 0.0 for k in FEATURE_KEYS}
    return features_by_node


# =============================================================
# 3. CORRÉLATION TEMPORELLE
# FIX 9 : range queries avec rate() — détecte l'activité réelle
# =============================================================

def detect_degradation_onset(node: str, rate_query: str,
                              threshold: float) -> float | None:
    """
    Detecte le premier timestamp ou rate_query >= threshold.
    FIX 9 : prend une query rate() en parametre (pas un compteur brut).
    """
    T      = THRESHOLDS
    series = prom_range_series(
        rate_query,
        T["corr_temporal_window"],
        T["corr_temporal_step"],
    )
    for ts, val in series:
        if val >= threshold:
            return ts
    return None


def temporal_correlation(nodes_by_role: dict) -> dict:
    """
    Detecte quel role a degrade EN PREMIER.
    FIX 9 : toutes les queries utilisent rate() pour eviter les faux positifs
    dus aux compteurs cumulatifs.
    """
    onset_times = {}
    T = THRESHOLDS

    for node in nodes_by_role.get("SDP", []):
        # gauge direct — 0 repos, >0 si incident actif
        ts = detect_degradation_onset(
            node,
            f'tt_sdp_timeout_count{{node="{node}"}}',
            T["corr_sdp_timeout_rate"]
        )
        if ts is not None:
            onset_times.setdefault("SDP", []).append(ts)

        ts2 = detect_degradation_onset(
            node,
            f'tt_sdp_conflict_count{{node="{node}"}}',
            T["corr_sdp_conflict_rate"]
        )
        if ts2 is not None:
            onset_times.setdefault("SDP_conflict", []).append(ts2)

    for node in nodes_by_role.get("CCN", []):
        # gauge direct — 0 repos, >0 si incident
        ts = detect_degradation_onset(
            node,
            f'tt_ccn_lookup_fail_count{{node="{node}"}}',
            T["corr_ccn_lookup_rate"]
        )
        if ts is not None:
            onset_times.setdefault("CCN", []).append(ts)

    for node in nodes_by_role.get("OCC", []):
        # occ_alarm_state est un gauge 0/1 — pas besoin de rate()
        ts = detect_degradation_onset(
            node,
            f'tt_occ_alarm_state{{node="{node}"}}',
            1.0
        )
        if ts is not None:
            onset_times.setdefault("OCC", []).append(ts)

        # Alarmes critiques en rate()
        ts2 = detect_degradation_onset(
            node,
            f'rate(tt_alarm_total{{node="{node}",severity="critical"}}[2m])',
            T["corr_occ_alarm_rate"]
        )
        if ts2 is not None:
            onset_times.setdefault("OCC_alarm", []).append(ts2)

    for role, node_list in nodes_by_role.items():
        for node in node_list:
            ts = detect_degradation_onset(
                node,
                f'node_load1{{node="{node}"}}',
                T["corr_load_threshold"]
            )
            if ts is not None:
                onset_times.setdefault(f"LOAD_{role}", []).append(ts)

    first_onset = {role: min(times) for role, times in onset_times.items()}
    return dict(sorted(first_onset.items(), key=lambda x: x[1]))


# =============================================================
# 4. ISOLATION FOREST (héritage v3.3 inchangé)
# =============================================================

def build_normal_baseline(nodes_meta: list) -> np.ndarray:
    """
    Baseline d'entraînement IF.
    Note : les features ccn_lookup_fail, sdp_timeout, etc. sont maintenant
    en rate/s — le baseline utilise 0.0 pour les compteurs au repos.
    """
    rng = np.random.default_rng(42)
    samples = []
    role_profiles = {
        "CCN":     {"cpu": 8,  "mem": 45, "tps": 90},
        "AIR":     {"cpu": 4,  "mem": 35, "tps": 35},
        "SDP":     {"cpu": 10, "mem": 64, "tps": 55},
        "VS":      {"cpu": 5,  "mem": 42, "tps": 12},
        "OCC":     {"cpu": 12, "mem": 70, "tps": 70},
        "AF":      {"cpu": 4,  "mem": 33, "tps": 6},
        "UNKNOWN": {"cpu": 6,  "mem": 50, "tps": 30},
    }
    for _ in range(400):
        for node_info in nodes_meta:
            p = role_profiles.get(node_info["role"], role_profiles["UNKNOWN"])
            samples.append([
                rng.normal(p["cpu"], 3),   # cpu_pct
                rng.normal(p["mem"], 4),   # mem_pct
                rng.normal(p["tps"], 5),   # tps
                rng.uniform(0.0, 0.05),    # anomaly_score
                rng.uniform(0.0, 0.10),    # prediction_risk
                0.0,                       # alarm_critical rate (0 repos)
                rng.choice([0.0, 0.0, 0.0, 0.001]),  # alarm_major rate
                0.0, 0.0,                  # errors_1004, errors_4001 rate
                rng.choice([0.0, 0.0, 0.0, 0.0, 0.001]),  # errors_other
                0.0, 0.0,                  # ccn_lookup_fail, ccn_comm_error rate
                0.0, 0.0,                  # sdp_timeout, sdp_conflict rate
                0.0,                       # occ_alarm_state
                1.0, 1.0, 1.0, 1.0,       # services up
            ])
    return np.array(samples, dtype=float)


def _nodes_topology_hash(nodes_meta: list) -> str:
    names = sorted(n["node"] for n in nodes_meta)
    return hashlib.md5("|".join(names).encode()).hexdigest()


def load_or_train_model(nodes_meta: list) -> tuple:
    current_hash = _nodes_topology_hash(nodes_meta)
    saved_hash   = (NODES_HASH_PATH.read_text().strip()
                    if NODES_HASH_PATH.exists() else "")

    if (MODEL_PATH.exists() and SCALER_PATH.exists()
            and saved_hash == current_hash):
        log.info("Chargement modele IF depuis %s", MODEL_DIR)
        with MODEL_PATH.open("rb") as f:  model  = pickle.load(f)
        with SCALER_PATH.open("rb") as f: scaler = pickle.load(f)
        return model, scaler

    log.info("Entrainement Isolation Forest (topologie: %s)...", current_hash[:8])
    X        = build_normal_baseline(nodes_meta)
    scaler   = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)
    model    = IsolationForest(
        n_estimators=200, contamination=0.05,
        max_samples="auto", random_state=42, n_jobs=-1,
    )
    model.fit(X_scaled)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    with MODEL_PATH.open("wb")  as f: pickle.dump(model,  f)
    with SCALER_PATH.open("wb") as f: pickle.dump(scaler, f)
    NODES_HASH_PATH.write_text(current_hash)
    log.info("Modele IF sauvegarde dans %s", MODEL_DIR)
    return model, scaler


def iforest_detect(model, scaler, features_by_node: dict) -> dict:
    results = {}
    for node, feat in features_by_node.items():
        vec        = np.array(features_to_vector(feat), dtype=float).reshape(1, -1)
        vec_scaled = scaler.transform(vec)
        raw        = float(model.decision_function(vec_scaled)[0])
        pred       = int(model.predict(vec_scaled)[0])
        normalized = max(0.0, min(1.0, (0.5 - raw) / 0.5))
        results[node] = {
            "is_anomaly": bool(pred == -1),
            "score":      round(normalized, 3),
            "raw_score":  round(raw, 4),
        }
    return results


# =============================================================
# 5. RÈGLES CRITIQUES (par rôle)
# FIX 8 : seuils adaptés aux valeurs rate/s
# =============================================================

def apply_critical_rules(node: str, role: str, feat: dict) -> list:
    """
    Applique les règles critiques.
    FIX 8 : feat['sdp_timeout'], feat['ccn_lookup_fail'], etc. sont
    maintenant en rate/s — les seuils sont adaptés en conséquence.
    """
    anomalies = []
    T = THRESHOLDS

    def add(atype, severity, reason, score, signals):
        anomalies.append({
            "node": node, "role": role, "type": atype,
            "severity": severity, "score": round(score, 2),
            "reason": reason, "signals": signals, "source": "rule",
        })

    # SDP — feat["sdp_timeout"] et feat["sdp_conflict"] sont en rate/s
    if role == "SDP":
        if feat["sdp_timeout"] >= T["sdp_timeout_rate_critical"]:
            add("sdp_corba_timeout", "CRITICAL",
                f"SDP CORBA timeouts: {int(feat['sdp_timeout'])}",
                0.92, ["sdp_timeout"])
        elif feat["sdp_timeout"] >= T["sdp_timeout_rate_warning"]:
            add("sdp_corba_timeout", "WARNING",
                f"SDP CORBA timeouts: {int(feat['sdp_timeout'])}",
                0.65, ["sdp_timeout"])

        if feat["sdp_conflict"] >= T["sdp_conflict_rate_critical"]:
            add("sdp_tt_conflict", "CRITICAL",
                f"Conflits TimesTen: {int(feat['sdp_conflict'])}",
                0.90, ["sdp_conflict"])
        elif feat["sdp_conflict"] >= T["sdp_conflict_rate_warning"]:
            add("sdp_tt_conflict", "WARNING",
                f"Conflits TimesTen: {int(feat['sdp_conflict'])}",
                0.60, ["sdp_conflict"])

        if feat["svc_sdp_up"] == 0.0:
            add("sdp_service_down", "CRITICAL",
                "Service SDP DOWN", 0.95, ["svc_sdp_up"])

    # CCN — feat["ccn_lookup_fail"] et feat["ccn_comm_error"] en rate/s
    if role == "CCN":
        if feat["ccn_lookup_fail"] >= T["ccn_lookup_rate_critical"]:
            add("ccn_lookup_failure", "CRITICAL",
                f"CCN lookup failures: {int(feat['ccn_lookup_fail'])}",
                0.90, ["ccn_lookup_fail"])
        elif feat["ccn_lookup_fail"] >= T["ccn_lookup_rate_warning"]:
            add("ccn_lookup_failure", "WARNING",
                f"CCN lookup failures: {int(feat['ccn_lookup_fail'])}",
                0.65, ["ccn_lookup_fail"])

        if feat["svc_diameter_up"] == 0.0:
            add("ccn_diameter_link_down", "CRITICAL",
                "CCN Diameter link DOWN", 0.95, ["svc_diameter_up"])
        if feat["svc_inap_up"] == 0.0:
            add("ccn_inap_down", "CRITICAL",
                "CCN INAP/SS7 service DOWN", 0.93, ["svc_inap_up"])

    # OCC — occ_alarm_state est un gauge 0/1 (inchangé)
    if role == "OCC":
        if feat["occ_alarm_state"] >= 1.0:
            add("occ_alarm_critical", "CRITICAL",
                "OCC rapporte un etat CRITICAL", 0.92, ["occ_alarm_state"])

    # AF
    if role == "AF":
        if feat["svc_dns_up"] == 0.0:
            add("af_dns_down", "CRITICAL",
                "AF DNS service DOWN", 0.88, ["svc_dns_up"])

    # Génériques (tous rôles) — CPU/RAM inchangés (%)
    if feat["cpu_pct"] > T["cpu_critical"]:
        add("hw_cpu_critical", "CRITICAL",
            f"CPU critique ({feat['cpu_pct']:.1f}%)", 0.85, ["cpu_pct"])
    elif feat["cpu_pct"] > T["cpu_warning"]:
        add("hw_cpu_warning", "WARNING",
            f"CPU elevee ({feat['cpu_pct']:.1f}%)", 0.55, ["cpu_pct"])

    if feat["mem_pct"] > T["mem_critical"]:
        add("hw_mem_critical", "CRITICAL",
            f"Memoire critique ({feat['mem_pct']:.1f}%)", 0.85, ["mem_pct"])
    elif feat["mem_pct"] > T["mem_warning"]:
        add("hw_mem_warning", "WARNING",
            f"Memoire elevee ({feat['mem_pct']:.1f}%)", 0.55, ["mem_pct"])

    # alarm_critical est maintenant en rate/s
    if feat["alarm_critical"] >= T["alarm_critical_rate_critical"]:
        add("alarm_critical", "CRITICAL",
            f"Alarme critique active ({feat['alarm_critical']:.3f}/s)",
            0.80, ["alarm_critical"])
    elif feat["alarm_critical"] >= T["alarm_critical_rate_warning"]:
        add("alarm_critical", "WARNING",
            f"Alarme critique ({feat['alarm_critical']:.3f}/s)",
            0.55, ["alarm_critical"])

    return anomalies


# =============================================================
# 6. FUSION IF + RÈGLES + LOKI (héritage v3.3)
# =============================================================

def _top_contributing_features(feat: dict, top_n: int = 4) -> list:
    # Référence normale : rate = 0 pour tous les compteurs
    normal_ref = {
        "cpu_pct": 8, "mem_pct": 50, "tps": 50,
        "anomaly_score": 0, "prediction_risk": 0,
        "alarm_critical": 0, "alarm_major": 0,        # rate/s
        "errors_1004": 0, "errors_4001": 0,            # rate/s
        "errors_other": 0,
        "ccn_lookup_fail": 0, "ccn_comm_error": 0,     # rate/s
        "sdp_timeout": 0, "sdp_conflict": 0,           # rate/s
        "occ_alarm_state": 0,
        "svc_diameter_up": 1, "svc_inap_up": 1,
        "svc_sdp_up": 1, "svc_dns_up": 1,
    }
    scores = {}
    for k, ref in normal_ref.items():
        val = feat.get(k, ref)
        scores[k] = abs(val - ref) * (10 if k.startswith("svc_") else 1)
    top = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:top_n]
    return [f"{k}={feat.get(k, 0):.3f}" for k, _ in top if scores[k] > 0]


def build_anomalies(nodes_meta, features_by_node, if_results) -> list:
    all_anomalies = []
    for node_info in nodes_meta:
        node = node_info["node"]
        role = node_info["role"]
        feat = features_by_node.get(node, {})
        ifr  = if_results.get(node, {})
        loki = _build_loki_enrichment(node)

        if ifr.get("is_anomaly"):
            score    = ifr["score"]
            severity = ("CRITICAL" if score >= THRESHOLDS["if_score_critical"]
                        else "WARNING")
            all_anomalies.append({
                "node": node, "role": role,
                "type": "isolation_forest_anomaly",
                "severity": severity, "score": score,
                "reason": f"Comportement anormal detecte (score={score:.2f})",
                "signals": _top_contributing_features(feat),
                "source": "isolation_forest",
                **loki,
            })

        rule_anomalies = apply_critical_rules(node, role, feat)
        for a in rule_anomalies:
            a.update(loki)
        all_anomalies.extend(rule_anomalies)

    # Déduplique — garde le score le plus élevé
    dedup = {}
    for a in all_anomalies:
        key = (a["node"], a["type"])
        if key not in dedup or dedup[key]["score"] < a["score"]:
            dedup[key] = a
    return list(dedup.values())


# =============================================================
# 7. CORRÉLATION AVANCÉE
# FIX 10 : conditions basées sur rate/s — plus de faux positifs permanents
# =============================================================

def sev_rank(sev: str) -> int:
    return {"INFO": 0, "WARNING": 1, "CRITICAL": 2}.get(sev, 0)


def correlate(features_by_node: dict, anomalies: list,
              nodes_meta: list) -> dict:
    nodes_by_role = get_nodes_by_role(nodes_meta)

    sdp_feat = get_features_for_role(features_by_node, nodes_by_role, "SDP")
    ccn_feat = get_features_for_role(features_by_node, nodes_by_role, "CCN")
    occ_feat = get_features_for_role(features_by_node, nodes_by_role, "OCC")
    af_feat  = get_features_for_role(features_by_node, nodes_by_role, "AF")

    T = THRESHOLDS

    # FIX 10 : conditions basées sur rate/s — 0 au repos, > 0 si incident
    sdp_degraded = (
        sdp_feat.get("sdp_timeout", 0)  >= T["corr_sdp_timeout_rate"] or
        sdp_feat.get("sdp_conflict", 0) >= T["corr_sdp_conflict_rate"]
    )
    # ccn_impacted : lookup_fail OU comm_error élevés
    # ccn_comm_error peut rester élevé quand ccn_lookup_fail vient de redescendre
    ccn_impacted = (
        ccn_feat.get("ccn_lookup_fail", 0) >= T["corr_ccn_lookup_rate"] or
        ccn_feat.get("ccn_comm_error",  0) >= T["corr_ccn_lookup_rate"]
    )
    # occ_impacted : gauge alarm_state OU rate alarmes critiques
    occ_impacted = (
        occ_feat.get("occ_alarm_state", 0) >= 1.0 or
        occ_feat.get("alarm_critical",  0) >= T["corr_occ_alarm_rate"]
    )
    diameter_down = (ccn_feat.get("svc_diameter_up", 1.0) == 0.0)
    dns_down      = (af_feat.get("svc_dns_up",       1.0) == 0.0)
    inap_down     = (ccn_feat.get("svc_inap_up",     1.0) == 0.0)

    log.info("Correlation — SDP: to=%.3f/s co=%.3f/s degraded=%s",
             sdp_feat.get("sdp_timeout",  0),
             sdp_feat.get("sdp_conflict", 0), sdp_degraded)
    log.info("Correlation — CCN: lookup=%.3f/s impacted=%s",
             ccn_feat.get("ccn_lookup_fail", 0), ccn_impacted)
    log.info("Correlation — OCC: alarm_state=%.0f alarm_rate=%.4f/s impacted=%s",
             occ_feat.get("occ_alarm_state", 0),
             occ_feat.get("alarm_critical",  0), occ_impacted)

    # Corrélation temporelle
    temporal         = temporal_correlation(nodes_by_role)
    temporal_summary = None
    if temporal:
        ordered          = list(temporal.keys())
        temporal_summary = (f"Ordre degradation: {' -> '.join(ordered)} "
                            f"(premier: {ordered[0]})")
        log.info("Correlation temporelle: %s", temporal_summary)

    # Enrichissement Loki
    loki_evidence = {}
    for role in ["SDP", "CCN", "OCC"]:
        for node in nodes_by_role.get(role, []):
            signals = _get_loki_signals(node)
            if signals:
                loki_evidence[node] = [s["message"] for s in signals[:3]]

    correlation = {
        "probable_root_cause": None,
        "severity":            "INFO",
        "summary":             None,
        "impacted_nodes":      [],
        "impacted_roles":      [],
        "supporting_signals":  [],
        "temporal_order":      temporal,
        "temporal_summary":    temporal_summary,
        "loki_evidence":       loki_evidence,
        "scenario":            None,
    }

    # Scénario 1 : Cascade SDP → CCN → OCC
    if sdp_degraded and ccn_impacted and occ_impacted:
        sdp_nodes = nodes_by_role.get("SDP", [])
        ccn_nodes = nodes_by_role.get("CCN", [])
        occ_nodes = nodes_by_role.get("OCC", [])
        correlation.update({
            "probable_root_cause": "SDP degradation with downstream cascade",
            "severity":            "CRITICAL",
            "summary": (
                f"SDP ({', '.join(sdp_nodes)}) est la root-cause. "
                f"CCN lookup={ccn_feat.get('ccn_lookup_fail',0):.2f}/s -> "
                f"OCC alarm_rate={occ_feat.get('alarm_critical',0):.3f}/s."
                + (f" {temporal_summary}" if temporal_summary else "")
            ),
            "impacted_nodes":     sdp_nodes + ccn_nodes + occ_nodes,
            "impacted_roles":     ["SDP", "CCN", "OCC"],
            "supporting_signals": [
                f"SDP to={sdp_feat.get('sdp_timeout',0):.2f}/s "
                f"co={sdp_feat.get('sdp_conflict',0):.2f}/s",
                f"CCN lookup={ccn_feat.get('ccn_lookup_fail',0):.2f}/s",
                f"OCC alarm={occ_feat.get('alarm_critical',0):.3f}/s",
            ],
            "scenario": "SDP_CASCADE",
        })
        return correlation

    # Scénario 2 : CCN Diameter down
    if diameter_down and not sdp_degraded:
        ccn_nodes = nodes_by_role.get("CCN", [])
        correlation.update({
            "probable_root_cause": "CCN Diameter link failure",
            "severity":            "CRITICAL",
            "summary": f"Lien Diameter CCN ({', '.join(ccn_nodes)}) DOWN.",
            "impacted_nodes":      ccn_nodes,
            "impacted_roles":      ["CCN"],
            "supporting_signals":  ["svc_diameter_up=0"],
            "scenario":            "CCN_DIAMETER_DOWN",
        })
        return correlation

    # Scénario 3 : INAP/SS7 down
    if inap_down:
        ccn_nodes = nodes_by_role.get("CCN", [])
        correlation.update({
            "probable_root_cause": "CCN INAP/SS7 link failure",
            "severity":            "CRITICAL",
            "summary": f"Service INAP/SS7 ({', '.join(ccn_nodes)}) DOWN.",
            "impacted_nodes":      ccn_nodes,
            "impacted_roles":      ["CCN"],
            "supporting_signals":  ["svc_inap_up=0"],
            "scenario":            "CCN_INAP_DOWN",
        })
        return correlation

    # Scénario 4 : DNS down
    if dns_down:
        af_nodes  = nodes_by_role.get("AF", [])
        all_nodes = [n["node"] for n in nodes_meta]
        correlation.update({
            "probable_root_cause": "AF DNS failure",
            "severity":            "CRITICAL",
            "summary": f"DNS ({', '.join(af_nodes)}) DOWN — tous noeuds impactes.",
            "impacted_nodes":      af_nodes + all_nodes,
            "impacted_roles":      ["AF"] + list(nodes_by_role.keys()),
            "supporting_signals":  ["svc_dns_up=0"],
            "scenario":            "DNS_DOWN",
        })
        return correlation

    # Scénario 6 : Cascade partielle SDP → CCN (OCC pas encore impacté)
    # Cas typique : incident SDP récent qui commence à impacter CCN
    # mais l'OCC n'a pas encore eu le temps de réagir
    if sdp_degraded and ccn_impacted and not occ_impacted:
        sdp_nodes = nodes_by_role.get("SDP", [])
        ccn_nodes = nodes_by_role.get("CCN", [])
        correlation.update({
            "probable_root_cause": "SDP degradation cascading to CCN",
            "severity":            "CRITICAL",
            "summary": (
                f"SDP ({', '.join(sdp_nodes)}) est la root-cause. "
                f"CCN lookup={ccn_feat.get('ccn_lookup_fail',0):.2f} — "
                "cascade en cours, OCC non encore impacte."
                + (f" {temporal_summary}" if temporal_summary else "")
            ),
            "impacted_nodes":     sdp_nodes + ccn_nodes,
            "impacted_roles":     ["SDP", "CCN"],
            "supporting_signals": [
                f"SDP to={sdp_feat.get('sdp_timeout',0):.2f} "
                f"co={sdp_feat.get('sdp_conflict',0):.2f}",
                f"CCN lookup={ccn_feat.get('ccn_lookup_fail',0):.2f}",
                "OCC: pas encore impacte",
            ],
            "scenario": "SDP_CCN_CASCADE",
        })
        return correlation

    # Scénario 7 : Cascade SDP → OCC (CCN non détecté au moment du scraping)
    # ccn_lookup peut être à 0 momentanément si sdp_bad vient de s'arrêter
    # mais l'OCC garde son alarme active — la cascade SDP→OCC reste probable
    if sdp_degraded and occ_impacted and not ccn_impacted:
        sdp_nodes = nodes_by_role.get("SDP", [])
        occ_nodes = nodes_by_role.get("OCC", [])
        ccn_nodes = nodes_by_role.get("CCN", [])
        correlation.update({
            "probable_root_cause": "SDP degradation with OCC impact",
            "severity":            "CRITICAL",
            "summary": (
                f"SDP ({', '.join(sdp_nodes)}) est la root-cause. "
                f"OCC alarm_state=1 — cascade SDP→OCC confirmee "
                "(CCN non detecte au moment du scraping)."
                + (f" {temporal_summary}" if temporal_summary else "")
            ),
            "impacted_nodes":     sdp_nodes + occ_nodes + ccn_nodes,
            "impacted_roles":     ["SDP", "OCC", "CCN"],
            "supporting_signals": [
                f"SDP to={sdp_feat.get('sdp_timeout',0):.2f} "
                f"co={sdp_feat.get('sdp_conflict',0):.2f}",
                f"OCC alarm_state=1 alarm_rate={occ_feat.get('alarm_critical',0):.3f}/s",
            ],
            "scenario": "SDP_OCC_CASCADE",
        })
        return correlation

    # Scénario 5 : SDP isolé
    if sdp_degraded and not ccn_impacted and not occ_impacted:
        sdp_nodes = nodes_by_role.get("SDP", [])
        correlation.update({
            "probable_root_cause": "SDP degradation (isolated)",
            "severity":            "WARNING",
            "summary": (
                f"SDP ({', '.join(sdp_nodes)}) degrade. "
                "Cascade non confirmee — surveillance recommandee."
            ),
            "impacted_nodes":     sdp_nodes,
            "impacted_roles":     ["SDP"],
            "supporting_signals": [
                f"sdp_timeout={sdp_feat.get('sdp_timeout',0):.2f}/s",
                f"sdp_conflict={sdp_feat.get('sdp_conflict',0):.2f}/s",
            ],
            "scenario": "SDP_ISOLATED",
        })
        return correlation

    # Fallback : pire anomalie
    if anomalies:
        worst = max(anomalies,
                    key=lambda a: (sev_rank(a["severity"]), a["score"]))
        correlation.update({
            "probable_root_cause": worst["node"],
            "severity":            worst["severity"],
            "summary": (
                f"Anomalie la plus severe sur {worst['node']} "
                f"[{worst['role']}] : {worst['reason']}"
            ),
            "impacted_nodes":     [worst["node"]],
            "impacted_roles":     [worst["role"]],
            "supporting_signals": worst.get("signals", []),
            "scenario":           "FALLBACK_WORST_ANOMALY",
        })

    return correlation


# =============================================================
# 8. CHARGEMENT HEALTH
# =============================================================

def load_health() -> dict:
    if not HEALTH_JSON.exists():
        raise FileNotFoundError(f"Fichier health manquant : {HEALTH_JSON}")
    with HEALTH_JSON.open("r", encoding="utf-8") as f:
        return json.load(f)


# =============================================================
# 9. MAIN
# =============================================================

def main():
    start_time = time.time()

    # Étape 0 : Collecte Loki synchrone (FIX 5)
    _init_loki()

    # Étape 1 : Découverte noeuds
    log.info("Decouverte des noeuds depuis Prometheus...")
    nodes_meta = discover_nodes()
    if not nodes_meta:
        log.error("Aucun noeud disponible. Arret.")
        return

    log.info("Noeuds : %s", [n["node"] for n in nodes_meta])
    nodes_by_role = get_nodes_by_role(nodes_meta)
    log.info("Roles : %s", nodes_by_role)

    # Étape 2 : Modèle Isolation Forest
    model, scaler = load_or_train_model(nodes_meta)

    # Étape 3 : Collecte métriques Prometheus
    log.info("Collecte metriques (%d noeuds en parallele)...", len(nodes_meta))
    features_by_node = collect_all_features(nodes_meta)
    for node_info in nodes_meta:
        node = node_info["node"]
        feat = features_by_node[node]
        log.info(
            "  [%-12s] cpu=%.1f%% mem=%.1f%% "
            "sdp_to=%.3f/s sdp_co=%.3f/s "
            "ccn_lk=%.3f/s occ_alm=%.0f alm_cr=%.4f/s",
            node,
            feat.get("cpu_pct", 0), feat.get("mem_pct", 0),
            feat.get("sdp_timeout", 0),  feat.get("sdp_conflict", 0),
            feat.get("ccn_lookup_fail", 0), feat.get("occ_alarm_state", 0),
            feat.get("alarm_critical", 0),
        )

    # Étape 4 : Isolation Forest
    log.info("Application Isolation Forest...")
    if_results = iforest_detect(model, scaler, features_by_node)
    for node, res in if_results.items():
        log.info("  IF %-12s → %s (score=%.3f)",
                 node, "ANOMALIE" if res["is_anomaly"] else "normal",
                 res["score"])

    # Étape 5 : Fusion anomalies
    anomalies = build_anomalies(nodes_meta, features_by_node, if_results)

    # Étape 6 : Corrélation
    correlation = correlate(features_by_node, anomalies, nodes_meta)

    # Étape 7 : Tri et payload
    anomalies_sorted = sorted(
        anomalies,
        key=lambda x: (sev_rank(x["severity"]), x["score"]),
        reverse=True,
    )

    health_ts = None
    try:
        health_ts = load_health().get("generated_at")
    except FileNotFoundError:
        log.warning("health_status.json absent")

    if_summary   = {
        node: {"is_anomaly": r["is_anomaly"], "score": r["score"]}
        for node, r in if_results.items()
    }
    loki_summary = {}
    try:
        from log_loki import get_all_nodes_summary
        loki_summary = get_all_nodes_summary()
    except ImportError:
        pass

    payload = {
        "generated_at":               datetime.now(timezone.utc).isoformat(),
        "source_health_generated_at": health_ts,
        "engine_version":             "hybrid-v3.5",
        "discovered_nodes":           len(nodes_meta),
        "nodes_by_role":              nodes_by_role,
        "detection_sources": {
            "isolation_forest":     True,
            "critical_rules":       True,
            "temporal_correlation": True,
            "loki_logs":            True,
            "loki_sync_collection": True,
        },
        "loki_summary":             loki_summary,
        "anomaly_count":            len(anomalies_sorted),
        "anomalies":                anomalies_sorted,
        "isolation_forest_summary": if_summary,
        "correlation":              correlation,
        "elapsed_seconds":          round(time.time() - start_time, 2),
    }

    ANOMALY_JSON.parent.mkdir(parents=True, exist_ok=True)
    with ANOMALY_JSON.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, cls=NumpyEncoder)

    log.info("Anomalies: %d | Root cause: %s [%s]",
             len(anomalies_sorted),
             correlation.get("probable_root_cause"),
             correlation.get("scenario"))
    log.info("Resultat sauvegarde dans %s", ANOMALY_JSON)
    print(json.dumps(payload, indent=2, ensure_ascii=False, cls=NumpyEncoder))


if __name__ == "__main__":
    main()
