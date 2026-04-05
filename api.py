#!/usr/bin/env python3
"""
api.py — API FastAPI TTCS (version finale)
==========================================
Endpoints :
  /                        → liste des endpoints
  /status                  → état santé tous nœuds
  /status/{node}           → état santé un nœud
  /summary                 → résumé global
  /inventory               → contenu servers.yml
  /anomalies               → toutes les anomalies
  /anomalies/{node}        → anomalies d'un nœud
  /correlation             → root-cause corrélation
  /predictions             → prédictions LSTM tous nœuds
  /predictions/{node}      → prédiction LSTM un nœud
  /timeline/{node}         → chronologie health+anomaly+lstm+logs
  /logs/status             → statut polling Loki
  /logs/summary            → résumé logs tous nœuds
  /logs/{node}             → logs analysés d'un nœud
  /logs/{node}/critical    → logs CRITICAL/ERROR d'un nœud
  /logs/{node}/alarms      → alarmes Ericsson d'un nœud
  /refresh                 → rafraîchit tout
"""

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import subprocess, json, os
from datetime import datetime, timezone
import pred

# ── Imports Loki (optionnel — ne plante pas si absent) ──────────────────────
try:
    from log_loki import (
        start_polling, is_polling_active,
        get_log_signals, get_critical_signals,
        get_alarm_signals, get_all_nodes_summary,
        LOG_BUFFER,
    )
    LOKI_AVAILABLE = True
except ImportError:
    LOKI_AVAILABLE = False

# ---------------- FastAPI ----------------
app = FastAPI(title="TTCS Health API", version="3.0")

# ---------------- Chemins ----------------
HEALTH_SCRIPT  = "/opt/ttcs_platform/healthcheck/healthcheck.py"
HEALTH_OUTPUT  = "/opt/ttcs_platform/output/health_status.json"
INVENTORY_FILE = "/opt/ttcs_platform/inventory/servers.yml"
ANOMALY_SCRIPT = "/opt/ttcs_platform/anomaly/anomaly_engine.py"
ANOMALY_OUTPUT = "/opt/ttcs_platform/anomaly/output/anomalies.json"

# ---------------- Démarrage ----------------
# Charger le modèle LSTM au démarrage (une seule fois)
MODEL, SCALER = pred.load_or_train()

# Démarrer le polling Loki en arrière-plan
if LOKI_AVAILABLE:
    start_polling()

# ---------------- Utility ----------------
def run_healthcheck():
    subprocess.run(["python3", HEALTH_SCRIPT], capture_output=True, text=True)

def run_anomaly():
    subprocess.run(["python3", ANOMALY_SCRIPT], capture_output=True, text=True)

def load_json_file(path: str, default):
    return json.load(open(path, "r")) if os.path.exists(path) else default

def load_health():
    return load_json_file(HEALTH_OUTPUT, {"generated_at": None, "nodes": []})

def load_anomalies():
    return load_json_file(ANOMALY_OUTPUT, {
        "generated_at":             None,
        "anomaly_count":            0,
        "anomalies":                [],
        "correlation":              {},
        "nodes_by_role":            {},
        "isolation_forest_summary": {},
    })

def load_inventory_text():
    return open(INVENTORY_FILE, "r").read() \
           if os.path.exists(INVENTORY_FILE) else ""


# ===========================================================================
# ENDPOINTS
# ===========================================================================

@app.get("/")
def root():
    return {
        "service": "TTCS Health API",
        "status":  "ok",
        "version": "3.0",
        "loki_available": LOKI_AVAILABLE,
        "endpoints": [
            "/status", "/status/{node}",
            "/summary", "/inventory",
            "/anomalies", "/anomalies/{node}",
            "/correlation",
            "/predictions", "/predictions/{node}",
            "/timeline/{node}",
            "/logs/status", "/logs/summary",
            "/logs/{node}", "/logs/{node}/critical", "/logs/{node}/alarms",
            "/refresh",
        ],
    }

# ---------------- Status ----------------

@app.get("/status")
def get_all_status():
    run_healthcheck()
    return load_health()

@app.get("/status/{node}")
def get_node_status(node: str):
    run_healthcheck()
    for n in load_health().get("nodes", []):
        if n.get("hostname") == node:
            return n
    return JSONResponse(status_code=404, content={"error": "node not found"})

# ---------------- Summary ----------------

@app.get("/summary")
def get_summary():
    run_healthcheck()
    nodes    = load_health().get("nodes", [])
    critical = [n for n in nodes if n.get("global_status") == "CRITICAL"]
    warning  = [n for n in nodes if n.get("global_status") == "WARNING"]
    normal   = [n for n in nodes if n.get("global_status") == "NORMAL"]
    return {
        "generated_at":   load_health().get("generated_at"),
        "total_nodes":    len(nodes),
        "critical_count": len(critical),
        "warning_count":  len(warning),
        "normal_count":   len(normal),
        "critical_nodes": [n["hostname"] for n in critical],
        "warning_nodes":  [n["hostname"] for n in warning],
    }

# ---------------- Inventory ----------------

@app.get("/inventory")
def get_inventory():
    return {"inventory": load_inventory_text()}

# ---------------- Anomalies ----------------

@app.get("/anomalies")
def get_anomalies():
    run_healthcheck()
    run_anomaly()
    return load_anomalies()

@app.get("/anomalies/{node}")
def get_node_anomalies(node: str):
    run_healthcheck()
    run_anomaly()
    data  = load_anomalies()
    items = [a for a in data.get("anomalies", []) if a.get("node") == node]
    return {
        "generated_at": data.get("generated_at"),
        "node":         node,
        "count":        len(items),
        "anomalies":    items,
    }

# ---------------- Correlation ----------------

@app.get("/correlation")
def get_correlation():
    run_healthcheck()
    run_anomaly()
    data = load_anomalies()
    return {
        "generated_at": data.get("generated_at"),
        "correlation":  data.get("correlation", {}),
    }

# ---------------- Predictions ----------------

@app.get("/predictions")
def get_predictions():
    start = datetime.now(timezone.utc)
    nodes = pred.discover_nodes_from_prometheus()
    if not nodes:
        return JSONResponse(
            status_code=503,
            content={"error": "Aucun nœud découvert depuis Prometheus"},
        )
    results = []
    for node_info in nodes:
        node, role = node_info["node"], node_info["role"]
        p = pred.predict_node(MODEL, SCALER, node)
        p["role"] = role
        results.append(p)

    critical_nodes = [r["node"] for r in results if r["severity"] == "CRITICAL"]
    warning_nodes  = [r["node"] for r in results if r["severity"] == "WARNING"]
    return {
        "generated_at":     start.isoformat(),
        "discovered_nodes": len(nodes),
        "summary": {
            "critical_nodes": critical_nodes,
            "warning_nodes":  warning_nodes,
            "normal_count":   sum(1 for r in results if r["severity"] == "NORMAL"),
        },
        "predictions":     results,
        "elapsed_seconds": round(
            (datetime.now(timezone.utc) - start).total_seconds(), 2),
    }

@app.get("/predictions/{node}")
def get_node_prediction(node: str):
    nodes     = pred.discover_nodes_from_prometheus()
    node_info = next((n for n in nodes if n["node"] == node), None)
    if node_info is None:
        return JSONResponse(
            status_code=404,
            content={
                "error":           f"Nœud '{node}' introuvable dans Prometheus",
                "available_nodes": [n["node"] for n in nodes],
            },
        )
    p = pred.predict_node(MODEL, SCALER, node)
    p["role"] = node_info["role"]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "prediction":   p,
    }

# ---------------- Timeline ----------------

@app.get("/timeline/{node}")
def get_timeline(node: str):
    run_healthcheck()
    run_anomaly()
    health_data  = load_health()
    anomaly_data = load_anomalies()

    health_node = next(
        (n for n in health_data.get("nodes", []) if n.get("hostname") == node),
        None,
    )
    node_anomalies = [
        a for a in anomaly_data.get("anomalies", []) if a.get("node") == node
    ]

    nodes     = pred.discover_nodes_from_prometheus()
    node_info = next((n for n in nodes if n["node"] == node), None)
    prediction = None
    if node_info:
        prediction = pred.predict_node(MODEL, SCALER, node)
        prediction["role"] = node_info["role"]

    events = []

    if health_node:
        events.append({
            "timestamp": health_data.get("generated_at"),
            "type":      "health_status",
            "status":    health_node.get("global_status"),
            "detail":    health_node.get("reason", "-"),
        })

    for a in node_anomalies:
        events.append({
            "timestamp": anomaly_data.get("generated_at"),
            "type":      "anomaly",
            "status":    a.get("severity"),
            "detail":    a.get("reason"),
            "log_signals": a.get("log_signals", []),
        })

    if prediction:
        events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type":      "lstm_prediction",
            "status":    prediction.get("severity"),
            "detail":    prediction.get("reason"),
        })

    # Logs Loki temps réel
    if LOKI_AVAILABLE:
        loki_events = get_critical_signals(node)
        for e in loki_events[-5:]:
            events.append({
                "timestamp": e.get("timestamp"),
                "type":      "loki_log",
                "status":    e.get("nlp_severity", "INFO"),
                "detail":    e.get("message", ""),
                "category":  e.get("category", ""),
            })

    events.sort(key=lambda e: e.get("timestamp") or "")

    return {
        "node":         node,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events":       events,
    }

# ---------------- Logs Loki ----------------

@app.get("/logs/status")
def logs_status():
    if not LOKI_AVAILABLE:
        return {"loki_available": False, "polling_active": False}
    return {
        "loki_available":    True,
        "polling_active":    is_polling_active(),
        "poll_interval_sec": 5,
        "nodes_buffered":    list(LOG_BUFFER.keys()),
    }

@app.get("/logs/summary")
def logs_summary():
    if not LOKI_AVAILABLE:
        return JSONResponse(status_code=503,
                            content={"error": "log_loki.py non disponible"})
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "nodes":        get_all_nodes_summary(),
    }

@app.get("/logs/{node}")
def get_node_logs(node: str, last_n: int = 50):
    if not LOKI_AVAILABLE:
        return JSONResponse(status_code=503,
                            content={"error": "log_loki.py non disponible"})
    events = get_log_signals(node, last_n)
    return {
        "node":         node,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count":        len(events),
        "events":       events,
    }

@app.get("/logs/{node}/critical")
def get_node_critical_logs(node: str):
    if not LOKI_AVAILABLE:
        return JSONResponse(status_code=503,
                            content={"error": "log_loki.py non disponible"})
    events = get_critical_signals(node)
    return {
        "node":         node,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count":        len(events),
        "events":       events,
    }

@app.get("/logs/{node}/alarms")
def get_node_alarms(node: str):
    if not LOKI_AVAILABLE:
        return JSONResponse(status_code=503,
                            content={"error": "log_loki.py non disponible"})
    events = get_alarm_signals(node)
    return {
        "node":         node,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count":        len(events),
        "alarms":       events,
    }

# ---------------- Refresh ----------------

@app.get("/refresh")
def refresh():
    run_healthcheck()
    run_anomaly()

    # Rafraîchir prédictions LSTM
    nodes      = pred.discover_nodes_from_prometheus()
    pred_count = 0
    for node_info in nodes:
        pred.predict_node(MODEL, SCALER, node_info["node"])
        pred_count += 1

    return {
        "status":                "refreshed",
        "health_generated_at":   load_health().get("generated_at"),
        "anomaly_generated_at":  load_anomalies().get("generated_at"),
        "predictions_refreshed": pred_count,
        "loki_polling_active":   is_polling_active() if LOKI_AVAILABLE else False,
    }
