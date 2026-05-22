from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime
import os
import glob

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────
# Chemins vers les fichiers Parquet générés par Java
# Adapte BASE_DIR selon où tu lances app.py
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "..", "bdcs-batch", "data", "output")

PARQUET_PATHS = {
    "top_malicious_ips":            os.path.join(OUTPUT_DIR, "top_malicious_ips"),
    "bytes_volume_by_threat_label": os.path.join(OUTPUT_DIR, "bytes_volume_by_threat_label"),
    "sqli_xss_detection":           os.path.join(OUTPUT_DIR, "sqli_xss_detection"),
    # Dans PARQUET_PATHS, ajoute :
    "port_scan_detection": os.path.join(OUTPUT_DIR, "port_scan_detection"),
    "brute_force_alerts": os.path.join(OUTPUT_DIR, "brute_force_alerts"),
}

# ─────────────────────────────────────────────
# Lecture Parquet avec pandas
# ─────────────────────────────────────────────
def read_parquet(key):
    """Lit un dossier Parquet et retourne une liste de dicts."""
    try:
        import pandas as pd
        path = PARQUET_PATHS[key]
        files = glob.glob(os.path.join(path, "*.parquet"))
        if not files:
            return None, f"Aucun fichier .parquet trouvé dans : {path}"
        df = pd.read_parquet(path)
        # Convertit les types numpy en types Python natifs
        return df.to_dict(orient="records"), None
    except ImportError:
        return None, "pandas non installé — lance : pip install pandas pyarrow"
    except Exception as e:
        return None, str(e)

def threat_level(score):
    if score >= 85: return "CRITICAL"
    if score >= 65: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"

# ─────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────

@app.route("/dashboard")
def dashboard():
    path = os.path.join(BASE_DIR, "dashboard.html")
    if not os.path.exists(path):
        return f"dashboard.html introuvable dans : {BASE_DIR}", 404
    return open(path, encoding="utf-8").read()

# ─────────────────────────────────────────────
# Routes API
# ─────────────────────────────────────────────
@app.route("/threats/port-scans")
def get_port_scans():
    """
    Lit data/output/port_scan_detection/ généré par PortScanDetectionJob.java
    Colonnes : source_ip, window_start, window_end, distinct_targets, connection_count
    """
    rows, err = read_parquet("port_scan_detection")
    if err:
        return jsonify({"error": err}), 500

    results = []
    for r in rows:
        results.append({
            "ip":               r.get("source_ip"),
            "window_start":     str(r.get("window_start", "")),
            "window_end":       str(r.get("window_end", "")),
            "distinct_targets": int(r.get("distinct_targets", 0)),
            "connection_count": int(r.get("connection_count", 0)),
        })

    return jsonify({"port_scans": results, "count": len(results)})
@app.route("/")
def home():
    return jsonify({
        "message": "BDCS API running",
        "version": "1.0.0",
        "dashboard": "/dashboard",
        "endpoints": [
            "GET /health",
            "GET /dashboard",
            "GET /threats/ip/<ip>",
            "GET /threats/top",
            "GET /threats/bytes",
            "GET /threats/sqli-xss",
            "GET /threats/stats",
        ]
    })

@app.route("/threats/streaming")
def get_streaming():
    import glob, json
    path = PARQUET_PATHS["brute_force_alerts"]
    files = glob.glob(os.path.join(path, "*.json"))
    if not files:
        return jsonify({"alerts": [], "message": "Aucune alerte — lance KafkaLogProducer + BruteForceDetectionJob"}), 200
    alerts = []
    for f in files:
        with open(f) as fp:
            for line in fp:
                try:
                    alerts.append(json.loads(line))
                except:
                    pass
    return jsonify({"alerts": alerts, "count": len(alerts)})

@app.route("/health")
def health():
    # Vérifie quels fichiers Parquet existent vraiment
    status = {}
    for key, path in PARQUET_PATHS.items():
        files = glob.glob(os.path.join(path, "*.parquet"))
        status[key] = "ok" if files else f"manquant ({path})"
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "parquet_files": status,
        "output_dir": OUTPUT_DIR,
    })


@app.route("/threats/top")
def get_top_threats():
    """
    Lit data/output/top_malicious_ips/ généré par TopMaliciousIPsJob.java
    Colonnes : source_ip, threat_count, malicious_count, suspicious_count, total_bytes
    """
    rows, err = read_parquet("top_malicious_ips")
    if err:
        return jsonify({"error": err}), 500

    # Score basé sur le volume : normalise threat_count entre 0 et 99
    all_counts = [int(r.get("threat_count", 0)) for r in rows]
    max_count  = max(all_counts) if all_counts else 1
    min_count  = min(all_counts) if all_counts else 0

    results = []
    for r in rows:
        threat_count = int(r.get("threat_count", 0))
        malicious    = int(r.get("malicious_count", 0))
        suspicious   = int(r.get("suspicious_count", 0))
        # Normalise entre 50 et 99 (toutes ces IPs sont déjà malveillantes)
        if max_count == min_count:
            score = 75
        else:
            score = int(50 + ((threat_count - min_count) / (max_count - min_count)) * 49)
        # Bonus si malicious_count élevé
        malicious_ratio = malicious / max(threat_count, 1)
        if malicious_ratio > 0.3:
            score = min(99, score + 10)
        results.append({
            "ip":               r.get("source_ip"),
            "threat_count":     threat_count,
            "malicious_count":  malicious,
            "suspicious_count": suspicious,
            "total_bytes":      int(r.get("total_bytes", 0)),
            "score":            score,
            "threat_level":     threat_level(score),
        })

    return jsonify({"top_malicious_ips": results, "count": len(results)})


@app.route("/threats/ip/<ip>")
def get_ip_threat(ip):
    """
    Cherche une IP dans les résultats batch de TopMaliciousIPsJob.
    """
    rows, err = read_parquet("top_malicious_ips")
    if err:
        return jsonify({"error": err}), 500

    match = next((r for r in rows if r.get("source_ip") == ip), None)
    if not match:
        return jsonify({"ip": ip, "status": "clean", "message": "IP non trouvée dans les données batch."}), 404

    threat_count = int(match.get("threat_count", 0))
    malicious    = int(match.get("malicious_count", 0))
    all_counts   = [int(r.get("threat_count", 0)) for r in rows]
    max_count    = max(all_counts) if all_counts else 1
    min_count    = min(all_counts) if all_counts else 0
    if max_count == min_count:
        score = 75
    else:
        score = int(50 + ((threat_count - min_count) / (max_count - min_count)) * 49)
    if (malicious / max(threat_count, 1)) > 0.3:
        score = min(99, score + 10)

    return jsonify({
        "ip": ip,
        "threat_level": threat_level(score),
        "batch_layer": {
            "reputation_score":  score,
            "threat_count":      threat_count,
            "malicious_count":   malicious,
            "suspicious_count":  int(match.get("suspicious_count", 0)),
            "total_bytes":       int(match.get("total_bytes", 0)),
        },
        "speed_layer": {
            "note": "BruteForceDetectionJob écrit en console — pas encore persisté",
            "active_threats": [],
        },
        "action": "BLOCK" if score >= 75 else "MONITOR",
    })


@app.route("/threats/bytes")
def get_bytes_by_threat():
    """
    Lit data/output/bytes_volume_by_threat_label/ généré par BytesVolumeByThreatLabelJob.java
    Colonnes : threat_label, event_count, total_bytes, avg_bytes, min_bytes, max_bytes
    """
    rows, err = read_parquet("bytes_volume_by_threat_label")
    if err:
        return jsonify({"error": err}), 500

    results = []
    for r in rows:
        results.append({
            "threat_label":  r.get("threat_label"),
            "event_count":   int(r.get("event_count", 0)),
            "total_bytes":   int(r.get("total_bytes", 0)),
            "avg_bytes":     round(float(r.get("avg_bytes", 0)), 2),
            "min_bytes":     int(r.get("min_bytes", 0)),
            "max_bytes":     int(r.get("max_bytes", 0)),
        })

    return jsonify({"bytes_by_threat_label": results, "count": len(results)})


@app.route("/threats/sqli-xss")
def get_sqli_xss():
    """
    Lit data/output/sqli_xss_detection/ généré par SqlXssDetectionJob.java
    Colonnes : attack_type, count
    """
    rows, err = read_parquet("sqli_xss_detection")
    if err:
        return jsonify({"error": err}), 500

    results = []
    for r in rows:
        results.append({
            "attack_type": r.get("attack_type"),
            "count":       int(r.get("count", 0)),
        })

    return jsonify({"sqli_xss_detections": results, "count": len(results)})


@app.route("/threats/stats")
def threat_stats():
    """Agrège toutes les sources pour le dashboard."""
    top_rows,   err1 = read_parquet("top_malicious_ips")
    bytes_rows, err2 = read_parquet("bytes_volume_by_threat_label")
    sqli_rows,  err3 = read_parquet("sqli_xss_detection")

    return jsonify({
        "top_ips_available":   err1 is None,
        "bytes_available":     err2 is None,
        "sqli_xss_available":  err3 is None,
        "errors": [e for e in [err1, err2, err3] if e],
        "summary": {
            "unique_malicious_ips": len(top_rows)  if top_rows  else 0,
            "threat_label_groups":  len(bytes_rows) if bytes_rows else 0,
            "attack_types_detected":len(sqli_rows)  if sqli_rows  else 0,
        },
        "timestamp": datetime.utcnow().isoformat(),
    })

# ─────────────────────────────────────────────
# ADD THIS ROUTE TO YOUR api/app.py
# Paste it anywhere before the  if __name__ == "__main__":  line
# ─────────────────────────────────────────────

@app.route("/threats/kpis")
def threat_kpis():
    """
    Single flat object with all scalar KPIs needed by Grafana stat/gauge panels.
    Grafana Infinity datasource reads one field per panel — no filtering needed.
    """
    sqli_rows,  e1 = read_parquet("sqli_xss_detection")
    bytes_rows, e2 = read_parquet("bytes_volume_by_threat_label")
    top_rows,   e3 = read_parquet("top_malicious_ips")

    # SQLi / XSS counts
    sqli_count = 0
    xss_count  = 0
    if sqli_rows:
        for r in sqli_rows:
            if r.get("attack_type") == "SQLi":
                sqli_count = int(r.get("count", 0))
            elif r.get("attack_type") == "XSS":
                xss_count = int(r.get("count", 0))

    # Event counts by threat label
    malicious_events  = 0
    suspicious_events = 0
    benign_events     = 0
    if bytes_rows:
        for r in bytes_rows:
            lbl = r.get("threat_label", "")
            cnt = int(r.get("event_count", 0))
            if lbl == "malicious":
                malicious_events = cnt
            elif lbl == "suspicious":
                suspicious_events = cnt
            elif lbl == "benign":
                benign_events = cnt

    return jsonify({
        "api_status":        "ok",
        "sqli_count":        sqli_count,
        "xss_count":         xss_count,
        "malicious_events":  malicious_events,
        "suspicious_events": suspicious_events,
        "benign_events":     benign_events,
        "top_ip_count":      len(top_rows) if top_rows else 0,
        "errors": [e for e in [e1, e2, e3] if e],
    })
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)