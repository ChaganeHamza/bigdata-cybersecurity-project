# ─────────────────────────────────────────────────────────────────────────
# REMPLACE l'ancienne route /threats/streaming dans api/app.py
# ─────────────────────────────────────────────────────────────────────────

import glob as _glob
import json as _json
from datetime import datetime as _dt, timedelta as _td

@app.route("/threats/streaming")
def get_streaming():
    """
    Lit les alertes JSON produites par SparkStreamingDetection.py
    Retourne les alertes des dernières 24h, triées par threat_score DESC.
    """
    alert_dir = PARQUET_PATHS["brute_force_alerts"]
    files = _glob.glob(os.path.join(alert_dir, "*.json"))

    if not files:
        return jsonify({
            "alerts": [],
            "count": 0,
            "message": "Aucune alerte — lancez KafkaLogProducer.py puis SparkStreamingDetection.py"
        }), 200

    alerts = []
    cutoff = _dt.utcnow() - _td(hours=24)

    for filepath in files:
        with open(filepath, encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = _json.loads(line)
                    alerts.append(alert)
                except Exception:
                    pass

    # Trier par threat_score décroissant
    alerts.sort(key=lambda a: int(a.get("threat_score", 0)), reverse=True)

    # Stats résumé
    by_type = {}
    for a in alerts:
        t = a.get("alert_type", "UNKNOWN")
        by_type[t] = by_type.get(t, 0) + 1

    return jsonify({
        "alerts": alerts,
        "count": len(alerts),
        "summary": {
            "total": len(alerts),
            "by_type": by_type,
            "unique_ips": len(set(a.get("source_ip") for a in alerts)),
        },
        "timestamp": _dt.utcnow().isoformat(),
    })


@app.route("/threats/streaming/stats")
def get_streaming_stats():
    """Stats agrégées du speed layer pour Grafana."""
    data = get_streaming().get_json()
    alerts = data.get("alerts", [])

    brute_force  = [a for a in alerts if a.get("alert_type") == "BRUTE_FORCE"]
    sqli_xss     = [a for a in alerts if a.get("alert_type") in ("SQLi", "XSS")]
    vol_anomaly  = [a for a in alerts if a.get("alert_type") == "VOLUME_ANOMALY"]
    critical     = [a for a in alerts if a.get("severity") == "CRITICAL"]

    return jsonify({
        "total_alerts":        len(alerts),
        "brute_force_count":   len(brute_force),
        "sqli_xss_count":      len(sqli_xss),
        "volume_anomaly_count":len(vol_anomaly),
        "critical_count":      len(critical),
        "unique_attacker_ips": len(set(a.get("source_ip") for a in alerts)),
        "top_attacker":        alerts[0].get("source_ip") if alerts else None,
        "timestamp":           _dt.utcnow().isoformat(),
    })