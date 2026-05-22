"""
KafkaLogProducer.py
────────────────────────────────────────────────────────────
Simule un flux continu de logs cybersécurité vers Kafka.
Lance-le avec :  python KafkaLogProducer.py

Dépendances :  pip install kafka-python
"""

import json
import random
import time
from datetime import datetime
from kafka import KafkaProducer

# ── Config ────────────────────────────────────────────────
KAFKA_BROKER   = "localhost:9092"
TOPIC          = "cybersecurity-logs"
EVENTS_PER_SEC = 10          # débit normal
BURST_INTERVAL = 30          # toutes les N secondes, injecter une attaque

# ── Données réalistes ─────────────────────────────────────
NORMAL_IPS = [f"10.0.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(50)]

# IPs attaquantes fixes pour déclencher le brute-force (même IP, many requests)
ATTACK_IPS = [
    "185.220.101.45",
    "94.102.49.190",
    "45.142.212.100",
    "192.241.220.137",
    "198.199.119.161",
]

PROTOCOLS  = ["HTTP", "TCP", "SSH", "HTTPS", "FTP"]
ACTIONS    = ["allowed", "blocked", "failed"]
LOG_TYPES  = ["firewall", "ids", "application"]
THREAT_LABELS = ["benign", "benign", "benign", "suspicious", "malicious"]  # ratio réaliste

NORMAL_PATHS = [
    "/index.html", "/api/v1/users", "/login",
    "/dashboard", "/static/app.js", "/favicon.ico",
]

ATTACK_PATHS = [
    "/wp-admin/?id=1' OR '1'='1",
    "/admin/login.php?user=admin'--",
    "/search?q=<script>alert('xss')</script>",
    "/api/users?id=1 UNION SELECT * FROM users--",
    "/login?user=admin&pass=' OR 1=1--",
    "/.env", "/config.php", "/wp-config.php",
    "/admin/../../../etc/passwd",
]

USER_AGENTS_NORMAL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "curl/7.68.0",
]

USER_AGENTS_ATTACK = [
    "sqlmap/1.7.8#stable",
    "nikto/2.1.6",
    "masscan/1.0",
    "python-requests/2.28",
    "Go-http-client/1.1",
]

# ── Producer ──────────────────────────────────────────────
producer = KafkaProducer(
    bootstrap_servers=KAFKA_BROKER,
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    key_serializer=lambda k: k.encode("utf-8") if k else None,
)

def make_normal_event():
    return {
        "timestamp":        datetime.utcnow().isoformat(),
        "source_ip":        random.choice(NORMAL_IPS),
        "dest_ip":          f"172.16.{random.randint(0,10)}.{random.randint(1,50)}",
        "dest_port":        random.choice([80, 443, 22, 3306, 8080]),
        "protocol":         random.choice(PROTOCOLS),
        "action":           "allowed",
        "threat_label":     "benign",
        "log_type":         random.choice(LOG_TYPES),
        "bytes_transferred": random.randint(100, 5000),
        "user_agent":       random.choice(USER_AGENTS_NORMAL),
        "request_path":     random.choice(NORMAL_PATHS),
    }

def make_brute_force_burst(attacker_ip, count=8):
    """Simule N connexions SSH échouées depuis la même IP en quelques secondes."""
    events = []
    for _ in range(count):
        events.append({
            "timestamp":        datetime.utcnow().isoformat(),
            "source_ip":        attacker_ip,
            "dest_ip":          "192.168.10.186",
            "dest_port":        22,
            "protocol":         "SSH",
            "action":           "failed",
            "threat_label":     "malicious",
            "log_type":         "firewall",
            "bytes_transferred": random.randint(100, 500),
            "user_agent":       random.choice(USER_AGENTS_ATTACK),
            "request_path":     "/ssh-login",
        })
    return events

def make_sqli_event(attacker_ip):
    return {
        "timestamp":        datetime.utcnow().isoformat(),
        "source_ip":        attacker_ip,
        "dest_ip":          "192.168.10.186",
        "dest_port":        80,
        "protocol":         "HTTP",
        "action":           "blocked",
        "threat_label":     "malicious",
        "log_type":         "ids",
        "bytes_transferred": random.randint(200, 2000),
        "user_agent":       "sqlmap/1.7.8#stable",
        "request_path":     random.choice([p for p in ATTACK_PATHS if "OR" in p or "UNION" in p]),
    }

def make_xss_event(attacker_ip):
    return {
        "timestamp":        datetime.utcnow().isoformat(),
        "source_ip":        attacker_ip,
        "dest_ip":          "192.168.10.186",
        "dest_port":        80,
        "protocol":         "HTTP",
        "action":           "blocked",
        "threat_label":     "suspicious",
        "log_type":         "application",
        "bytes_transferred": random.randint(100, 800),
        "user_agent":       "Mozilla/5.0 (compatible; attacker)",
        "request_path":     random.choice([p for p in ATTACK_PATHS if "script" in p]),
    }

def send(event):
    producer.send(TOPIC, key=event["source_ip"], value=event)

# ── Main loop ─────────────────────────────────────────────
print(f"🚀 KafkaLogProducer démarré → topic '{TOPIC}' sur {KAFKA_BROKER}")
print(f"   Débit normal : {EVENTS_PER_SEC} evt/s | Burst attaque toutes {BURST_INTERVAL}s")
print("   Ctrl+C pour arrêter\n")

burst_counter = 0
total_sent    = 0

try:
    while True:
        # Événements normaux
        for _ in range(EVENTS_PER_SEC):
            send(make_normal_event())
            total_sent += 1

        burst_counter += 1

        # Toutes les BURST_INTERVAL secondes → injecter une attaque
        if burst_counter >= BURST_INTERVAL:
            burst_counter = 0
            attacker = random.choice(ATTACK_IPS)
            attack_type = random.choice(["brute_force", "sqli", "xss"])

            if attack_type == "brute_force":
                events = make_brute_force_burst(attacker, count=random.randint(6, 12))
                for e in events:
                    send(e)
                    total_sent += 1
                print(f"  🔴 BURST brute-force: {attacker} → {len(events)} tentatives SSH échouées")

            elif attack_type == "sqli":
                for _ in range(3):
                    send(make_sqli_event(attacker))
                    total_sent += 1
                print(f"  🟠 BURST SQLi: {attacker} → injection SQL détectée")

            else:
                for _ in range(3):
                    send(make_xss_event(attacker))
                    total_sent += 1
                print(f"  🟣 BURST XSS: {attacker} → script XSS détecté")

        producer.flush()
        print(f"  ✅ {total_sent} événements envoyés (t={burst_counter}s)", end="\r")
        time.sleep(1)

except KeyboardInterrupt:
    print(f"\n\n⏹️  Arrêt — {total_sent} événements envoyés au total.")
    producer.flush()
    producer.close()