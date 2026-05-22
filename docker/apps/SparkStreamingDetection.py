"""
SparkStreamingDetection.py — FIXED
Runs 3 separate streaming queries (one per detection type).
Spark Structured Streaming does not support union of aggregated streams.
"""

import json
import os
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField, StringType, IntegerType, LongType
)

# ── Config ────────────────────────────────────────────────────────────────
KAFKA_BROKER  = "kafka:29092"
TOPIC         = "cybersecurity-logs"
OUTPUT_DIR    = "/opt/spark-apps/brute_force_alerts"
CHECKPOINT    = "/tmp/bdcs_checkpoint"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Spark Session ─────────────────────────────────────────────────────────
spark = (SparkSession.builder
    .appName("BDCS-StreamingDetection")
    .config("spark.sql.shuffle.partitions", "4")
    .config("spark.streaming.stopGracefullyOnShutdown", "true")
    .getOrCreate())

spark.sparkContext.setLogLevel("WARN")

# ── Schema ────────────────────────────────────────────────────────────────
log_schema = StructType([
    StructField("timestamp",         StringType(),  True),
    StructField("source_ip",         StringType(),  True),
    StructField("dest_ip",           StringType(),  True),
    StructField("dest_port",         IntegerType(), True),
    StructField("protocol",          StringType(),  True),
    StructField("action",            StringType(),  True),
    StructField("threat_label",      StringType(),  True),
    StructField("log_type",          StringType(),  True),
    StructField("bytes_transferred", LongType(),    True),
    StructField("user_agent",        StringType(),  True),
    StructField("request_path",      StringType(),  True),
])

# ── Read from Kafka ───────────────────────────────────────────────────────
def make_parsed_stream():
    raw = (spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BROKER)
        .option("subscribe", TOPIC)
        .option("startingOffsets", "latest")
        .option("failOnDataLoss", "false")
        .load())
    return (raw
        .selectExpr("CAST(value AS STRING) as raw_json", "timestamp as kafka_ts")
        .select(F.from_json(F.col("raw_json"), log_schema).alias("d"), "kafka_ts")
        .select("d.*", "kafka_ts")
        .withColumn("event_ts", F.to_timestamp(F.col("timestamp")))
        .withWatermark("event_ts", "2 minutes"))

# ── Writer helper ─────────────────────────────────────────────────────────
def make_writer(label):
    def write_batch(batch_df, batch_id):
        rows = batch_df.collect()
        if not rows:
            return
        out = os.path.join(OUTPUT_DIR, f"{label}_batch_{batch_id}.json")
        with open(out, "a", encoding="utf-8") as f:
            for row in rows:
                alert = row.asDict()
                f.write(json.dumps(alert, default=str) + "\n")
                print(f"  ALERT [{alert.get('alert_type','?')}] "
                      f"{alert.get('source_ip','?')} "
                      f"count={alert.get('count','?')} "
                      f"severity={alert.get('severity','?')}")
    return write_batch

# ════════════════════════════════════════════════════════════════
# QUERY 1 — Brute-Force
# ════════════════════════════════════════════════════════════════
parsed1 = make_parsed_stream()
brute_force = (parsed1
    .filter((F.col("action") == "failed") &
            (F.col("protocol").isin("SSH","HTTP","HTTPS","FTP")))
    .groupBy(F.window("event_ts","1 minute","30 seconds"), F.col("source_ip"))
    .agg(
        F.count("*").alias("count"),
        F.first("dest_ip").alias("target_ip"),
        F.first("protocol").alias("protocol"),
    )
    .filter(F.col("count") >= 5)
    .select(
        F.col("source_ip"),
        F.col("window.start").cast(StringType()).alias("window_start"),
        F.col("window.end").cast(StringType()).alias("window_end"),
        F.col("count"),
        F.col("target_ip"),
        F.col("protocol"),
        F.lit("BRUTE_FORCE").alias("alert_type"),
        F.lit("HIGH").alias("severity"),
        (F.col("count") * 10).alias("threat_score"),
    ))

q1 = (brute_force.writeStream
    .outputMode("update")
    .foreachBatch(make_writer("brute_force"))
    .option("checkpointLocation", CHECKPOINT + "/brute_force")
    .trigger(processingTime="5 seconds")
    .start())

# ════════════════════════════════════════════════════════════════
# QUERY 2 — SQLi / XSS
# ════════════════════════════════════════════════════════════════
SQLI = r"(?i)(union\s+select|or\s+1=1|'\s*--|\bsqlmap\b|select\s+\*\s+from|drop\s+table)"
XSS  = r"(?i)(<script|javascript:|onerror=|onload=|alert\s*\(|document\.cookie)"

parsed2 = make_parsed_stream()
attack_sigs = (parsed2
    .withColumn("is_sqli",
        F.col("request_path").rlike(SQLI) | F.col("user_agent").rlike(SQLI))
    .withColumn("is_xss",
        F.col("request_path").rlike(XSS) | F.col("user_agent").rlike(XSS))
    .filter(F.col("is_sqli") | F.col("is_xss"))
    .groupBy(
        F.window("event_ts","1 minute","30 seconds"),
        F.col("source_ip"),
        F.when(F.col("is_sqli"), "SQLi").otherwise("XSS").alias("attack_type")
    )
    .agg(F.count("*").alias("count"))
    .select(
        F.col("source_ip"),
        F.col("window.start").cast(StringType()).alias("window_start"),
        F.col("window.end").cast(StringType()).alias("window_end"),
        F.col("count"),
        F.lit("").alias("target_ip"),
        F.lit("HTTP").alias("protocol"),
        F.col("attack_type").alias("alert_type"),
        F.lit("CRITICAL").alias("severity"),
        F.lit(90).cast(LongType()).alias("threat_score"),
    ))

q2 = (attack_sigs.writeStream
    .outputMode("update")
    .foreachBatch(make_writer("sqli_xss"))
    .option("checkpointLocation", CHECKPOINT + "/sqli_xss")
    .trigger(processingTime="5 seconds")
    .start())

# ════════════════════════════════════════════════════════════════
# QUERY 3 — Volume Anomaly (> 10 MB in 10 sec)
# ════════════════════════════════════════════════════════════════
parsed3 = make_parsed_stream()
volume_alerts = (parsed3
    .groupBy(F.window("event_ts","10 seconds","5 seconds"), F.col("source_ip"))
    .agg(
        F.sum("bytes_transferred").alias("total_bytes"),
        F.count("*").alias("count"),
    )
    .filter(F.col("total_bytes") > 10 * 1024 * 1024)
    .select(
        F.col("source_ip"),
        F.col("window.start").cast(StringType()).alias("window_start"),
        F.col("window.end").cast(StringType()).alias("window_end"),
        F.col("count"),
        F.lit("").alias("target_ip"),
        F.lit("TCP").alias("protocol"),
        F.lit("VOLUME_ANOMALY").alias("alert_type"),
        F.lit("HIGH").alias("severity"),
        F.lit(70).cast(LongType()).alias("threat_score"),
    ))

q3 = (volume_alerts.writeStream
    .outputMode("update")
    .foreachBatch(make_writer("volume"))
    .option("checkpointLocation", CHECKPOINT + "/volume")
    .trigger(processingTime="5 seconds")
    .start())

print("=" * 60)
print("BDCS Spark Streaming — 3 detection queries running")
print(f"  Kafka: {KAFKA_BROKER} | Topic: {TOPIC}")
print(f"  Output: {OUTPUT_DIR}")
print(f"  Q1: Brute-Force | Q2: SQLi/XSS | Q3: Volume Anomaly")
print("=" * 60)

# Wait for all queries
spark.streams.awaitAnyTermination()