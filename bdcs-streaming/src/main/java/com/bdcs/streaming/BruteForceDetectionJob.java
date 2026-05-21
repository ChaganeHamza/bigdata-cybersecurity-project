package com.bdcs.streaming;

import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;

import static org.apache.spark.sql.functions.*;

public class BruteForceDetectionJob {

        public static void main(String[] args) throws Exception {

                SparkSession spark = SparkSession.builder()
                                .appName("BDCS-14 Brute Force Detection")
                                .master("local[*]")
                                .config("spark.sql.shuffle.partitions", "4")
                                .config("spark.ui.enabled", "false")
                                .getOrCreate();

                // Lecture depuis Kafka - CHANGEMENT CLÉ : startingOffsets = "earliest"
                Dataset<Row> kafkaLogs = spark.readStream()
                                .format("kafka")
                                .option("kafka.bootstrap.servers", "localhost:9092")
                                .option("subscribe", "cybersecurity-logs")
                                .option("startingOffsets", "earliest") // ← MODIFIÉ (était "latest")
                                .option("failOnDataLoss", "false") // ← AJOUTÉ
                                .load();

                // Conversion du message JSON
                Dataset<Row> logs = kafkaLogs
                                .selectExpr("CAST(value AS STRING) AS raw_log");

                // Filtrage des tentatives échouées
                Dataset<Row> bruteForceAlerts = logs
                                .filter(lower(col("raw_log")).contains("failed login"))
                                .withColumn("source_ip",
                                                regexp_extract(col("raw_log"),
                                                                "\"source_ip\":\"(\\d+\\.\\d+\\.\\d+\\.\\d+)\"", 1))
                                .withColumn("event_time", current_timestamp())
                                .groupBy(
                                                window(col("event_time"), "1 minute"),
                                                col("source_ip"))
                                .count()
                                .filter(col("count").geq(5));

                // Affichage des alertes
                bruteForceAlerts.writeStream()
                                .outputMode("complete")
                                .format("console")
                                .option("truncate", "false")
                                .start()
                                .awaitTermination();
        }
}