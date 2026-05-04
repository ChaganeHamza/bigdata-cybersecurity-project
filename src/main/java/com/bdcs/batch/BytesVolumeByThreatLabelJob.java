package com.bdcs.batch;

import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;

import static org.apache.spark.sql.functions.*;

public class BytesVolumeByThreatLabelJob {

    public static void main(String[] args) {

        SparkSession spark = SparkSession.builder()
                .appName("BDCS-9 Bytes Volume By Threat Label")
                .master("local[*]")
                .config("spark.sql.shuffle.partitions", "4")
                .config("spark.ui.enabled", "false")
                .getOrCreate();

        Dataset<Row> logs = spark.read()
                .parquet("data/clean/clean_logs.parquet");

        Dataset<Row> bytesByThreatLabel = logs
                .groupBy(lower(col("threat_label")).alias("threat_label"))
                .agg(
                        count("*").alias("event_count"),
                        sum(col("bytes_transferred")).alias("total_bytes"),
                        avg(col("bytes_transferred")).alias("avg_bytes"),
                        min(col("bytes_transferred")).alias("min_bytes"),
                        max(col("bytes_transferred")).alias("max_bytes"))
                .orderBy(desc("total_bytes"));

        bytesByThreatLabel.show(false);

        bytesByThreatLabel.write()
                .mode("overwrite")
                .parquet("data/output/bytes_volume_by_threat_label");

        spark.stop();
        System.exit(0);
    }
}