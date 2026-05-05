package com.bdcs.batch;

import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;

import static org.apache.spark.sql.functions.*;

public class PortScanDetectionJob {

    public static void main(String[] args) {

        SparkSession spark = SparkSession.builder()
                .appName("BDCS-7 Port Scan Detection")
                .master("local[*]")
                .config("spark.sql.shuffle.partitions", "4")
                .config("spark.ui.enabled", "false")
                .getOrCreate();

        Dataset<Row> logs = spark.read()
                .parquet("hdfs://hadoop-master:9000/data/cybersecurity/clean_logs.parquet");

        Dataset<Row> portScans = logs
                .filter(col("protocol").equalTo("TCP"))
                .withColumn("event_time", col("timestamp"))
                .groupBy(
                        col("source_ip"),
                        window(col("event_time"), "5 minutes"))
                .agg(
                        countDistinct(col("dest_ip")).alias("distinct_targets"),
                        count("*").alias("connection_count"))
                .filter(col("distinct_targets").gt(20))
                .orderBy(desc("distinct_targets"));

        portScans.show(false);

        // Force execution
        portScans.count();

        spark.stop();
        System.exit(0); // 🔥 IMPORTANT pour tuer les threads
    }
}