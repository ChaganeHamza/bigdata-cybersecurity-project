package com.bdcs.batch;

import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;

import static org.apache.spark.sql.functions.*;

public class TopMaliciousIPsJob {

    public static void main(String[] args) {

        SparkSession spark = SparkSession.builder()
                .appName("BDCS-6 Top 10 Malicious IPs")
                .master("local[*]")
                .config("spark.sql.shuffle.partitions", "4")
                .config("spark.ui.enabled", "false")
                .getOrCreate();

        Dataset<Row> logs = spark.read()
                .parquet("data/clean/clean_logs.parquet");

        Dataset<Row> topMaliciousIPs = logs
                .filter(
                        lower(col("threat_label")).equalTo("malicious")
                                .or(lower(col("threat_label")).equalTo("suspicious")))
                .groupBy(col("source_ip"))
                .agg(
                        count("*").alias("threat_count"),
                        sum(when(lower(col("threat_label")).equalTo("malicious"), 1).otherwise(0))
                                .alias("malicious_count"),
                        sum(when(lower(col("threat_label")).equalTo("suspicious"), 1).otherwise(0))
                                .alias("suspicious_count"),
                        sum(col("bytes_transferred")).alias("total_bytes"))
                .orderBy(desc("threat_count"))
                .limit(10);

        topMaliciousIPs.show(false);

        topMaliciousIPs.write()
                .mode("overwrite")
                .parquet("data/output/top_malicious_ips");

        spark.stop();
        System.exit(0);
    }
}