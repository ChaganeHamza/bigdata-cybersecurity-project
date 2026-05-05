package com.bdcs.streaming;

import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.streaming.Trigger;
import org.apache.spark.sql.types.DataTypes;
import org.apache.spark.sql.types.StructField;
import org.apache.spark.sql.types.StructType;
import static org.apache.spark.sql.functions.*;

public class BruteForceDetector {
    public static void main(String[] args) throws Exception {
        
        System.out.println("=== SCRUM-19: Brute-Force Detection Started ===");
        
        SparkSession spark = SparkSession.builder()
                .appName("Brute-Force Detection")
                .master("local[*]")
                .getOrCreate();
        
        // Define JSON schema properly
        StructType schema = DataTypes.createStructType(new StructField[]{
            DataTypes.createStructField("timestamp", DataTypes.StringType, true),
            DataTypes.createStructField("source_ip", DataTypes.StringType, true),
            DataTypes.createStructField("dest_ip", DataTypes.StringType, true),
            DataTypes.createStructField("protocol", DataTypes.StringType, true),
            DataTypes.createStructField("action", DataTypes.StringType, true),
            DataTypes.createStructField("threat_label", DataTypes.StringType, true),
            DataTypes.createStructField("log_type", DataTypes.StringType, true),
            DataTypes.createStructField("bytes_transferred", DataTypes.LongType, true),
            DataTypes.createStructField("user_agent", DataTypes.StringType, true),
            DataTypes.createStructField("request_path", DataTypes.StringType, true)
        });
        
        // Read from Kafka
        Dataset<Row> kafkaStream = spark
                .readStream()
                .format("kafka")
                .option("kafka.bootstrap.servers", "kafka:9092")
                .option("subscribe", "cybersecurity-logs")
                .option("startingOffsets", "latest")
                .load()
                .selectExpr("CAST(value AS STRING) as json")
                .select(from_json(col("json"), schema).alias("data"))
                .select("data.*");
        
        // Detect brute-force: 5+ blocked actions from same IP in 1 minute
        Dataset<Row> bruteForce = kafkaStream
                .filter(col("action").equalTo("blocked"))
                .groupBy(
                    col("source_ip"),
                    window(col("timestamp"), "1 minute")
                )
                .count()
                .filter(col("count").gt(5))
                .select(
                    col("source_ip"),
                    col("window").getField("start").as("window_start"),
                    col("window").getField("end").as("window_end"),
                    col("count").as("failed_attempts"),
                    lit("BRUTE_FORCE").as("threat_type"),
                    current_timestamp().as("detected_at")
                );
        
        // Write to console
        org.apache.spark.sql.streaming.StreamingQuery query = bruteForce
                .writeStream()
                .outputMode("update")
                .trigger(Trigger.ProcessingTime("10 seconds"))
                .format("console")
                .option("truncate", false)
                .start();
        
        query.awaitTermination();
    }
}
