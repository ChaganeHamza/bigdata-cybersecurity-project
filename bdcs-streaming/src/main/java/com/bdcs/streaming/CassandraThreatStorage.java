package com.bdcs.streaming;

import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.streaming.Trigger;
import org.apache.spark.sql.types.DataTypes;
import org.apache.spark.sql.types.StructField;
import org.apache.spark.sql.types.StructType;
import static org.apache.spark.sql.functions.*;

public class CassandraThreatStorage {
    public static void main(String[] args) throws Exception {
        
        System.out.println("=== SCRUM-23: Threat Storage Started ===");
        
        SparkSession spark = SparkSession.builder()
                .appName("Threat Storage")
                .master("local[*]")
                .getOrCreate();
        
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
        
        Dataset<Row> threats = kafkaStream
                .filter(col("threat_label").isin("malicious", "suspicious"))
                .select(
                    col("source_ip").as("ip_source"),
                    col("timestamp").as("last_seen"),
                    col("threat_label").as("attack_type"),
                    current_timestamp().as("stored_at")
                );
        
        org.apache.spark.sql.streaming.StreamingQuery query = threats
                .writeStream()
                .outputMode("append")
                .trigger(Trigger.ProcessingTime("5 seconds"))
                .format("console")
                .option("truncate", false)
                .start();
        
        query.awaitTermination();
    }
}
