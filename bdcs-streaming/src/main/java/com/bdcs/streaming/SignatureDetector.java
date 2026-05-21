package com.bdcs.streaming;

import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.streaming.Trigger;
import org.apache.spark.sql.types.DataTypes;
import org.apache.spark.sql.types.StructField;
import org.apache.spark.sql.types.StructType;
import static org.apache.spark.sql.functions.*;

public class SignatureDetector {
    public static void main(String[] args) throws Exception {
        
        System.out.println("=== SCRUM-20: Signature Detection Started ===");
        
        SparkSession spark = SparkSession.builder()
                .appName("Signature Detection")
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
        
        Dataset<Row> signatures = kafkaStream
                .filter(
                    col("request_path").contains("' OR '1'='1")
                    .or(col("request_path").contains("<script>"))
                    .or(col("user_agent").contains("sqlmap"))
                    .or(col("user_agent").contains("nikto"))
                )
                .select(
                    col("timestamp"),
                    col("source_ip"),
                    col("request_path"),
                    col("user_agent"),
                    lit("SIGNATURE_ATTACK").as("threat_type")
                );
        
        org.apache.spark.sql.streaming.StreamingQuery query = signatures
                .writeStream()
                .outputMode("append")
                .trigger(Trigger.ProcessingTime("5 seconds"))
                .format("console")
                .option("truncate", false)
                .start();
        
        query.awaitTermination();
    }
}
