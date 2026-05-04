package com.bdcs.streaming;

import org.apache.spark.sql.SparkSession;

public class MainStreaming {

    public static void main(String[] args) {

        SparkSession spark = SparkSession.builder()
                .appName("BDCS Streaming")
                .master("local[*]")
                .getOrCreate();

        System.out.println("Streaming project works!");

        spark.stop();
    }
}