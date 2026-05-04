package com.bdcs.batch;

import org.apache.spark.sql.SparkSession;

public class Main {
    public static void main(String[] args) {

        SparkSession spark = SparkSession.builder()
                .appName("BDCS Batch")
                .master("local[*]")
                .getOrCreate();

        System.out.println("Project works!");

        spark.stop();
    }
}