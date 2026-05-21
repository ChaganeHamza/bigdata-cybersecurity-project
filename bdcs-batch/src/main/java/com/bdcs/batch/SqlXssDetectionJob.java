package com.bdcs.batch;

import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.RowFactory;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.types.StructType;

import java.util.Arrays;

import static org.apache.spark.sql.functions.*;

public class SqlXssDetectionJob {

<
        public static void main(String[] args) {

                SparkSession spark = SparkSession.builder()
                                .appName("BDCS-8 SQLi & XSS Detection")
                                .master("local[*]")
                                .config("spark.sql.shuffle.partitions", "4")
                                .config("spark.ui.enabled", "false")
                                .getOrCreate();

                Dataset<Row> logs = spark.read()
                                .parquet("../data/clean/clean_logs.parquet");

                Dataset<Row> sqli = logs
                                .filter(
                                                lower(col("request_path"))
                                                                .rlike("('.*or.*=)|(or 1=1)|(union select)|(drop table)|(--)"))
                                .withColumn("attack_type", lit("SQLi"));

                Dataset<Row> xss = logs
                                .filter(
                                                lower(col("request_path"))
                                                                .rlike("(<script)|(</script>)|(onerror=)|(alert\\()|(img src)|(javascript:)|(onload=)"))
                                .withColumn("attack_type", lit("XSS"));

                long sqliTotal = sqli.count();
                long xssTotal = xss.count();

                StructType schema = new StructType()
                                .add("attack_type", "string")
                                .add("count", "long");

                Dataset<Row> results = spark.createDataFrame(
                                Arrays.asList(
                                                RowFactory.create("SQLi", sqliTotal),
                                                RowFactory.create("XSS", xssTotal)),
                                schema).orderBy(desc("count"));

                results.show(false);

                results.write()
                                .mode("overwrite")
                                .parquet("data/output/sqli_xss_detection");

                spark.stop();
                System.exit(0);
        }
=======
    public static void main(String[] args) {

        SparkSession spark = SparkSession.builder()
                .appName("BDCS-8 SQLi & XSS Detection")
                .master("local[*]")
                .config("spark.sql.shuffle.partitions", "4")
                .config("spark.ui.enabled", "false")
                .getOrCreate();

        Dataset<Row> logs = spark.read()
                .parquet("hdfs://hadoop-master:9000/data/cybersecurity/clean_logs.parquet");

        Dataset<Row> sqli = logs
                .filter(
                        lower(col("request_path"))
                                .rlike("('.*or.*=)|(or 1=1)|(union select)|(drop table)|(--)"))
                .withColumn("attack_type", lit("SQLi"));

        Dataset<Row> xss = logs
                .filter(
                        lower(col("request_path"))
                                .rlike("(<script)|(</script>)|(onerror=)|(alert\\()|(img src)|(javascript:)|(onload=)"))
                .withColumn("attack_type", lit("XSS"));

        long sqliTotal = sqli.count();
        long xssTotal = xss.count();

        StructType schema = new StructType()
                .add("attack_type", "string")
                .add("count", "long");

        Dataset<Row> results = spark.createDataFrame(
                Arrays.asList(
                        RowFactory.create("SQLi", sqliTotal),
                        RowFactory.create("XSS", xssTotal)),
                schema).orderBy(desc("count"));

        results.show(false);

        results.write()
                .mode("overwrite")
                .parquet("data/output/sqli_xss_detection");

        spark.stop();
        System.exit(0);
    }

}