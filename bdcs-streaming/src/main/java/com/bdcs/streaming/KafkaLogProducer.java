package com.bdcs.streaming;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;

import java.util.Properties;
import java.util.Random;

public class KafkaLogProducer {

    public static void main(String[] args) throws Exception {

        String topic = "cybersecurity-logs";

        Properties props = new Properties();
        props.put("bootstrap.servers", "kafka:9092");
        props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");

        KafkaProducer<String, String> producer = new KafkaProducer<>(props);
        Random rand = new Random();

        System.out.println("=== Starting Kafka Producer ===");

        // Envoi de 10 tentatives de brute force (failed login)
        for (int i = 0; i < 10; i++) {
            String log = "{"
                    + "\"timestamp\":\"2026-05-19 20:" + String.format("%02d", rand.nextInt(60)) + "\","
                    + "\"source_ip\":\"192.168.1.100\","
                    + "\"dest_ip\":\"10.0.0.1\","
                    + "\"request\":\"/login\","
                    + "\"status\":401,"
                    + "\"bytes\":500,"
                    + "\"threat_label\":\"malicious\","
                    + "\"message\":\"failed login attempt\""
                    + "}";

            producer.send(new ProducerRecord<>(topic, log));
            System.out.println("Sent: " + log);
            Thread.sleep(1000);
        }

        producer.close();
        System.out.println("=== Producer finished ===");
    }
}
