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

        String[] threats = {"normal", "suspicious", "malicious"};
        String[] endpoints = {"/login", "/admin", "/api", "/search"};

        for (int i = 0; i < 30; i++) {

            String log = "{"
                    + "\"timestamp\":\"2026-05-04 20:" + rand.nextInt(60) + "\","
                    + "\"source_ip\":\"192.168.1." + rand.nextInt(255) + "\","
                    + "\"dest_ip\":\"10.0.0." + rand.nextInt(255) + "\","
                    + "\"request\":\"" + endpoints[rand.nextInt(endpoints.length)] + "\","
                    + "\"status\":200,"
                    + "\"bytes\":" + rand.nextInt(5000) + ","
                    + "\"threat_label\":\"" + threats[rand.nextInt(threats.length)] + "\""
                    + "}";

            producer.send(new ProducerRecord<>(topic, log));

            System.out.println("Sent: " + log);

            Thread.sleep(500);
        }

        producer.close();
    }
}
