

# BDCS-10 — HBase Setup Commands

## 1. Enter HBase container
docker exec -it hbase bash

## 2. Start HBase shell
hbase shell

## 3. Check status
status

## 4. Create tables
create 'top_malicious_ips', 'stats'
create 'port_scans', 'stats'
create 'sqli_xss_detection', 'stats'
create 'bytes_volume_by_threat_label', 'stats'

## 5. List tables
list



# ----------------------

# BDCS-11 — Create Kafka Topic cybersecurity-logs

## 1. Enter Kafka container
docker exec -it kafka bash

## 2. Create Kafka topic
kafka-topics \
  --create \
  --topic cybersecurity-logs \
  --bootstrap-server localhost:9092 \
  --partitions 1 \
  --replication-factor 1

## 3. Verify topic creation
kafka-topics \
  --list \
  --bootstrap-server localhost:9092