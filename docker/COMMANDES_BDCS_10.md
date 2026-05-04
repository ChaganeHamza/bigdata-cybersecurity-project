

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