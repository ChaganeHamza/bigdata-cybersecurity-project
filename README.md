# bigdata-cybersecurity-project


PS Desktop\tp\TP_BIGDATA\LAB\bigdata-cybersecurity-project> while ($true) { docker cp spark:/opt/spark-apps/brute_force_alerts/. "Desktop\tp\TP_BIGDATA\LAB\bigdata-cybersecurity-project\bdcs-batch\data\output\brute_force_alerts\" ; Start-Sleep -Seconds 10 }

Desktop\tp\TP_BIGDATA\LAB\bigdata-cybersecurity-project\streaming>docker exec -it spark bash -c "/spark/bin/spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.2.1 /opt/spark-apps/SparkStreamingDetection.py"

Desktop\tp\TP_BIGDATA\LAB\bigdata-cybersecurity-project\streaming>python KafkaLogProducer.py

Desktop\tp\TP_BIGDATA\LAB\bigdata-cybersecurity-project\api>python app.py

## SCRUM-8 - Dataset Preparation

- Dataset downloaded from Kaggle
- 6 million logs processed
- No missing values or duplicates
- Timestamp converted to datetime
- Clean dataset saved as parquet format