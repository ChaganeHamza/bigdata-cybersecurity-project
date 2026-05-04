import pandas as pd

df = pd.read_csv("cybersecurity_threat_detection_logs.csv")

# convertir timestamp
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

# sauvegarder
df.to_parquet("clean_logs.parquet")

print("Done ✅")