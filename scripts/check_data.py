import pandas as pd

df = pd.read_csv("cybersecurity_threat_detection_logs.csv")

print("Shape:", df.shape)

print("\nColumns:")
print(df.columns)

print("\nMissing values:")
print(df.isnull().sum())

print("\nData types:")
print(df.dtypes)

print("\nDuplicates:")
print(df.duplicated().sum())

print("\nSample:")   
print(df.head())