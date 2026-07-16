# 1_train_model.py
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

print("🚀 Step 1: Load Dataset...")

# Load atau generate sample
try:
    df = pd.read_parquet('Data/Syn-training.parquet')
except FileNotFoundError:
    print("⚠️ Sample not found, generating new...")
    # Quick generate
    np.random.seed(42)
    n = 5000
    data = {
        'Flow Duration': np.random.randint(1000, 100000, n),
        'Total Fwd Packets': np.random.randint(1, 100, n),
        'Total Backward Packets': np.random.randint(1, 100, n),
        'Flow Bytes/s': np.random.randint(1000, 100000, n),
        'Flow Packets/s': np.random.randint(10, 1000, n),
        'SYN Flag Count': np.random.randint(0, 10, n),
        'ACK Flag Count': np.random.randint(0, 50, n),
        'Label': ['BENIGN'] * (n//2) + ['DDoS'] * (n//2)
    }
    df = pd.DataFrame(data)
    os.makedirs('data', exist_ok=True)
    df.to_parquet('data/sample_ddos.parquet', index=False)

print(f"📊 Dataset: {len(df)} samples")
print(f"📊 Label distribution:\n{df['Label'].value_counts()}")

# Features selection
features = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Flow Bytes/s', 'Flow Packets/s', 'SYN Flag Count', 'ACK Flag Count']

X = df[features]
y = df['Label']

print("\n🚀 Step 2: Training Model...")

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train Random Forest
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n✅ TRAINING DONE!")
print(f"📈 Accuracy: {accuracy*100:.2f}%")
print(f"\n📋 Classification Report:")
print(classification_report(y_test, y_pred))

# Save model
os.makedirs('models', exist_ok=True)
joblib.dump(model, 'models/ddos_model.pkl')
print(f"\n💾 Model saved to: models/ddos_model.pkl")