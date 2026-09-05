import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODELS_DIR, exist_ok=True)
MODEL_PATH = os.path.join(MODELS_DIR, "rf_ids_model.pkl")

FEATURE_KEYS = ["arbitration_id", "iat", "fps", "entropy", "hamming_dist", "id_freq", "dlc"]

def generate_synthetic_dataset(num_samples=2000):
    """Generates synthetic CAN feature dataset based on Car-Hacking dataset distributions."""
    np.random.seed(42)
    X, y = [], []
    
    # 1. Normal traffic (Class 0)
    for _ in range(int(num_samples * 0.7)):
        arb_id = np.random.choice([0x0C4, 0x1A0, 0x2B0, 0x000])
        iat = np.random.uniform(0.015, 0.10)
        fps = np.random.uniform(10, 60)
        entropy = np.random.uniform(0.5, 2.5)
        hamming = np.random.randint(0, 4)
        id_freq = np.random.uniform(0.1, 0.4)
        dlc = 8.0
        X.append([arb_id, iat, fps, entropy, hamming, id_freq, dlc])
        y.append(0)
        
    # 2. DoS Attack (Class 1) - High frequency ID 0x000, iat near zero, high fps
    for _ in range(int(num_samples * 0.1)):
        X.append([0x000, np.random.uniform(0.0001, 0.002), np.random.uniform(300, 1000), 0.0, 0.0, 0.9, 8.0])
        y.append(1)
        
    # 3. Fuzzing Attack (Class 1) - High entropy, random IDs, high hamming distance
    for _ in range(int(num_samples * 0.1)):
        arb_id = np.random.choice([0x0C4, 0x1A0, 0x300, 0x7FF])
        X.append([arb_id, np.random.uniform(0.001, 0.01), np.random.uniform(100, 500), np.random.uniform(2.8, 3.0), np.random.randint(10, 30), 0.05, 8.0])
        y.append(1)

    # 4. Spoofing Attack (Class 1) - Rapid bursts of fixed payload on ID 0x1A0
    for _ in range(int(num_samples * 0.1)):
        X.append([0x1A0, np.random.uniform(0.001, 0.005), np.random.uniform(150, 400), 0.5, 0.0, 0.7, 8.0])
        y.append(1)

    return np.array(X), np.array(y)

def train_and_save_model():
    print("[IDS Model Trainer] Generating dataset & training Random Forest model...")
    X, y = generate_synthetic_dataset(num_samples=5000)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    rf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
    rf.fit(X_train, y_train)
    
    y_pred = rf.predict(X_test)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print("=== IDS Machine Learning Model Evaluation ===")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))
    
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(rf, f)
    print(f"[IDS Model Trainer] Model saved to {MODEL_PATH}")
    return rf

if __name__ == "__main__":
    train_and_save_model()
