import os
import numpy as np
from scapy.all import rdpcap, IP
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

PCAP_DIR = "data/closed_world/"
MAX_PACKETS = 1500 

def extract_features(pcap_path):
    try:
        packets = rdpcap(pcap_path)
    except Exception: return None
    if len(packets) < 10: return None

    try: client_ip = packets[0][IP].src
    except IndexError: return None 

    seq_features =[]
    total_in = 0
    total_out = 0

    for p in packets:
        if IP in p:
            size = p[IP].len
            if p[IP].src == client_ip:
                seq_features.append(size)
                total_out += size
            else:
                seq_features.append(-size)
                total_in += size
        if len(seq_features) >= MAX_PACKETS: break

    if len(seq_features) < MAX_PACKETS:
        seq_features.extend([0] * (MAX_PACKETS - len(seq_features)))

    return[len(packets), total_in, total_out] + seq_features

def main():
    X, y = [],[]
    for filename in os.listdir(PCAP_DIR):
        if not filename.endswith(".pcap"): continue
        filepath = os.path.join(PCAP_DIR, filename)
        features = extract_features(filepath)
        if features is not None:
            X.append(features)
            y.append(filename.split('_')[0])

    if not X: return print("Error: No pcaps found.")
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=150, max_depth=20, random_state=42)
    clf.fit(X_train, y_train)
    
    print(f"\n✅ PRELIMINARY ACCURACY: {accuracy_score(y_test, clf.predict(X_test)) * 100:.2f}%")

if __name__ == "__main__":
    main()