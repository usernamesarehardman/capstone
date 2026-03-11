import os
import csv
import zipfile
import shutil
from scapy.all import rdpcap, IP

# --- CONFIGURATION ---
ZIP_DIR = "zipped_sites"        # Folder where your 50 zip files are sitting
TMP_DIR = "tmp_pcaps"           # Invisible temp folder Python will create and delete
OUTPUT_FILE = "wf_dataset.csv"  # The final mega CSV
MAX_PACKETS = 1500

def extract_raw_sequence(pcap_path):
    """Reads a pcap and returns a list of directional packet sizes."""
    try:
        packets = rdpcap(pcap_path)
    except Exception:
        return None

    if len(packets) < 10:
        return None

    try:
        client_ip = packets[0][IP].src
    except IndexError:
        return None

    sequence = []
    for p in packets:
        if IP in p:
            size = p[IP].len
            if p[IP].src == client_ip:
                sequence.append(size)   # Outgoing (+1)
            else:
                sequence.append(-size)  # Incoming (-1)
                
        if len(sequence) >= MAX_PACKETS:
            break

    # Pad with zeros if the trace is shorter than MAX_PACKETS
    if len(sequence) < MAX_PACKETS:
        sequence.extend([0] * (MAX_PACKETS - len(sequence)))

    return sequence

def main():
    if not os.path.exists(ZIP_DIR):
        print(f"Error: Could not find the folder '{ZIP_DIR}'.")
        return

    os.makedirs(TMP_DIR, exist_ok=True)
    zip_files =[f for f in os.listdir(ZIP_DIR) if f.endswith('.zip')]
    
    print(f"Found {len(zip_files)} zipped websites. Starting data extraction...")

    # Open the Mega CSV and write the header row
    with open(OUTPUT_FILE, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        header = ['website_label'] +[f'pkt_{i+1}' for i in range(MAX_PACKETS)]
        writer.writerow(header)

        success_count = 0

        # Process one zip file at a time
        for zip_name in zip_files:
            site_label = zip_name.replace('.zip', '')
            zip_path = os.path.join(ZIP_DIR, zip_name)
            
            print(f"📦 Unzipping and processing: {site_label}...")
            
            # Extract this single zip to the temp folder
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(TMP_DIR)
            
            # Find all extracted pcaps
            for root, dirs, files in os.walk(TMP_DIR):
                for file in files:
                    if file.endswith('.pcap'):
                        pcap_path = os.path.join(root, file)
                        
                        # Extract the packet sequence
                        sequence = extract_raw_sequence(pcap_path)
                        
                        if sequence is not None:
                            # Write to the Mega CSV immediately
                            writer.writerow([site_label] + sequence)
                            success_count += 1
            
            # DELETE the extracted pcaps to free up space for the next zip!
            shutil.rmtree(TMP_DIR)
            os.makedirs(TMP_DIR, exist_ok=True)

    # Final cleanup of the temp folder
    shutil.rmtree(TMP_DIR)

    print("==================================================")
    print(f"✅ Data Extraction Complete! Processed {success_count} traces.")
    print(f"📁 Master Dataset saved as '{OUTPUT_FILE}' (Hand this to your ML Engineer!)")

if __name__ == "__main__":
    main()