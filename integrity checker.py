import os
import hashlib
import time
import json

# Target directory to monitor
target_directory = 'target/directory'
baseline ={}
# Baseline file to store the hashes
baseline_file = 'baseline.json'

with open('baseline.json', 'w') as file:
    json.dump(baseline, file)

# Function to calculate file hash
def calculate_file_hash(file_path):
    hash_object = hashlib.sha256()
    with open(file_path, 'rb') as file:
        while True:
            data = file.read(65536)
            if not data:
                break
            hash_object.update(data)
    return hash_object.hexdigest()

# Function to load the baseline hashes
def load_baseline():
    baseline = {}
    if os.path.exists(baseline_file):
        with open(baseline_file, 'r') as file:
            baseline = json.load(file)
    return baseline

# Function to save the baseline hashes
def save_baseline(baseline):
    with open(baseline_file, 'w') as file:
        json.dump(baseline, file)

# Function to check for modifications
def check_modifications():
    baseline = load_baseline()
    modified_files = []

    # Traverse the target directory and calculate current hashes
    for root, dirs, files in os.walk(target_directory):
        for file in files:
            file_path = os.path.join(root, file)
            current_hash = calculate_file_hash(file_path)

            # Compare current hash with the baseline hash
            if file_path in baseline and baseline[file_path] != current_hash:
                modified_files.append(file_path)

            # Update the baseline with the current hash
            baseline[file_path] = current_hash

    # Save the updated baseline
    save_baseline(baseline)

    return modified_files

# Main loop to periodically check for modifications
def monitor_directory(interval):
    while True:
        modified_files = check_modifications()

        # Alert if modifications are detected
        if modified_files:
            print('Modifications detected:')
            for file_path in modified_files:
                print(file_path)
            print('----------------------------------------')

        time.sleep(interval)

# Run the monitoring loop
monitor_directory(60)  # Check every 60 seconds
