# ----------------------------------------
# SIEM Lite - Threat Detection & Mitigation
# Supports both auth.log and CSV formats
# ----------------------------------------

import re
import sys
import json


# ----------------------------------------
# Extract IPs (Log + CSV Support)
# ----------------------------------------
def extract_ips(log_data):
    """
    Extract IP addresses from:
    1. auth.log → only 'Failed password' entries
    2. CSV → generic IP extraction (fallback)
    """

    # Pattern for auth.log (strict)
    log_pattern = r'Failed password.*?(\d+\.\d+\.\d+\.\d+)'
    ips = re.findall(log_pattern, log_data)

    # If no matches, assume CSV and extract all IPs
    if not ips:
        csv_pattern = r'(\d+\.\d+\.\d+\.\d+)'
        ips = re.findall(csv_pattern, log_data)

    return ips


# ----------------------------------------
# Count IP occurrences
# ----------------------------------------
def count_ips(ip_list):
    ip_count = {}

    for ip in ip_list:
        if ip in ip_count:
            ip_count[ip] += 1
        else:
            ip_count[ip] = 1

    return ip_count


# ----------------------------------------
# Detect malicious IPs
# ----------------------------------------
def detect_malicious_ips(ip_count, threshold):
    malicious = []

    for ip, count in ip_count.items():
        if count >= threshold:
            malicious.append(ip)

    return malicious


# ----------------------------------------
# Main Function
# ----------------------------------------
def main():

    # Validate command-line arguments
    if len(sys.argv) != 3:
        print("Usage: python task2.py <log_or_csv_file> <threshold>")
        return

    file_name = sys.argv[1]

    # Validate threshold
    try:
        threshold = int(sys.argv[2])
    except ValueError:
        print("Error: Threshold must be a number.")
        return

    # Read file with error handling
    try:
        with open(file_name, "r") as file:
            log_data = file.read()
    except FileNotFoundError:
        print("Error: File not found.")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # Step 1: Extract IPs using regex
    ip_list = extract_ips(log_data)

    # Step 2: Count occurrences
    ip_count = count_ips(ip_list)

    # Step 3: Detect attackers
    malicious_ips = detect_malicious_ips(ip_count, threshold)

    # Step 4: Export JSON
    output = {
        "input_file": file_name,
        "threshold": threshold,
        "total_malicious_ips": len(malicious_ips),
        "malicious_ips": malicious_ips
    }

    try:
        with open("malicious_ips.json", "w") as json_file:
            json.dump(output, json_file, indent=4)
    except Exception as e:
        print(f"Error writing JSON: {e}")
        return

    # Output message
    print("\nDetection complete.")
    print(f"File processed: {file_name}")
    print(f"Malicious IPs found: {len(malicious_ips)}")
    print("Results saved to malicious_ips.json")


# ----------------------------------------
# Run Program
# ----------------------------------------
if __name__ == "__main__":
    main()