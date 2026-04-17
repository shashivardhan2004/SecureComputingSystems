# ----------------------------------------
# Malware Analysis & Digital Forensics Tool
# ----------------------------------------

import hashlib
import os
import shutil
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS


# ----------------------------------------
# CONFIGURATION
# ----------------------------------------

QUARANTINE_DIR = "QUARANTINE_VAULT"

# Example known malicious hash
KNOWN_BAD_HASHES = [
    "4594eac418baa8e5156de32869bd2b423dcf4327ee6323899853131f3faf17d4"
]

# Safe directory (current working directory)
SAFE_DIRECTORY = os.getcwd()


# ----------------------------------------
# Safe Hashing (Chunk-Based)
# ----------------------------------------
def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(4096):  # SAFE chunk reading
                sha256.update(chunk)
    except Exception as e:
        print(f"Error hashing file: {e}")
        return None

    return sha256.hexdigest()


# ----------------------------------------
# Quarantine File
# ----------------------------------------
def quarantine_file(file_path):
    try:
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)

        destination = os.path.join(QUARANTINE_DIR, os.path.basename(file_path))

        shutil.move(file_path, destination)

        print(f"File moved to quarantine: {destination}")

    except Exception as e:
        print(f"Error during quarantine: {e}")


# ----------------------------------------
# Extract EXIF GPS Metadata
# ----------------------------------------
def extract_exif(file_path):
    try:
        image = Image.open(file_path)
        exif_data = image._getexif()

        if not exif_data:
            print("No EXIF metadata found.")
            return

        gps_data = {}

        for tag, value in exif_data.items():
            tag_name = TAGS.get(tag, tag)

            if tag_name == "GPSInfo":
                for key in value:
                    gps_tag = GPSTAGS.get(key, key)
                    gps_data[gps_tag] = value[key]

        if gps_data:
            print("GPS Metadata Found:")
            for key, val in gps_data.items():
                print(f"{key}: {val}")
        else:
            print("No GPS metadata found.")

    except Exception:
        print("File is not a valid image or has no EXIF data.")


# ----------------------------------------
# Scan Directory (SAFE)
# ----------------------------------------
def scan_directory(directory):

    # Convert to absolute paths
    directory = os.path.abspath(directory)
    safe_base = os.path.abspath(SAFE_DIRECTORY)

    # Secure whitelist check
    if not os.path.commonpath([directory, safe_base]) == safe_base:
        print("Access denied: Directory not allowed.")
        return

    for root, dirs, files in os.walk(directory):
        for file in files:

            file_path = os.path.join(root, file)

            print(f"\nScanning: {file_path}")

            # Step 1: Safe hashing
            file_hash = calculate_sha256(file_path)

            if not file_hash:
                continue

            print(f"SHA-256: {file_hash}")

            # Step 2: Signature check
            if file_hash in KNOWN_BAD_HASHES:
                print("Malicious file detected!")

                # Step 3: Quarantine
                quarantine_file(file_path)

            # Step 4: EXIF extraction (for images)
            if file.lower().endswith((".jpg", ".jpeg", ".png")):
                extract_exif(file_path)


# ----------------------------------------
# Main Function
# ----------------------------------------
def main():
    directory = input("Enter directory to scan: ").strip()

    if not os.path.exists(directory):
        print("Directory does not exist.")
        return

    scan_directory(directory)


# ----------------------------------------
# Run Program
# ----------------------------------------
if __name__ == "__main__":
    main()