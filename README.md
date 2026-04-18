# Secure Computing Systems Coursework

## Overview
This repository contains three Python cybersecurity tools developed for the **7018SCN Secure Computing Systems** coursework.

The project demonstrates practical understanding of:

- Secure Software Development  
- Threat Detection & Incident Response  
- Malware Analysis & Digital Forensics  
- Legal, Ethical and Compliance Awareness  

---

## Project Structure

```text
SecureComputingSystems/
│── Task1/
│   ├── task1.py
│   ├── users.json
│   ├── test_cases.txt
│   └── Output_Screenshots/

│── Task2/
│   ├── task2.py
│   ├── auth.log
│   ├── data.csv
│   ├── malicious_ips.json
│   ├── test_cases_summary.txt
│   └── Output_Screenshots/

│── Task3/
│   ├── task3.py
│   ├── sa.py
│   ├── QUARANTINE_VAULT/
│   ├── test_samples/
│   ├── test_cases_summary.txt
│   └── Output_Screenshots/

│── Task 4.docx
│── README.md


#

Task 1 – Secure Authentication System
Description

I created a secure command-line authentication system for storing and validating user credentials safely.

Features
SHA-256 password hashing
Random 16-byte salt generation
Strong password complexity validation
Login verification system
Failed login delay to reduce brute-force attacks
Secure JSON user storage
Run
python task1.py
Task 2 – SIEM Lite Threat Detection Tool
Description

I developed a lightweight SIEM solution that analyses system logs and network data to detect suspicious activity.

Features
Reads auth.log and data.csv
Detects repeated failed login attempts
Detects traffic anomalies
Extracts attacker IP addresses using Regex
Dynamic threshold using command-line arguments
Exports malicious IPs to JSON
Run
python task2.py 5

(5 = alert threshold)

Task 3 – Malware Analysis & Digital Forensics Tool
Description

I built a safe static analysis tool that scans suspicious files without executing them.

Features
SHA-256 file hashing using chunk reading
Checks against known malicious signatures
Automatically quarantines malicious files
EXIF metadata extraction from images
GPS data extraction (if available)
Run
python task3.py
Task 4 – Executive Report

In my report, I discussed:

UK Computer Misuse Act
Ethical penetration testing
Rules of Engagement
GDPR compliance
ISO27001 standards
Requirements

Install dependency:

pip install pillow

Use:

Python 3.10+
How to Use
Download or clone the repository
Open terminal inside the project folder
Run each task individually
Review outputs and screenshots
Author

Shashivardhan Chintha Kunta
Coventry University
7018SCN Secure Computing Systems Coursework

Disclaimer

I created this project strictly for academic purposes only.
These tools should not be used on any system or network without proper authorization.
