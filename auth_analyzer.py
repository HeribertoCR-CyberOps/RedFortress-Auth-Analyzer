import re

# SSP Enterprise Rule: Threshold for locking out an IP
FAILURE_THRESHOLD = 3

# Regex to extract IP addresses specifically from failed SSH attempts
regex_pattern = r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"
failed_ips = {}

print("[*] Initializing Red Fortress Authentication Analyzer...")

try:
    with open("dummy_syslog.log", "r") as file:
        for line in file:
            match = re.search(regex_pattern, line)
            if match:
                ip = match.group(1)
                # Count the failures per IP
                failed_ips[ip] = failed_ips.get(ip, 0) + 1

    print("\n--- SSP THREAT DETECTIONS ---")
    for ip, count in failed_ips.items():
        if count >= FAILURE_THRESHOLD:
            print(f"[!] MALICIOUS IP BLOCKED: {ip} (Failures: {count})")
        else:
            print(f"[*] Suspicious IP Monitored: {ip} (Failures: {count})")

except FileNotFoundError:
    print("[-] CRITICAL ERROR: Target log file not found.")