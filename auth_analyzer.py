import re
import json
import datetime

def analyze_and_output():
    log_file = "dummy_syslog.log"
    threshold = 3
    pattern = r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"
    
    # Initialize threat collection structure
    report = {"timestamp": datetime.datetime.now().isoformat(), "alerts": []}
    
    try:
        with open(log_file, "r") as file:
            failed_ips = {}
            for line in file:
                match = re.search(pattern, line)
                if match:
                    ip = match.group(1)
                    failed_ips[ip] = failed_ips.get(ip, 0) + 1
            
            # Map detections to structured JSON
            for ip, count in failed_ips.items():
                report["alerts"].append({
                    "ip": ip,
                    "count": count,
                    "severity": "CRITICAL" if count >= threshold else "SUSPICIOUS"
                })
        
        # Output to stdout for n8n consumption
        print(json.dumps(report))
        
    except FileNotFoundError:
        print(json.dumps({"error": "Log file not found"}))

if __name__ == "__main__":
    analyze_and_output()
