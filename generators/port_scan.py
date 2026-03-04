from faker import Faker
import random
import json
from datetime import datetime, timedelta

fake = Faker()

# Common ports a scanner would hit
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 1433, 1723, 3306, 3389,
    5900, 6379, 8080, 8443, 9200, 27017
]

def generate_port_scan_logs(num_targets=50, scanner_ip=None):
    
    logs = []
    
    # The scanner — one IP probing many ports
    if scanner_ip is None:
        scanner_ip = fake.ipv4()
    
    # The target machine being scanned
    target_ip = fake.ipv4_private()
    
    start_time = datetime.now() - timedelta(minutes=5)
    
    # Shuffle ports so scan doesn't go in perfect order — more realistic
    ports_to_scan = random.sample(COMMON_PORTS, min(num_targets, len(COMMON_PORTS)))
    # If num_targets exceeds our list, add random high ports too
    if num_targets > len(COMMON_PORTS):
        extra_ports = [random.randint(1024, 65535) for _ in range(num_targets - len(COMMON_PORTS))]
        ports_to_scan += extra_ports
    
    for i, port in enumerate(ports_to_scan):
        
        # KEY PATTERN — very fast, fractions of a second between each probe
        timestamp = start_time + timedelta(seconds=i * random.uniform(0.1, 0.5))
        
        # Most ports are closed or filtered — occasionally one is open
        connection_state = random.choices(
            ["closed", "filtered", "open"],
            weights=[60, 30, 10]  # 10% chance of open port
        )[0]
        
        log_entry = {
            "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
            "event_type": "connection_attempt",
            "source_ip": scanner_ip,
            "dest_ip": target_ip,
            "dest_port": port,
            "connection_state": connection_state,
            "protocol": "TCP",
            "packets_sent": 1
        }
        
        logs.append(log_entry)
    
    return logs


def save_logs(logs, filepath="sample_logs/port_scan.json"):
    with open(filepath, "w") as f:
        json.dump(logs, f, indent=2)
    print(f"[+] Saved {len(logs)} port scan log entries to {filepath}")


if __name__ == "__main__":
    logs = generate_port_scan_logs(num_targets=50)
    save_logs(logs)