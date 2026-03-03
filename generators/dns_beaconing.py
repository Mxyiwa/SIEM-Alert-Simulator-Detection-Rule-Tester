from faker import Faker
import random
import json
from datetime import datetime, timedelta

fake = Faker()

# Simulated C2 domains — these look like real malware callback domains
C2_DOMAINS = [
    "update-service.ddns.net",
    "telemetry-check.xyz",
    "cdn-delivery.top",
    "sync-api.info",
    "metrics-collector.online"
]

def generate_dns_beaconing_logs(num_beacons=40, infected_host=None):
    
    logs = []
    
    # The infected internal machine making the beaconing calls
    if infected_host is None:
        infected_host = fake.ipv4_private()
    
    # The C2 domain being called home to — consistent across all beacons
    c2_domain = random.choice(C2_DOMAINS)
    
    # DNS resolver the host is using
    dns_resolver = "8.8.8.8"
    
    # Beaconing starts from some point in the past
    start_time = datetime.now() - timedelta(hours=2)
    
    for i in range(num_beacons):
        
        # KEY PATTERN — regular interval with slight jitter to mimic real C2 behaviour
        # Most C2 frameworks add small random jitter to avoid detection by fixed-interval rules
        beacon_interval = 30  # seconds between beacons
        jitter = random.uniform(-3, 3)  # small variation
        timestamp = start_time + timedelta(seconds=i * (beacon_interval + jitter))
        
        # DNS response — sometimes gets an answer, sometimes times out
        response = random.choice(["NOERROR", "NOERROR", "NOERROR", "TIMEOUT"])
        
        log_entry = {
            "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
            "event_type": "dns_query",
            "source_ip": infected_host,
            "dest_ip": dns_resolver,
            "dest_port": 53,
            "query_domain": c2_domain,
            "query_type": "A",
            "response_code": response,
            "protocol": "DNS"
        }
        
        logs.append(log_entry)
    
    return logs


def save_logs(logs, filepath="sample_logs/dns_beaconing.json"):
    with open(filepath, "w") as f:
        json.dump(logs, f, indent=2)
    print(f"[+] Saved {len(logs)} DNS beaconing log entries to {filepath}")


if __name__ == "__main__":
    logs = generate_dns_beaconing_logs(num_beacons=40)
    save_logs(logs)