from faker import Faker
import random
import json
from datetime import datetime, timedelta

fake = Faker()

def generate_rdp_spray_logs(num_attempts=60, target_ip=None):
    
    logs = []
    
    # RDP spray — one attacker trying many different usernames across the network
    attacker_ip = fake.ipv4()
    
    # Multiple target machines — spray hits different hosts unlike brute force
    target_ips = [fake.ipv4_private() for _ in range(10)]
    
    # Large list of usernames — spray tries different users not the same one repeatedly
    usernames = [fake.user_name() for _ in range(20)]
    usernames += ["administrator", "admin", "guest", "service", "backup", "helpdesk"]
    
    start_time = datetime.now() - timedelta(minutes=15)
    
    for i in range(num_attempts):
        
        # Attempts spread slightly further apart than brute force — spray is slower to avoid lockout
        timestamp = start_time + timedelta(seconds=i * random.uniform(3, 8))
        
        # Almost all failed — success very rare in a spray
        status = "failed" if i < num_attempts - 1 else random.choice(["failed", "success"])
        
        log_entry = {
            "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
            "event_type": "rdp_login",
            "source_ip": attacker_ip,
            "dest_ip": random.choice(target_ips),   # different host each time
            "dest_port": 3389,
            "username": random.choice(usernames),    # different username each time
            "status": status,
            "protocol": "RDP"
        }
        
        logs.append(log_entry)
    
    return logs


def save_logs(logs, filepath="sample_logs/rdp_spray.json"):
    with open(filepath, "w") as f:
        json.dump(logs, f, indent=2)
    print(f"[+] Saved {len(logs)} RDP spray log entries to {filepath}")


if __name__ == "__main__":
    logs = generate_rdp_spray_logs(num_attempts=60)
    save_logs(logs)