from faker import Faker
import random
import json
from datetime import datetime, timedelta

fake = Faker()

def generate_ssh_bruteforce_logs(num_attempts=50, target_ip=None):
    
    logs = []
    
    # The attacker — one IP hammering the target
    attacker_ip = fake.ipv4()
    
    # The victim server — fixed IP, or generate one
    if target_ip is None:
        target_ip = fake.ipv4_private()
    
    # Start time — we'll increment it slightly each attempt
    start_time = datetime.now() - timedelta(minutes=10)
    
    # A few usernames the attacker tries over and over
    common_usernames = ["root", "admin", "administrator", "user", "test", fake.user_name()]
    
    for i in range(num_attempts):
        
        # Each attempt is a few seconds apart
        timestamp = start_time + timedelta(seconds=i * random.uniform(1, 5))
        
        # Mostly failed attempts, occasional success at the end
        if i < num_attempts - 2:
            status = "failed"
        else:
            status = random.choice(["failed", "success"])
        
        log_entry = {
            "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
            "event_type": "ssh_login",
            "source_ip": attacker_ip,
            "dest_ip": target_ip,
            "dest_port": 22,
            "username": random.choice(common_usernames),
            "status": status,
            "protocol": "SSH"
        }
        
        logs.append(log_entry)
    
    return logs


def save_logs(logs, filepath="sample_logs/ssh_bruteforce.json"):
    with open(filepath, "w") as f:
        json.dump(logs, f, indent=2)
    print(f"[+] Saved {len(logs)} SSH brute force log entries to {filepath}")


if __name__ == "__main__":
    logs = generate_ssh_bruteforce_logs(num_attempts=50)
    save_logs(logs)