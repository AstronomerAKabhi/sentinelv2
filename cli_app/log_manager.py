#!/usr/bin/env python3
"""
Sentinel V2 Log Manager
Saves scan logs to local file automatically
"""

import json
import os
from datetime import datetime

# Log file location
LOG_DIR = os.path.expanduser("~/sentinel_v2/logs")
LOG_FILE = os.path.join(LOG_DIR, "scan_history.json")

def ensure_log_dir():
    """Create logs directory if it doesn't exist"""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

def save_scan_log(scan_data):
    """
    Save scan result to log file
    
    Args:
        scan_data: dict with keys: timestamp, target, threat_level, score, indicators, type
    """
    ensure_log_dir()
    
    # Load existing logs
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as f:
                logs = json.load(f)
        except:
            logs = []
    
    # Add new log entry
    log_entry = {
        "timestamp": scan_data.get("timestamp", datetime.now().timestamp()),
        "datetime": datetime.fromtimestamp(scan_data.get("timestamp", datetime.now().timestamp())).isoformat(),
        "target": scan_data.get("target", ""),
        "type": scan_data.get("type", "unknown"),
        "threat_level": scan_data.get("threat_level", "UNKNOWN"),
        "score": scan_data.get("score", 0),
        "confidence": scan_data.get("confidence", 0.0),
        "indicators": scan_data.get("indicators", []),
        "status": scan_data.get("status", ""),
        "isolation_method": scan_data.get("isolation_method", "")
    }
    
    logs.append(log_entry)
    
    # Keep only last 1000 logs
    if len(logs) > 1000:
        logs = logs[-1000:]
    
    # Save back to file
    with open(LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=2)
    
    return LOG_FILE

def get_logs(limit=100):
    """Get recent scan logs"""
    if not os.path.exists(LOG_FILE):
        return []
    
    try:
        with open(LOG_FILE, 'r') as f:
            logs = json.load(f)
        return logs[-limit:] if limit else logs
    except:
        return []

if __name__ == "__main__":
    # Test
    ensure_log_dir()
    print(f"Log directory: {LOG_DIR}")
    print(f"Log file: {LOG_FILE}")
    print(f"Total logs: {len(get_logs(limit=None))}")
