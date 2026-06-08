# utils/helper_functions.py

import datetime
import json
import os
import sys
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import LOG_PATH, REPORT_PATH, SEVERITY


def timestamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_event(message: str, level: str = "INFO") -> None:
    """Append a structured log line to the system log file."""
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    entry = f"[{timestamp()}] [{level}] {message}\n"
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(entry)
    print(entry.strip())


def get_severity(attack_type: str) -> str:
    return SEVERITY.get(attack_type, "UNKNOWN")


def _salvage_json(content: str) -> list:
    """Try to salvage valid JSON objects from corrupted file."""
    try:
        return json.loads(content)
    except:
        pass
    
    try:
        # Find all complete JSON objects by tracking braces
        objects = []
        depth = 0
        current = ""
        
        for char in content:
            current += char
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0 and current.strip():
                    try:
                        obj = json.loads(current)
                        objects.append(obj)
                        current = ""
                    except:
                        pass
        
        return objects if objects else []
    except:
        return []


def save_report(report: dict) -> None:
    """Append a threat report record to the JSON report file (atomic write)."""
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    reports = []
    
    # Try to read existing reports with retry logic
    max_retries = 3
    for attempt in range(max_retries):
        try:
            if os.path.exists(REPORT_PATH):
                with open(REPORT_PATH, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        reports = json.loads(content)
            break
        except (json.JSONDecodeError, IOError):
            if attempt < max_retries - 1:
                time.sleep(0.15)
            else:
                reports = []
    
    reports.append(report)
    
    # Write to temporary file first, then atomic rename
    temp_path = None
    try:
        temp_dir = os.path.dirname(REPORT_PATH) or "."
        os.makedirs(temp_dir, exist_ok=True)
        temp_fd, temp_path = tempfile.mkstemp(dir=temp_dir, suffix=".json")
        with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2)
        os.replace(temp_path, REPORT_PATH)
    except Exception as e:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass
        log_event(f"Warning: save_report error - {e}", "WARNING")


def load_reports() -> list:
    """Load reports with advanced error recovery for concurrent access."""
    if not os.path.exists(REPORT_PATH):
        return []
    
    max_retries = 5
    last_error = None
    
    for attempt in range(max_retries):
        try:
            with open(REPORT_PATH, "r", encoding="utf-8") as f:
                content = f.read().strip()
                
                if not content:
                    return []
                
                # Try standard JSON parse
                try:
                    data = json.loads(content)
                    return data if isinstance(data, list) else []
                except json.JSONDecodeError:
                    # Try salvage on last retry
                    if attempt == max_retries - 1:
                        salvaged = _salvage_json(content)
                        return salvaged
                    # Wait and retry
                    time.sleep(0.2)
                    continue
                    
        except IOError as e:
            last_error = e
            if attempt < max_retries - 1:
                time.sleep(0.2)
            continue
    
    # If all retries fail, return empty list
    if last_error:
        log_event(f"load_reports: Failed after {max_retries} retries", "WARNING")
    
    return []