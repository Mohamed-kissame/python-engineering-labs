import json
import os



import json


def load_security_logs(file_path: str) -> list[dict]:
    """Load and validate security events from a JSON file."""

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            logs = json.load(file)

    except FileNotFoundError as error:
        raise FileNotFoundError(
            f"Security log file not found: {file_path}"
        ) from error

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in '{file_path}': {error}"
        ) from error

   
    if not isinstance(logs, list):
        raise TypeError("JSON root must be a list of security events")

   
    for index, event in enumerate(logs, start=1):
        try:
            validate_log(event)
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"Invalid security event #{index}: {error}"
            ) from error

    return logs


def analyze_security_logs(logs: list[dict]) -> dict:
    """Calculate basic security log statistics."""
    slow_responses = 0
    unique_ips = set()

    for entry in logs:
        ip = entry["ip"]
        response_time = entry["response_ms"]

        unique_ips.add(ip)

        if response_time > 200:
            slow_responses += 1

    return {
        "total_events": len(logs),
        "unique_ips": len(unique_ips),
        "slow_responses": slow_responses,
    }


def validate_log(event : dict) -> None :
    
    if type(event) is not dict :
        raise TypeError("Security event must be a dictionary") 
    
    required_fields = {"ip", "status", "response_ms"}

    missing_fields = required_fields - event.keys()
    
    if missing_fields :
        raise ValueError(f"Missing Fields : {missing_fields}")
    
    if type(event['ip']) is not str :
        raise TypeError("ip Type Must be a string ")
    
    if not event['ip'].strip() :
        raise ValueError("Ip cannot be empty")
    
    if type(event['status']) is not int :
        raise TypeError("Status must be a int")
    
    if not 100 <= event['status'] <= 599 :
        raise ValueError("Invalid HTTP status")
    
    if type(event['response_ms']) not in (int , float) :
        raise TypeError("Response Time must be numeric")
    if event['response_ms'] < 0 :
        raise ValueError("Response time cannot be negative")

def display_report(logs: list[dict], report: dict) -> None:
    """Display security events and their statistics."""
    print("===== SECURITY LOG REPORT =====")

    for entry in logs:
        print(
            f"IP: {entry['ip']} | "
            f"Status: {entry['status']} | "
            f"Time: {entry['response_ms']} ms"
        )

    print("\n===== SUMMARY =====")
    print(f"Total events: {report['total_events']}")
    print(f"Unique IPs: {report['unique_ips']}")
    print(f"Slow responses: {report['slow_responses']}")


if __name__ == "__main__":
   try:
    logs = load_security_logs("security_logs.json")
    print(f"Loaded {len(logs)} security events")

   except (FileNotFoundError, ValueError, TypeError) as error:
    print(f"Error: {error}")
   
   report = analyze_security_logs(logs)
   display_report(logs, report)
