
import json

from security_event import SecurityEvent
from security_log_loader import SecurityLogLoader


def test_load_valid_security_logs(tmp_path):
    """Verify that valid JSON logs become SecurityEvent objects."""

   
    logs = [
        {"ip": "192.168.1.10", "status": 200, "response_ms": 120},
        {"ip": "192.168.1.11", "status": 404, "response_ms": 350},
    ]

    file_path = tmp_path / "security_logs.json"
    file_path.write_text(json.dumps(logs), encoding="utf-8")

    
    loader = SecurityLogLoader()
    events = loader.load_security_logs(str(file_path))

    assert len(events) == 2
    assert all(isinstance(event, SecurityEvent) for event in events)

    assert events[0].ip == "192.168.1.10"
    assert events[0].status == 200
    assert events[1].status == 404
    assert events[1].is_error() is True
