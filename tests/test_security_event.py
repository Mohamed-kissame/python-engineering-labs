from security_event import SecurityEvent
import pytest

@pytest.mark.parametrize(
    "status, expected",
    [
        (200, False),
        (301, False),
        (404, True),
        (500, True),
    ]
)
def test_http_error_detection(status, expected):
    event = SecurityEvent("192.168.1.10", status, 120)

    assert event.is_error() is expected
    
def test_empty_ip():
    with pytest.raises(ValueError, match="IP cannot be empty"):
     SecurityEvent("", 200, 120)
       
def test_invalid_status():
    with pytest.raises(ValueError):
       SecurityEvent("192.168.1.10", 700, 120)
       
def test_invalid_response_time():
    with pytest.raises(TypeError):
      SecurityEvent("192.168.1.10", 500, "120")