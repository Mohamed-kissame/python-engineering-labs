from security_event import SecurityEvent


def test_successful_http_event():
    event = SecurityEvent("192.168.1.10", 200, 120)

    assert event.is_error() is False
    
def test_client_error_event():
    event = SecurityEvent("192.168.1.10", 404, 120)
    
    assert event.is_error() is True


def test_server_error_event():
    event = SecurityEvent("192.168.1.10", 500, 120)
    
    assert event.is_error() is True