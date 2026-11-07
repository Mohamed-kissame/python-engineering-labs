from security_event import SecurityEvent

class SecurityLogAnalyzer:

    def analyze_security_logs( self, events: list[SecurityEvent],slow_threshold_ms: int = 1000) -> dict:
        