
from collections import Counter
from security_event import SecurityEvent


class SecurityLogAnalyzer:

    def analyze_security_logs(self,events: list[SecurityEvent], slow_threshold_ms: int = 1000 ) -> dict:
        """Analyze security events and return a summary report."""

        if type(slow_threshold_ms) is not int:
            raise TypeError("Slow response threshold must be an integer")

        if slow_threshold_ms < 0:
            raise ValueError("Slow response threshold cannot be negative")

        unique_ips = set()
        status_frequencies = Counter()
        error_events = 0
        slow_responses = 0

        for event in events:
            unique_ips.add(event.ip)
            status_frequencies[event.status] += 1

            if event.is_error():
                error_events += 1

            if event.response_ms > slow_threshold_ms:
                slow_responses += 1

        return {
            "total_events": len(events),
            "unique_ips": len(unique_ips),
            "error_events": error_events,
            "slow_responses": slow_responses,
            "status_frequencies": dict(status_frequencies)
        }
