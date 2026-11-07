from security_log_loader import SecurityLogLoader

if __name__ == "__main__":
    try:
        loader = SecurityLogLoader()
        events = loader.load_security_logs("security_logs.json")

        print(f"Successfully loaded {len(events)} security events.")

        for event in events:
            print(
                f"IP: {event.ip} | "
                f"Status: {event.status} | "
                f"Response: {event.response_ms}ms | "
                f"Is Error: {event.is_error()}"
            )

    except (OSError, TypeError, ValueError) as error:
        print(f"Failed to load security logs: {error}")
