from security_event import SecurityEvent
import json

class SecurityLogLoader:

    def load_security_logs(self, file_path: str) -> list[SecurityEvent]:
        """Read JSON and return validated SecurityEvent objects."""

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
            raise TypeError("JSON root must be a list")

        events: list[SecurityEvent] = []

        for index, log in enumerate(logs, start=1):
            if not isinstance(log, dict):
                raise TypeError(
                    f"Security event #{index} must be a dictionary"
                )

            try:
                event = SecurityEvent(**log)
            except (TypeError, ValueError) as error:
                raise ValueError(
                    f"Invalid security event #{index}: {error}"
                ) from error

            events.append(event)

        return events