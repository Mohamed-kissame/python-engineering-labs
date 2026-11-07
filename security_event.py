from dataclasses import dataclass
import math

@dataclass(frozen=True)
class SecurityEvent:
    ip: str
    status: int
    response_ms: int | float

    def __post_init__(self) -> None:
        if type(self.ip) is not str:
            raise TypeError("IP must be a string")

        if not self.ip.strip():
            raise ValueError("IP cannot be empty")

        if type(self.status) is not int:
            raise TypeError("Status must be an integer")

        if not 100 <= self.status <= 599:
            raise ValueError("Status must be between 100 and 599")

        if type(self.response_ms) not in (int, float):
            raise TypeError("Response time must be numeric")

        if not math.isfinite(self.response_ms) or self.response_ms < 0:
            raise ValueError("Response time must be finite and non-negative")

    def is_error(self) -> bool:
        return 400 <= self.status <= 599
