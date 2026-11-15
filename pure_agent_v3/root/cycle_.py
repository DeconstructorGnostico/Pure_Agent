"""§9 Control del ciclo: cycle, max_cycles, REJECT_STREAK → HALT, omega_history, state_events."""


class ControlCycle:
    def __init__(self, max_cycles=100, max_reject_streak=3):
        self.cycle = 0
        self.max_cycles = max_cycles
        self.max_reject_streak = max_reject_streak
        self.reject_streak = 0
        self.omega_history: list[dict] = []
        self.state_events: list[tuple] = []

    def start(self) -> str | None:
        self.cycle += 1
        if self.cycle > self.max_cycles:
            return f"max_cycles={self.max_cycles} Achieved."
        return None

    def close_(self, state: str, metrics: dict) -> str | None:
        self.omega_history.append({"cycle": self.cycle, "state": state, **metrics})
        if state in ("REJECTED", "FAILED"):
            self.reject_streak += 1
        elif state in ("COMMITTED", "VERIFIED"):
            self.reject_streak = 0
        if self.reject_streak >= self.max_reject_streak:
            return f"REJECT_STREAK={self.reject_streak} ≥ {self.max_reject_streak}"
        return None

    def restart(self):
        self.reject_streak = 0
