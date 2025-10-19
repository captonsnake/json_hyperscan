from typing import Any


class JSONHyperscan:
    def __init__(self, patterns: list[str] | None = None) -> None:
        self.patterns = patterns or []

    def compile(self) -> None:
        pass

    def add_pattern(self, pattern: str) -> None:
        pass

    def match_any(self, haystack: list | dict) -> bool:
        return True

    def match_all(self, haystack: list | dict) -> bool:
        return True

    def find_any(self, haystack: list | dict) -> Any:
        return []

    def find_all(self, haystack: list | dict) -> Any:
        return []
