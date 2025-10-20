from typing import Any


class State:
    pass


class JSONHyperscan:
    def __init__(self, patterns: list[str] | None = None) -> None:
        self.patterns: set[str] = set(patterns) if patterns else set()
        self.__database: State | None = None

    def compile(self) -> None:
        pass

    def add_pattern(self, pattern: str) -> None:
        if pattern not in self.patterns:
            self.patterns.add(pattern)

    def match_any(self, haystack: list | dict) -> bool:
        return True

    def match_all(self, haystack: list | dict) -> bool:
        return True

    def find_any(self, haystack: list | dict) -> Any:
        return []

    def find_all(self, haystack: list | dict) -> Any:
        return []
