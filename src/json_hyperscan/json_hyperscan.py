from collections import defaultdict
from typing import Any


class State:
    """A state in the hyperscan automaton."""

    def __init__(self, state_id: int) -> None:
        self.id = state_id
        self.transitions = defaultdict(set)
        self.accepting = False


class JSONHyperscan:
    def __init__(self, patterns: list[str] | None = None) -> None:
        self.__database: list[State] = []
        self.root_state: State = self.__new_state()

        for pattern in patterns or []:
            self.add_pattern(pattern)

    def __new_state(self) -> State:
        state = State(len(self.__database))
        self.__database.append(state)
        return state

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
