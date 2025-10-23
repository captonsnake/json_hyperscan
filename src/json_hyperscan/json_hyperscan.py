from collections import defaultdict, deque
from typing import Any, Generator
from jsonpath_ng.ext import parse
from jsonpath_ng.jsonpath import (
    Root,
    Child,
    This,
    Slice,
    Index,
    Fields,
    Where,
    WhereNot,
    Descendants,
    Union,
    Intersect,
)
from jsonpath_ng.ext.filter import Filter


class State:
    """A state in the hyperscan automaton."""

    def __init__(self, state_id: int) -> None:
        self.id = state_id
        self.transitions = defaultdict(set[State])
        self.accepting = False
        self.value = None
        self.patterns = set()


class JSONHyperscan:
    def __init__(self, patterns: list[str] | None = None) -> None:
        self.__database: list[State] = []
        self.root_state: State = self.__new_state()
        self.__patterns = set()

        for pattern in patterns or []:
            self.add_pattern(pattern)

    def __new_state(self, value: Any = None) -> State:
        state = State(len(self.__database))
        self.__database.append(state)
        state.value = value
        return state

    def __add_pattern_states(self, node) -> State:
        if isinstance(node, Root):
            return self.root_state
        elif isinstance(node, (Child, Where, WhereNot, Descendants, Union, Intersect)):
            parent_state = self.__add_pattern_states(node.left)
            child_state = self.__add_pattern_states(node.right)
            parent_state.transitions[node.__class__.__name__].add(child_state)
            return child_state
        elif isinstance(node, This):
            return self.__new_state()
        elif isinstance(node, Slice):
            return self.__new_state((node.start, node.end))
        elif isinstance(node, Index):
            return self.__new_state(node.index)
        elif isinstance(node, Fields):
            return self.__new_state(node.fields)
        elif isinstance(node, Filter):
            return self.__new_state(node.filter)
        else:
            raise NotImplementedError(f"Node type {type(node)} not implemented.")

    def add_pattern(self, pattern: str) -> None:
        compiled_pattern = parse(pattern)
        end_node: State = self.__add_pattern_states(compiled_pattern)
        end_node.accepting = True
        end_node.patterns.add(pattern)
        self.__patterns.add(pattern)

    def _match_helper(
        self, haystack: list | dict
    ) -> Generator[tuple[set[str], Any], None, None]:
        stack: deque[tuple[State, Any]] = deque()
        stack.append((self.root_state, haystack))
        visited = set()
        while stack:
            state, current_haystack = stack.pop()
            for transition, next_states in state.transitions.items():
                if state.accepting:
                    yield (state.patterns, current_haystack)

                for next_state in next_states:
                    state_id = (next_state.id, id(current_haystack))
                    if state_id in visited:
                        continue
                    visited.add(state_id)

                    if transition == "Descendants":
                        stack.append((next_state, current_haystack))
                        if isinstance(current_haystack, dict):
                            for value in current_haystack.values():
                                stack.append((state, value))
                        elif isinstance(current_haystack, list):
                            for item in current_haystack:
                                stack.append((state, item))

                    elif transition == "Child":
                        if isinstance(current_haystack, dict):
                            for key, value in current_haystack.items():
                                stack.append((next_state, value))
                        elif isinstance(current_haystack, list):
                            for item in current_haystack:
                                stack.append((next_state, item))

                    elif transition == "Fields":
                        if isinstance(current_haystack, dict):
                            for field in next_state.value:
                                if field in current_haystack:
                                    stack.append((next_state, current_haystack[field]))

                    elif transition == "Index":
                        if isinstance(current_haystack, list):
                            index = next_state.value
                            if 0 <= index < len(current_haystack):
                                stack.append((next_state, current_haystack[index]))

                    elif transition == "Slice":
                        if isinstance(current_haystack, list):
                            start, end = next_state.value
                            for item in current_haystack[start:end]:
                                stack.append((next_state, item))

                    elif transition == "Filter":
                        filter_expr = next_state.value
                        if isinstance(current_haystack, list):
                            for item in current_haystack:
                                match = list(filter_expr.find(item))
                                if match:
                                    stack.append((next_state, item))

    def match_any(self, haystack: list | dict) -> bool:
        return next(self._match_helper(haystack), None) is not None

    def match_all(self, haystack: list | dict) -> bool:
        matches = set()
        for patterns, _ in self._match_helper(haystack):
            matches.update(patterns)
        return len(matches) == len(self.__patterns)

    def find_any(self, haystack: list | dict) -> Any:
        match = next(self._match_helper(haystack), None)
        return match[1] if match else None

    def find_all(self, haystack: list | dict) -> Any:
        return [value for _, value in self._match_helper(haystack)]

    def iter_matches(
        self, haystack: list | dict
    ) -> Generator[tuple[set[str], Any], None, None]:
        yield from self._match_helper(haystack)
