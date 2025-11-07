from collections import defaultdict, deque
from contextlib import suppress
from dataclasses import dataclass
import enum
from typing import Any, Generator, Iterable

import jsonpath_rfc9535
from jsonpath_rfc9535 import segments
from jsonpath_rfc9535 import selectors
from jsonpath_rfc9535.filter_expressions import FilterContext, FilterExpression

_TransitionValueType = str | int | slice | FilterExpression


@dataclass
class Result:
    """A match result from the hyperscan automaton."""

    pattern: str
    value: Any


class _TransitionType(enum.Enum):
    """Types of transitions in the hyperscan automaton."""

    Field = "Field"
    Child = "Child"
    Descendants = "Descendants"
    Index = "Index"
    Slice = "Slice"
    Filter = "Filter"


class _State:
    """A state in the hyperscan automaton."""

    __slots__ = ("transitions", "accepting", "value", "pattern")

    def __init__(self) -> None:
        self.transitions: dict[_TransitionType, list["_State"]] = defaultdict(list)
        self.accepting: bool = False  # An Accepting state indicates a match
        self.value: _TransitionValueType | None = None
        self.pattern: str | None = None


class JSONHyperscan:
    def __init__(self, patterns: list[str] | None = None) -> None:
        """JSON Hyperscan automaton for matching JSONPath patterns.

        :param patterns: Patterns to add to the automaton on initialization, defaults to None
        :type patterns: list[str] | None, optional
        """
        self.__database: list[_State] = []
        self.__start: _State = self.__new_state()

        for pattern in patterns or []:
            self.add_pattern(pattern)

    def __new_state(self) -> _State:
        state = _State()
        self.__database.append(state)
        return state

    def add_pattern(self, pattern: str) -> None:
        """
        Add a JSONPath pattern to the hyperscan automaton.

        :param pattern: The JSONPath pattern to add.
        :type pattern: str
        :raises ValueError: If the pattern is invalid.
        """
        try:
            query: jsonpath_rfc9535.JSONPathQuery = jsonpath_rfc9535.compile(pattern)
        except Exception as e:
            raise ValueError(f"Invalid JSONPath pattern: {pattern}") from e
        states: list[_State] = [self.__start]
        parent_states: Iterable[_State] = (self.__start,)

        for segment in query.segments:
            if isinstance(segment, segments.JSONPathRecursiveDescentSegment):
                recursive_state = self.__new_state()
                for parent_state in parent_states:
                    parent_state.transitions[_TransitionType.Descendants].append(
                        recursive_state
                    )
                parent_states = (recursive_state,)
            elif isinstance(segment, segments.JSONPathChildSegment):
                child_state = self.__new_state()
                for parent_state in parent_states:
                    parent_state.transitions[_TransitionType.Child].append(child_state)
                parent_states = (child_state,)

            next_parent_states = []
            for selector in reversed(segment.selectors):
                next_state = self.__new_state()
                if isinstance(selector, selectors.NameSelector):
                    next_state.value = selector.name
                    transition_type = _TransitionType.Field
                elif isinstance(selector, selectors.WildcardSelector):
                    next_state.value = "*"
                    transition_type = _TransitionType.Field
                elif isinstance(selector, selectors.IndexSelector):
                    next_state.value = selector.index
                    transition_type = _TransitionType.Index
                elif isinstance(selector, selectors.SliceSelector):
                    next_state.value = selector.slice
                    transition_type = _TransitionType.Slice
                elif isinstance(selector, selectors.FilterSelector):
                    next_state.value = selector.expression
                    transition_type = _TransitionType.Filter
                else:
                    # Defensive: explicitly fail for unsupported selector types.
                    raise ValueError(
                        f"Unsupported selector type in pattern '{pattern}': {type(selector)!r}"
                    )

                for parent_state in parent_states:
                    parent_state.transitions[transition_type].append(next_state)
                next_parent_states.append(next_state)
                states.append(next_state)

            parent_states = next_parent_states

        for state in states:
            if not state.transitions:
                state.accepting = True
                state.pattern = pattern

    def _match_helper(self, haystack: list | dict) -> Generator[Result, None, None]:
        """
        Helper method to perform matching on the haystack.

        :param haystack: The JSON data to match against.
        :type haystack: list | dict
        :yield: Match results.
        :rtype: Generator[Result, None, None]
        """
        stack: deque[tuple[_State, Any]] = deque()
        stack.append((self.__start, haystack))
        visited = set()
        while stack:
            state, current_haystack = stack.pop()

            if state.accepting:
                if state.pattern:
                    yield Result(pattern=state.pattern, value=current_haystack)

            for transition, next_states in state.transitions.items():
                for next_state in next_states:
                    state_id = (next_state, id(current_haystack))
                    if state_id in visited:
                        continue
                    visited.add(state_id)

                    if transition == _TransitionType.Descendants:
                        if isinstance(current_haystack, dict):
                            for value in reversed(current_haystack.values()):
                                stack.append((state, value))
                        elif isinstance(current_haystack, list):
                            for item in reversed(current_haystack):
                                stack.append((state, item))
                        stack.append((next_state, current_haystack))

                    elif transition == _TransitionType.Child:
                        stack.append((next_state, current_haystack))

                    elif transition == _TransitionType.Field:
                        field = next_state.value
                        if field == "*":
                            if isinstance(current_haystack, dict):
                                for val in reversed(current_haystack.values()):
                                    stack.append((next_state, val))
                            elif isinstance(current_haystack, list):
                                # Reverse to maintain order when popping from stack
                                for item in reversed(current_haystack):
                                    stack.append((next_state, item))
                        elif (
                            isinstance(current_haystack, dict)
                            and field in current_haystack
                        ):
                            stack.append((next_state, current_haystack[field]))

                    elif transition == _TransitionType.Index:
                        if isinstance(current_haystack, list):
                            index = next_state.value
                            if isinstance(index, int):
                                with suppress(IndexError):
                                    stack.append((next_state, current_haystack[index]))

                    elif transition == _TransitionType.Slice:
                        s = next_state.value
                        if isinstance(s, slice):
                            if s.step == 0:
                                continue
                            if isinstance(current_haystack, list):
                                with suppress(IndexError):
                                    for item in reversed(current_haystack[s]):
                                        stack.append((next_state, item))
                            elif isinstance(current_haystack, dict):
                                with suppress(IndexError):
                                    items = list(current_haystack.values())[s]
                                    for item in reversed(items):
                                        stack.append((next_state, item))

                    elif transition == _TransitionType.Filter:
                        expr = next_state.value
                        if not isinstance(expr, FilterExpression):
                            continue
                        if isinstance(current_haystack, list):
                            for item in reversed(current_haystack):
                                context = FilterContext(
                                    env=jsonpath_rfc9535.DEFAULT_ENV,
                                    root=haystack,
                                    current=item,
                                )
                                if expr.evaluate(context):
                                    stack.append((next_state, item))
                        elif isinstance(current_haystack, dict):
                            for val in reversed(current_haystack.values()):
                                context = FilterContext(
                                    env=jsonpath_rfc9535.DEFAULT_ENV,
                                    root=haystack,
                                    current=val,
                                )
                                if expr.evaluate(context):
                                    stack.append((next_state, val))

    def match_any(self, haystack: Any) -> Result | None:
        """
        Match any result for the patterns in the automaton.

        :param haystack: The JSON data to match against.
        :type haystack: Any
        :return: Any result
        :rtype: Result | None
        """
        return next(self._match_helper(haystack), None)

    def match_all(self, haystack: Any) -> list[Result]:
        """
        Match all results for the patterns in the automaton.

        :param haystack: The JSON data to match against.
        :type haystack: Any
        :return: All matches in the haystack
        :rtype: list[Result]
        """
        return list(self._match_helper(haystack))

    def iter_matches(self, haystack: Any) -> Generator[Result, None, None]:
        yield from self._match_helper(haystack)
