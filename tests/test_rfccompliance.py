"""Test Python JSONPath against the JSONPath Compliance Test Suite.

The CTS is a submodule located in /tests/cts. After a git clone, run
`git submodule update --init` from the root of the repository.

References:
https://github.com/jg-rp/python-jsonpath-rfc9535/tree/main/tests/test_compliance.py
"""

import json
import operator
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

import pytest

from json_hyperscan.json_hyperscan import JSONHyperscan


@dataclass
class Case:
    name: str
    selector: str
    document: Any = None
    result: Any = None
    result_paths: Optional[List[Any]] = None
    results: Optional[List[Any]] = None
    results_paths: Optional[List[Any]] = None
    invalid_selector: Optional[bool] = None
    tags: List[str] = field(default_factory=list)


SKIP: Dict[str, str] = {
    "basic, name shorthand, extended unicode ☺": "Unicode handling not implemented fully yet.",
}


def cases() -> List[Case]:
    with open("tests/jsonpath-compliance-test-suite/cts.json", encoding="utf8") as fd:
        data = json.load(fd)
    return [Case(**case) for case in data["tests"]]


def valid_cases() -> List[Case]:
    return [case for case in cases() if not case.invalid_selector]


def invalid_cases() -> List[Case]:
    return [case for case in cases() if case.invalid_selector]


@pytest.mark.parametrize("case", valid_cases(), ids=operator.attrgetter("name"))
def test_compliance(case: Case) -> None:
    if case.name in SKIP:
        pytest.skip(reason=SKIP[case.name])  # no cov

    assert case.document is not None
    hyperscan_db = JSONHyperscan()
    hyperscan_db.add_pattern(case.selector)

    result = hyperscan_db.find_all(case.document)
    if case.results is None:
        assert result == case.result, f"Case {case.name} failed."
    else:
        assert result in case.results, f"Case {case.name} failed."


# @pytest.mark.parametrize("case", invalid_cases(), ids=operator.attrgetter("name"))
# def test_invalid_selectors(case: Case) -> None:
#     if case.name in SKIP:
#         pytest.skip(reason=SKIP[case.name])  # no cov

#     with pytest.raises(jsonpath.JSONPathError):
#         jsonpath.compile(case.selector)
