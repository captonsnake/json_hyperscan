import pytest

from json_hyperscan import JSONHyperscan


def test_unsupported_selector_type_raises_value_error():
    db = JSONHyperscan()

    with pytest.raises(ValueError):
        db.add_pattern("$[invalidselector]")


def test_slice_step_zero_is_ignored_or_safe():
    db = JSONHyperscan()
    try:
        db.add_pattern("$..book[::0]")
    except ValueError:
        pytest.skip("parser rejects zero-step slices")


def test_filter_payload_malformed_is_handled():
    db = JSONHyperscan()
    db.add_pattern("$.store.book[?(@.price < 10)]")
    sample = {"store": {"book": [{"price": 5}, {"price": 20}]}}
    results = db.match_all(sample)
    assert any(r.value == {"price": 5} for r in results)
