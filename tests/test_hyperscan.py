from json_hyperscan.json_hyperscan import JSONHyperscan
import pytest
import json
from jsonpath_ng import parse

SAMPLE_DATA_PATH = "tests/files/128K.json"


class TestHyperscan:
    @pytest.fixture(scope="class")
    def sample_data(self):
        """Load sample data from JSON file."""
        with open(SAMPLE_DATA_PATH) as f:
            return json.load(f)

    # yapf: disable
    @pytest.mark.parametrize(
            "pattern",
            [
                "abc",
                "def",
                "ghi"
            ]
        )
    # yapf: enable
    def test_match_any(self, pattern, sample_data):
        # Arrange
        hyperscan_db = JSONHyperscan()

        hyperscan_db.add_pattern(pattern)

        hyperscan_db.compile()

        # Act
        result = hyperscan_db.match_any(sample_data)

        # Verify parity with jsonpath_ng
        jsonpath_expr = parse(f"$..{pattern}")
        jsonpath_results = [match.value for match in jsonpath_expr.find(sample_data)]

        # Assert
        assert result is not None, f"Pattern {pattern} should match but did not."
        assert result == jsonpath_results, f"Pattern {pattern} produced different results."
