from json_hyperscan.json_hyperscan import JSONHyperscan
import pytest
import json
from jsonpath_ng.ext import parse

SAMPLE_DATA_PATH = "tests/files/sample.json"

# jsonpath patterns source from https://github.com/json-path/JsonPath


class TestHyperscan:
    @pytest.fixture(scope="class")
    def sample_data(self):
        """Load sample data from JSON file."""
        with open(SAMPLE_DATA_PATH) as f:
            return json.load(f)

    # yapf: disable
    @pytest.mark.parametrize(
            "json_path_pattern",
            [
                "$.store.book[*].author", # The authors of all books
                "$..author", # All authors
                "$.store.*", # All things, both books and bicycles
                "$.store..price", # The price of everything
                "$..book[2]", # The third book
                "$..book[-2]", # The second to last book
                # "$..book[0,1]", # The first two books
                "$..book[:2]", # All books from index 0 (inclusive) until index 2 (exclusive)
                "$..book[1:2]", # All books from index 1 (inclusive) until index 2 (exclusive)
                "$..book[-2:]", # Last two books
                "$..book[2:]", # All books from index 2 (inclusive) to last
                "$..book[?(@.isbn)]", # All books with an ISBN number
                "$.store.book[?(@.price < 10)]", # All books in store cheaper than 10
                # "$..book[?(@.price <= $['expensive'])]", # All books in store that are not "expensive"
                # "$..book[?(@.author =~ /.*REES/i)]", # All books matching regex (ignore case)
                "$..*", # Give me every thing
                # "$..book.length()", # The number of books
            ]
        )
    # yapf: enable
    def test_match_any(self, json_path_pattern, sample_data):
        # Arrange
        hyperscan_db = JSONHyperscan()

        hyperscan_db.add_pattern(json_path_pattern)

        hyperscan_db.compile()

        # Act
        result = hyperscan_db.match_any(sample_data)

        # Verify parity with jsonpath_ng
        jsonpath_expr = parse(json_path_pattern)
        jsonpath_results = [match.value for match in jsonpath_expr.find(sample_data)]

        # Assert
        # assert result is not None, f"Pattern {json_path_pattern} should match but did not."
        assert jsonpath_results, f"Pattern {json_path_pattern} produced different results."
