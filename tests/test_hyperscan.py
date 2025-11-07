import jsonpath_rfc9535
from json_hyperscan import JSONHyperscan
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
                pytest.param("$.store.book", id="all_books"), # The list of all books
                pytest.param("$.store.book[*].author", id="authors_of_all_books"), # The authors of all books
                pytest.param("$..author", id="all_authors"), # All authors
                pytest.param("$.store.*", id="all_things"), # All things, both books and bicycles
                pytest.param("$.store..price", id="price_of_everything"), # The price of everything
                pytest.param("$..book[2]", id="third_book"), # The third book
                pytest.param("$..book[-2]", id="second_to_last_book"), # The second to last book
                pytest.param("$..book[0,1]", id="first_two_books, comma sep", marks=pytest.mark.xfail()), # The first two books
                pytest.param("$..book[:2]", id="first_two_books"), # All books from index 0 (inclusive) until index 2 (exclusive)
                pytest.param("$..book[1:2]", id="second_book"), # All books from index 1 (inclusive) until index 2 (exclusive)
                pytest.param("$..book[-2:]", id="last_two_books"), # Last two books
                pytest.param("$..book[2:]", id="books_from_index_2"), # All books from index 2 (inclusive) to last
                pytest.param("$..book[?(@.isbn)]", id="books_with_isbn"), # All books with an ISBN number
                pytest.param("$.store.book[?(@.price < 10)]", id="cheap_books"), # All books in store cheaper than 10
                pytest.param("$..*", id="give_me_everything"), # Give me every thing
            ]
        )
    # yapf: enable
    def test_match_any(self, json_path_pattern, sample_data):
        # Arrange
        hyperscan_db = JSONHyperscan()

        hyperscan_db.add_pattern(json_path_pattern)

        # Act
        result = hyperscan_db.match_any(sample_data)
        assert result
        result = result.value

        # Verify parity with jsonpath_ng
        jsonpath_expr = parse(json_path_pattern)
        jsonpath_results = [match.value for match in jsonpath_expr.find(sample_data)]

        # Assert
        assert result in jsonpath_results, f"Pattern {json_path_pattern} did not match as expected."

    def test_match_all(self, sample_data):
        # Arrange
        patterns = [
            "$.store.book",
            "$.store.book[*].author",
            "$..author",
            "$.store.*",
            "$.store..price",
            "$..book[2]",
            "$..book[-2]",
            "$..book[:2]",
            "$..book[1:2]",
            "$..book[-2:]",
            "$..book[2:]",
            "$..book[?(@.isbn)]",
            "$.store.book[?(@.price < 10)]",
            "$..*",
        ]
        hyperscan_db = JSONHyperscan()

        for pattern in patterns:
            hyperscan_db.add_pattern(pattern)

        # Act
        results = hyperscan_db.match_all(sample_data)

        # Verify parity with jsonpath_ng
        for pattern in patterns:
            jsonpath_expr = jsonpath_rfc9535.compile(pattern)
            expected_values = [match.value for match in jsonpath_expr.find(sample_data)]

            matched_values = [match.value for match in results if match.pattern == pattern]
            for value in matched_values:
                assert value in expected_values, f"Pattern {pattern} did not match as expected."

    @pytest.mark.parametrize(
        "non_matching_pattern",
        [
            pytest.param("$.store.bicycle.doors", id="no_bicycle_doors"),  # No bicycle has a doors field
            pytest.param("$.store.book[?(@.price > 100)]", id="no_expensive_books"),  # No book is more than $100
            pytest.param("$..book[?(@.author == 'Unknown Author')]", id="no_unknown_author"),  # No book by 'Unknown Author'
            pytest.param("$.store.book[10]", id="no_eleventh_book"),  # There is no eleventh book
            pytest.param("$.nonexistent.field", id="no_nonexistent_field"),  # Nonexistent field
            pytest.param("$..book[?(@.price < 0)]", id="no_negative_price_books"),  # No book has a negative price
        ],
    )
    def test_match_none(self, sample_data, non_matching_pattern):
        # Arrange
        hyperscan_db = JSONHyperscan()

        hyperscan_db.add_pattern(non_matching_pattern)

        # Act
        result = hyperscan_db.match_any(sample_data)
        assert not result

        # Verify parity with jsonpath_ng
        jsonpath_expr = parse(non_matching_pattern)
        jsonpath_results = [match.value for match in jsonpath_expr.find(sample_data)]
        assert not jsonpath_results, f"Pattern {non_matching_pattern} should not match but did."

        # Assert
        assert result is None, f"Pattern {non_matching_pattern} should not match but did."
