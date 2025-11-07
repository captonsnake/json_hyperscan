JSON Hyperscan
================

A small, fast library that builds a simple "hyperscan" automaton to match many JSONPath (RFC9535-style) expressions against JSON documents. The project provides a compact in-process matcher that aims for parity with `jsonpath_rfc9535`.

Key features
------------
- Add many JSONPath selectors and build a matching automaton
- Query JSON documents for matches efficiently
- Support for field, child, descendant, index, slice and filter selectors
- Small, well-tested core implementation located at `src/json_hyperscan/json_hyperscan.py`

Quick start
-----------

Install (developer/test environment)

This project uses modern Python tooling. Create a virtual environment and install dev dependencies listed in `pyproject.toml`.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .[dev]
```

Note about the compliance test-suite
----------------------------------

The project includes the JSONPath compliance tests as a git submodule at `tests/jsonpath-compliance-test-suite`.
CI checks out submodules automatically, but if you're running tests locally you may need to initialize it first:

```bash
git submodule update --init --recursive
```

Or, if you only need runtime installation (no dev extras):

```bash
pip install -e .
```

Basic usage
-----------

A minimal example using the public API in `JSONHyperscan`:

```python
from json_hyperscan import JSONHyperscan

hs = JSONHyperscan()
hs.add_pattern('$.store.book[*].author')
hs.add_pattern('$..title')

doc = {
	"store": {
		"book": [
			{"author": "Nigel Rees", "title": "Sayings of the Century"},
			{"author": "Evelyn Waugh", "title": "Sword of Honour"}
		]
	}
}

matches = list(hs.iter_matches(doc))
for m in matches:
	print(m)
```

License
-------
See the `LICENSE` file in the repository.

Acknowledgements
----------------
This project uses `jsonpath_rfc9535` for parsing and some tests compare output to other JSONPath implementations. See `pyproject.toml` for the dependency list used in development and testing.

