"""Tests for the optional Argyph code-context adapter (Task 18).

The argyph CLI ships with `index`/`search` stubbed in the current milestone
("not implemented in this milestone"), but its documented MCP `search_code`
response is a JSON object with a `hits` array. `_parse_search` targets that
real documented shape and degrades to `[]` on the stub / any malformed input.
"""

import json

import pytest

from infra.argyph_index import ArgyphIndex, argyph_binary

ARGYPH = argyph_binary()


def test_argyph_binary_discovery_prefers_config():
    assert argyph_binary("/explicit/path/argyph") == "/explicit/path/argyph"


def test_parses_search_output_into_codechunks():
    """The parser maps argyph search output to CodeChunk."""
    idx = ArgyphIndex(binary="/nonexistent/argyph")
    # Matches argyph's documented `search_code` response (docs/tools-reference.md).
    sample = json.dumps(
        {
            "hits": [
                {
                    "chunk_id": "src/auth/session.rs:38:52",
                    "chunk_text": "pub struct SessionConfig { ttl: Duration }",
                    "file": "src/auth/session.rs",
                    "byte_range": [840, 1210],
                    "line_range": [38, 52],
                    "score": 0.87,
                    "source": "hybrid",
                },
                {
                    "chunk_id": "hello.py:1:2",
                    "chunk_text": "def greet():\n    return 'hi'",
                    "file": "hello.py",
                    "line_range": [1, 2],
                    "score": 0.42,
                },
            ],
            "index_coverage": 1.0,
        }
    )
    chunks = idx._parse_search(sample, top_k=5)
    assert len(chunks) == 2
    assert chunks[0].file_path == "src/auth/session.rs"
    assert chunks[0].language == "rust"
    assert chunks[0].line_range == "L38-L52"
    assert chunks[0].score == 0.87
    assert chunks[1].language == "python"


def test_parse_search_caps_at_top_k():
    idx = ArgyphIndex(binary="/nonexistent/argyph")
    hits = [
        {"file": f"f{i}.py", "chunk_text": "x", "line_range": [1, 1], "score": 0.1}
        for i in range(10)
    ]
    chunks = idx._parse_search(json.dumps({"hits": hits}), top_k=3)
    assert len(chunks) == 3


def test_parse_search_tolerates_garbage():
    idx = ArgyphIndex(binary="/nonexistent/argyph")
    assert idx._parse_search("", top_k=5) == []
    assert idx._parse_search("search: not implemented in this milestone", top_k=5) == []
    assert idx._parse_search("{not json", top_k=5) == []
    # malformed hit entries are skipped, valid ones survive
    mixed = json.dumps({"hits": [None, 7, {"file": "ok.py", "chunk_text": "c"}]})
    chunks = idx._parse_search(mixed, top_k=5)
    assert len(chunks) == 1
    assert chunks[0].file_path == "ok.py"


def test_search_returns_empty_when_unavailable():
    idx = ArgyphIndex(binary="/nonexistent/argyph")
    assert idx.available is False
    assert idx.search("anything", top_k=3, repo_path="/tmp") == []


@pytest.mark.skipif(ARGYPH is None, reason="argyph binary not available")
def test_live_index_and_search(tmp_path):
    (tmp_path / "hello.py").write_text("def greet():\n    return 'hi'\n")
    idx = ArgyphIndex(binary=ARGYPH)
    idx.index(str(tmp_path))
    chunks = idx.search("greet function", top_k=3, repo_path=str(tmp_path))
    assert isinstance(chunks, list)


def test_search_codebase_falls_back_to_python_when_argyph_absent(server):
    """With backend=argyph but no binary, search_codebase still returns a
    list (Python fallback), never raises."""
    server.set_code_context(backend="argyph", argyph_binary="/nonexistent/argyph",
                            repo_path="/tmp")
    result = server.search_codebase("anything", top_k=3)
    assert isinstance(result, list)
