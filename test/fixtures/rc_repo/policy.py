"""Fixture: the write sink the handler calls."""


def write_file(path, body):
    """The boundary-crossing sink: actually performs the write."""
    return {"written": path, "bytes": len(body)}
