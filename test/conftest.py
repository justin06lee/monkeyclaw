"""Pytest fixtures shared across the test suite."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from infra.database import Database
from infra.mcp_server import MCPServer


@pytest.fixture
def tmp_db(tmp_path: Path) -> Database:
    db_path = tmp_path / "test.db"
    db = Database(db_path)
    yield db
    db.close()


@pytest.fixture
def db(tmp_path: Path) -> Database:
    database = Database(tmp_path / "test.db")
    yield database
    database.close()


@pytest.fixture
def real_mcp(tmp_db: Database) -> MCPServer:
    return MCPServer(tmp_db)


@pytest.fixture
def server(db: Database) -> MCPServer:
    return MCPServer(db)


@pytest.fixture(autouse=True)
def _isolate_logs(tmp_path: Path, monkeypatch):
    """Send logs to a per-test directory so we don't pollute logs/ on rerun."""
    monkeypatch.setenv("MC_LOGGING__FILE", str(tmp_path / "monkeyclaw.log"))
    yield
