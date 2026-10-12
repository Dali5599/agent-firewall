import os
import tempfile
from typing import Generator
import pytest
from fastapi.testclient import TestClient

from agent_firewall.database import init_db, get_db_path, DB_PATH
from agent_firewall.proxy import app

@pytest.fixture(scope="session", autouse=True)
def configure_test_environment() -> None:
    os.environ["AGENT_FIREWALL_ENV"] = "test"
    os.environ["AGENT_FIREWALL_MASTER_KEY"] = "test-master-key-0123456789abcdef"
    os.environ["AGENT_FIREWALL_TOKEN_BUDGET"] = "1000"

@pytest.fixture(autouse=True)
def test_db(monkeypatch: pytest.MonkeyPatch) -> Generator[str, None, None]:
    fd, temp_db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    monkeypatch.setenv("DATABASE_URL", temp_db_path)
    init_db(temp_db_path)
    yield temp_db_path
    if os.path.exists(temp_db_path):
        os.unlink(temp_db_path)
