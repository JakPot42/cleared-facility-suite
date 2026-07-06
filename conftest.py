"""conftest.py — set DATABASE_URL before any imports, provide shared test fixtures
for the 5-app merged Cleared Facility Suite."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Must set before importing anything that imports database.py
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}"
os.environ["DEMO_MODE"] = "True"
os.environ["ANTHROPIC_API_KEY"] = ""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

import ato.router
import rai.router
import cve.router
import hh.router
import clearance.router
from database import Base, engine, get_db
from main import app


@pytest.fixture(scope="session")
def db_engine():
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture(scope="session")
def db_session(db_engine):
    """Session-scoped so seeding happens exactly once regardless of which
    test/fixture (this one directly, or `client` transitively) triggers it
    first -- pytest caches session-scoped fixtures per session, not per
    request order."""
    Session = sessionmaker(bind=db_engine)
    session = Session()

    # Seed all 5 tools once, same as production's lifespan handler
    ato.router.seed_demo_data(session)
    rai.router.seed_demo_data(session)
    cve.router.seed_demo_data(session)
    hh.router.seed_demo_data(session)
    clearance.router.seed_demo_data(session)

    yield session
    session.close()


@pytest.fixture(scope="session")
def client(db_engine, db_session):
    Session = sessionmaker(bind=db_engine)

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


@pytest.fixture(scope="session")
def seeded_db(client, db_session):
    """Alias matching cve_prioritizer's original fixture name -- client already seeded."""
    return db_session
