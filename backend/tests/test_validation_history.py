"""Validation history in MongoDB: attempts, hashes, investigations, restarts, migration and history-driven retries.

Needs a real MongoDB server: set TEST_MONGODB_URI (e.g. mongodb://localhost:27017, or
`docker run -d -p 27017:27017 mongo:7`). Each test uses its own throwaway database,
dropped afterwards. Without TEST_MONGODB_URI these tests are skipped, not mocked.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import textwrap
import threading
import time
import uuid
from pathlib import Path

import pytest
from fastapi import HTTPException

from models.schemas import (
    AttemptStatus, ChainFix, FindingCategory, FixEdit, FixValidation, ValidationRequest, ValidationStatus, Vulnerability,
)
from services import dependency_scanner, fix_validation, scan_store, validation_history
from utils import sandbox
from utils.config import settings

from conftest import FakeScanner, baseline_for, chain_at, fake_findings
from test_fix_validation import param_audit, param_login

BACKEND = Path(__file__).resolve().parent.parent
MONGO_URI = os.getenv("TEST_MONGODB_URI", "")
needs_mongo = pytest.mark.skipif(not MONGO_URI, reason="TEST_MONGODB_URI is not set (needs a real MongoDB server)")


@pytest.fixture(autouse=True)
def fresh_stores(request, tmp_path, monkeypatch):
    """Own SQLite scan store and, for MongoDB tests, own MongoDB database per test."""
    monkeypatch.setattr(settings, "DB_PATH", tmp_path / "db" / "scans.db")
    monkeypatch.setattr(settings, "TEMP_DIR", tmp_path / "temp")
    settings.TEMP_DIR.mkdir()
    name = f"vh_test_{uuid.uuid4().hex[:10]}"
    monkeypatch.setattr(settings, "MONGODB_URI", MONGO_URI)
    monkeypatch.setattr(settings, "MONGODB_DATABASE", name)
    _restart()
    yield name
    _restart()
    if MONGO_URI:  # also when only a subprocess used the database
        from pymongo import MongoClient
        with MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000) as client:
            client.drop_database(name)


def _restart() -> None:
    """Drop open connections, as a backend restart would."""
    validation_history.reset()
    if scan_store._conn is not None:
        scan_store._conn.close()
    scan_store._conn = None


def _investigation(scan="s1", key="chain:c1", **kw) -> dict:
    kw.setdefault("max_attempts", 10)
    return validation_history.open_investigation(scan, key, **kw)


def _fix(name="f", strategy_id="") -> ChainFix:
    return ChainFix(strategy=name, break_point="op", origin="template", strategy_id=strategy_id,
                    edits=[FixEdit(file="app.py", start_line=1, end_line=1, original="a", replacement=name)])


def _attempt(n: int, status=ValidationStatus.FAIL, summary="still open", strategy_id="") -> fix_validation.ValidationAttempt:
    a = fix_validation.ValidationAttempt(attempt=n, fix=_fix(f"fix {n}", strategy_id), status=status, summary=summary,
                                         code_hash=f"{n:064x}", diff=f"+fix {n}")
    a.record_status = fix_validation.record_status(a)
    return a


def _record(inv_id: str, n: int, status=ValidationStatus.FAIL, summary="still open", strategy_id="") -> str:
    aid = validation_history.begin_attempt(inv_id, "v1", n)
    validation_history.set_fix(aid, _fix(f"fix {n}", strategy_id))
    validation_history.set_code_hash(aid, f"{n:064x}")
    validation_history.finish_attempt(aid, _attempt(n, status, summary, strategy_id))
    return aid


def _journal(inv: dict, validation_id: str, first: int = 1):
    from routers.chains import _Journal
    return _Journal(FixValidation(id=validation_id, scan_id="s1", investigation_id=inv["investigation_id"],
                                  first_attempt=first), False)


# ---------- hashing (no database) ----------

def test_code_hash_is_deterministic(tmp_path):
    a, b = tmp_path / "a", tmp_path / "elsewhere" / "b"
    for root, order in ((a, ["x.py", "pkg/y.py"]), (b, ["pkg/y.py", "x.py"])):  # different creation order and location
        for rel in order:
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes({"x.py": b"print(1)\n", "pkg/y.py": b"y = 2\n"}[rel])
    (b / ".git").mkdir()
    (b / ".git" / "HEAD").write_text("ref: main")  # VCS metadata is not code

    assert sandbox.code_hash(a) == sandbox.code_hash(b) == sandbox.code_hash(a)
    assert len(sandbox.code_hash(a)) == 64
    (b / "x.py").write_bytes(b"print(2)\n")
    assert sandbox.code_hash(a) != sandbox.code_hash(b), "content is part of the hash"
    (b / "x.py").write_bytes(b"print(1)\n")
    (b / "x.py").rename(b / "z.py")
    assert sandbox.code_hash(a) != sandbox.code_hash(b), "paths are part of the hash"


# ---------- configuration ----------

def test_without_mongodb_uri_validation_explains_setup_and_does_not_fall_back(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from main import app

    monkeypatch.setattr(settings, "MONGODB_URI", "")
    validation_history.reset()
    with pytest.raises(validation_history.HistoryUnavailable, match="MONGODB_URI is not set"):
        validation_history.begin_attempt("x", "v", 1)
    with TestClient(app) as client:  # the app still starts: scanning works without MongoDB
        r = client.get("/api/scan/s/investigations/i")
    assert r.status_code == 503 and "MONGODB_URI" in r.json()["detail"] and "MONGODB_DATABASE" in r.json()["detail"]
    assert not settings.DB_PATH.exists() or "validation_attempts" not in {
        row[0] for row in sqlite3.connect(settings.DB_PATH).execute("SELECT name FROM sqlite_master")}


# ---------- the store ----------

@needs_mongo
def test_attempt_numbers_parents_and_failed_attempts_are_kept():
    inv = _investigation()
    ids = [_record(inv["investigation_id"], n, ValidationStatus.PASS if n == 3 else ValidationStatus.FAIL)
           for n in (1, 2, 3)]

    records = validation_history.attempts(inv["investigation_id"])
    assert [r.attempt_number for r in records] == [1, 2, 3]
    assert [r.attempt_id for r in records] == ids and len(set(ids)) == 3
    assert [r.parent_attempt_id for r in records] == [None, ids[0], ids[1]]
    assert [r.status for r in records] == ["FAILED", "FAILED", "PASSED"]
    assert records[0].failure_reason == "still open" and records[2].failure_reason is None
    assert records[0].patch[0].replacement == "fix 1" and records[0].diff == "+fix 1"
    assert records[0].code_hash == f"{1:064x}"
    assert all(r.created_at and r.finished_at for r in records)

    # Numbers cannot repeat or skip, and finished attempts are never changed
    with pytest.raises(validation_history.DuplicateAttempt):
        validation_history.begin_attempt(inv["investigation_id"], "v2", 2)
    with pytest.raises(ValueError):
        validation_history.begin_attempt(inv["investigation_id"], "v2", 5)
    for change in (lambda: validation_history.finish_attempt(ids[0], _attempt(1, ValidationStatus.PASS)),
                   lambda: validation_history.close_attempt(ids[0], AttemptStatus.SKIPPED, "x"),
                   lambda: validation_history.set_code_hash(ids[0], "0" * 64)):
        with pytest.raises(validation_history.ImmutableAttempt):
            change()
    assert validation_history.fail_running("v1", "crash") == 0, "finished attempts are not touched by crash handling"
    assert [r.status for r in validation_history.attempts(inv["investigation_id"])] == ["FAILED", "FAILED", "PASSED"]


@needs_mongo
def test_indexes_enforce_unique_attempt_numbers_and_one_current_investigation():
    validation_history.connect()
    db = validation_history._db()
    a = db.validation_attempts.index_information()["attempt_number_unique"]
    assert a["unique"] and a["key"] == [("investigation_id", 1), ("attempt_number", 1)]
    assert db.investigations.index_information()["current_investigation_unique"]["unique"]
    inv = _investigation()
    validation_history.begin_attempt(inv["investigation_id"], "v", 1)
    from pymongo.errors import DuplicateKeyError
    with pytest.raises(DuplicateKeyError):  # even bypassing the checks in begin_attempt
        db.validation_attempts.insert_one({"_id": "x", "investigation_id": inv["investigation_id"], "attempt_number": 1})


@needs_mongo
def test_racing_writers_cannot_duplicate_an_attempt_number():
    inv = _investigation()
    validation_history.connect()
    results: list[str] = []
    barrier = threading.Barrier(8)

    def write() -> None:
        barrier.wait()
        try:
            validation_history.begin_attempt(inv["investigation_id"], "v", 1)
            results.append("ok")
        except validation_history.DuplicateAttempt:
            results.append("duplicate")

    threads = [threading.Thread(target=write) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["duplicate"] * 7 + ["ok"]
    assert [r.attempt_number for r in validation_history.attempts(inv["investigation_id"])] == [1]


@needs_mongo
def test_concurrent_requests_for_one_problem_get_one_run():
    from routers.chains import _reserve

    scan = {"status": "complete", "repo_url": "https://github.com/t/x", "vulnerabilities": [], "chains": []}
    outcomes: list[str] = []
    barrier = threading.Barrier(6)

    def click(i: int) -> None:
        barrier.wait()
        try:
            _reserve("s1", scan, ValidationRequest(), None, "f1", f"v{i}")
            outcomes.append("started")
        except HTTPException as e:
            outcomes.append(e.detail["code"])

    threads = [threading.Thread(target=click, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(outcomes) == ["already_running"] * 5 + ["started"]
    db = validation_history._db()
    assert db.investigations.count_documents({"scan_id": "s1"}) == 1, "one investigation, not one per request"


@needs_mongo
def test_investigations_are_never_replaced_silently():
    inv = _investigation()
    assert _investigation()["investigation_id"] == inv["investigation_id"], "resumed, not duplicated"
    assert validation_history.claim(inv["investigation_id"], "run-a") == 1
    assert validation_history.claim(inv["investigation_id"], "run-b") is None, "already running"
    assert _investigation(new=True)["investigation_id"] == inv["investigation_id"], "a running one is not closed"
    _record(inv["investigation_id"], 1, ValidationStatus.PASS, "")
    assert validation_history.release(inv["investigation_id"], "run-a") == "passed"
    assert _investigation()["investigation_id"] == inv["investigation_id"], "passed stays current until asked"
    assert validation_history.claim(inv["investigation_id"], "run-b") is None, "a passed investigation takes no runs"
    fresh = _investigation(new=True)
    assert fresh["investigation_id"] != inv["investigation_id"] and fresh["status"] == "open"
    assert validation_history.get_investigation(inv["investigation_id"]).status == "closed"


# ---------- the loop, persisted ----------

@needs_mongo
def test_loop_persists_every_attempt_with_its_code_hash(make_repo, tmp_path):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)
    inv = _investigation()
    target = fix_validation.ChainTarget(chain, base, FakeScanner())

    result = asyncio.run(fix_validation.run_loop(target, tmp_path / "work", 3, journal=_journal(inv, "v1")))

    records = validation_history.attempts(inv["investigation_id"])
    assert [a.status for a in result.attempts] == [ValidationStatus.FAIL, ValidationStatus.PASS]
    assert [(r.attempt_number, r.status, r.phase) for r in records] == [(1, "FAILED", "validating"),
                                                                        (2, "PASSED", "validating")]
    assert records[1].parent_attempt_id == records[0].attempt_id
    assert records[0].failure_reason == result.attempts[0].summary
    # One hash per attempt: the exact snapshot that was checked
    assert records[0].code_hash == sandbox.code_hash(tmp_path / "work" / "attempt-1") == result.attempts[0].code_hash
    assert records[1].code_hash == sandbox.code_hash(tmp_path / "work" / "attempt-2") != records[0].code_hash
    assert {c.name for c in records[0].checks} >= {"reproduce_original", "alternative_paths", "scanner_recheck"}
    assert records[1].patch and "INSERT INTO audit" in records[1].diff
    assert records[0].strategy and records[0].fix_origin == "template"


@needs_mongo
def test_attempt_is_recorded_before_its_fix_is_generated(make_repo, tmp_path, monkeypatch):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)
    inv = _investigation()
    seen = []
    real = fix_validation.ChainTarget.first_fix

    async def first_fix(self):
        seen.append([(r.attempt_number, r.status, r.phase, r.patch) for r in validation_history.attempts(inv["investigation_id"])])
        return await real(self)

    monkeypatch.setattr(fix_validation.ChainTarget, "first_fix", first_fix)
    asyncio.run(fix_validation.run_loop(fix_validation.ChainTarget(chain, base, FakeScanner()), tmp_path / "w", 1,
                                        journal=_journal(inv, "v1")))
    assert seen == [[(1, "RUNNING", "generating", [])]]


@needs_mongo
def test_infrastructure_problem_is_error_not_a_failed_fix(make_repo, tmp_path):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)
    inv = _investigation()
    first = fix_validation.developer_fix(param_login(root) + param_audit(root), chain, root)
    target = fix_validation.ChainTarget(chain, base, FakeScanner(error="semgrep: network unreachable"), developer_fix=first)

    [a] = asyncio.run(fix_validation.run_loop(target, tmp_path / "work", 3, journal=_journal(inv, "v1"))).attempts
    assert a.status == ValidationStatus.INCONCLUSIVE and a.record_status == "ERROR"
    [r] = validation_history.attempts(inv["investigation_id"])
    assert r.status == "ERROR" and "scanner" in r.failure_reason


@needs_mongo
def test_identical_code_is_recorded_as_skipped(make_repo, tmp_path):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)
    inv = _investigation()

    def run(n: int, first: int):
        fix = fix_validation.developer_fix(param_login(root), chain, root)
        target = fix_validation.ChainTarget(chain, base, FakeScanner(), developer_fix=fix)
        return asyncio.run(fix_validation.run_loop(target, tmp_path / f"w{n}", 1, first_attempt=first,
                                                   journal=_journal(inv, f"v{n}", first)))

    assert run(1, 1).attempts[0].status == ValidationStatus.FAIL
    again = run(2, 2)
    assert again.stop_reason == "duplicate" and not again.attempts and again.result == "SKIPPED"
    first, skipped = validation_history.attempts(inv["investigation_id"])
    assert skipped.attempt_number == 2 and skipped.status == "SKIPPED"
    assert skipped.code_hash == first.code_hash and skipped.parent_attempt_id == first.attempt_id
    assert "attempt 1 (FAILED)" in skipped.failure_reason and skipped.patch


@needs_mongo
def test_no_fix_is_recorded_as_inconclusive(make_repo, tmp_path):
    root = make_repo("chain_app")
    base = baseline_for(root)
    inv = _investigation()
    target = fix_validation.ChainTarget(chain_at(base, "run_query"), base, FakeScanner())
    result = asyncio.run(fix_validation.run_loop(target, tmp_path / "w", 3, journal=_journal(inv, "v1")))
    assert result.stop_reason == "no_fix"
    [r] = validation_history.attempts(inv["investigation_id"])
    assert (r.status, r.phase, r.code_hash) == ("INCONCLUSIVE", "generating", None)
    assert "No automated fix" in r.failure_reason


@needs_mongo
def test_concurrent_investigations_do_not_interfere(make_repo, tmp_path):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chains = [chain_at(base, "login", 0), chain_at(base, "login", 1)]
    invs = [_investigation(key=f"chain:{c.id}") for c in chains]

    async def both():
        return await asyncio.gather(*[
            fix_validation.run_loop(fix_validation.ChainTarget(c, base, FakeScanner()), tmp_path / f"w{i}", 3,
                                    journal=_journal(inv, f"v{i}"))
            for i, (c, inv) in enumerate(zip(chains, invs))])

    results = asyncio.run(both())
    for inv, result in zip(invs, results):
        records = validation_history.attempts(inv["investigation_id"])
        assert [r.attempt_number for r in records] == list(range(1, len(result.attempts) + 1))
        assert {r.investigation_id for r in records} == {inv["investigation_id"]}
        own = {r.attempt_id for r in records}
        assert all(r.parent_attempt_id in own for r in records[1:]), "parents stay inside their investigation"
        assert records[-1].status == "PASSED"


# ---------- through the API: Validate Fix clicked again and again ----------

SIMULATED_OSV = {"0.12": ("GHSA-0001", "1.0"), "1.0": ("GHSA-0002", "2.0"), "2.0": ("GHSA-0003", "2.2.5")}


async def _simulated_osv(repo: Path):
    line = next(l for l in (repo / "requirements.txt").read_text().splitlines() if l.startswith("flask=="))
    version = line.split("==")[1]
    if version not in SIMULATED_OSV:
        return [], []
    advisory, fixed = SIMULATED_OSV[version]
    return [Vulnerability(id="dep_001", title=f"flask {version}: {advisory}", severity="high", scanner_severity="high",
                          file="requirements.txt", line=2, rule_id=advisory, category=FindingCategory.DEPENDENCY,
                          package="flask", installed_version=version, fixed_version=fixed)], []


@pytest.fixture
def api(monkeypatch):
    """The FastAPI app with cloning and the vulnerability database replaced; returns (client, add_scan)."""
    from fastapi.testclient import TestClient

    from main import app
    from routers.scan import scans
    from services import repo_manager

    sources: dict[str, Path] = {}

    def fake_clone(url: str, dest: Path, commit):
        shutil.copytree(sources[url], dest)
        return "0" * 40

    monkeypatch.setattr(repo_manager, "clone_at_commit", fake_clone)
    monkeypatch.setattr(dependency_scanner, "scan_dependencies", _simulated_osv)
    monkeypatch.setattr(fix_validation, "semgrep_scanner", FakeScanner())

    def add_scan(scan_id: str, root: Path, findings: list[Vulnerability], chains=()) -> None:
        url = f"https://github.com/test/{scan_id}"
        sources[url] = root
        scans[scan_id] = {"scan_id": scan_id, "repo_url": url, "repo_name": scan_id, "status": "complete",
                          "started_at": "2026-01-01T00:00:00+00:00", "commit": "0" * 40, "languages": ["python"],
                          "vulnerabilities": findings, "chains": list(chains), "validations": {}}

    with TestClient(app) as client:
        yield client, add_scan
    for sid in [s for s in scans if s.startswith("t-")]:
        scans.pop(sid)


def _wait(client, scan_id: str, v: dict) -> dict:
    for _ in range(600):
        if v["state"] != "running":
            return v
        time.sleep(0.05)
        v = client.get(f"/api/scan/{scan_id}/validations/{v['id']}").json()
    raise AssertionError("validation did not finish")


def _validate(client, scan_id: str, finding_id: str, **body) -> dict:
    r = client.post(f"/api/scan/{scan_id}/findings/{finding_id}/validate", json=body)
    assert r.status_code == 200, r.text
    return _wait(client, scan_id, r.json())


def _history(client, scan_id: str, inv_id: str) -> dict:
    r = client.get(f"/api/scan/{scan_id}/investigations/{inv_id}")
    assert r.status_code == 200, r.text
    return r.json()


def _dep_repo(tmp_path: Path) -> tuple[Path, Vulnerability]:
    root = tmp_path / "dep"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.32.4\nflask==0.12\ngunicorn==22.0.0\n")
    [finding] = asyncio.run(_simulated_osv(root))[0]
    return root, finding


@needs_mongo
def test_attempts_1_2_3_across_three_validate_clicks(api, tmp_path):
    client, add_scan = api
    root, finding = _dep_repo(tmp_path)
    add_scan("t-dep", root, [finding])

    runs = [_validate(client, "t-dep", "dep_001", max_attempts=1) for _ in range(3)]

    # One investigation, numbered on across clicks, each run starting from the previous best code
    assert len({r["investigation_id"] for r in runs}) == 1
    assert [r["first_attempt"] for r in runs] == [1, 2, 3]
    assert [r["attempts"][0]["attempt"] for r in runs] == [1, 2, 3]
    assert [r["attempts"][0]["fix"]["edits"][0]["replacement"] for r in runs] == ["flask==1.0", "flask==2.0", "flask==2.2.5"]
    assert [r["result"] for r in runs] == ["FAILED", "FAILED", "PASSED"]
    assert runs[2]["final_fix"]["edits"][0]["original"] == "flask==0.12", "final code is relative to the scanned code"

    inv = _history(client, "t-dep", runs[0]["investigation_id"])
    assert inv["status"] == "passed" and inv["best_attempt"] == 3
    records = inv["attempts"]
    assert [(r["attempt_number"], r["status"], r["outcome"]) for r in records] == [
        (1, "FAILED", "new_vulnerability"), (2, "FAILED", "new_vulnerability"), (3, "PASSED", "pass")]
    assert [r["parent_attempt_id"] for r in records] == [None, records[0]["attempt_id"], records[1]["attempt_id"]]
    assert all(r["code_hash"] and len(r["code_hash"]) == 64 for r in records)
    assert len({r["code_hash"] for r in records}) == 3
    assert "GHSA-0002" in records[0]["failure_reason"]
    assert all(r["rule_id"] == "GHSA-0001" and r["finding_id"] == "dep_001" for r in records)
    assert records[2]["patch"][0]["replacement"] == "flask==2.2.5" and "+flask==2.2.5" in records[2]["diff"]
    assert {c["name"] for c in records[2]["checks"]} >= {"reproduce_original"}

    # Survives a restart: new connection, same history
    _restart()
    assert _history(client, "t-dep", runs[0]["investigation_id"])["attempts"] == records

    # Passed: the next click is refused until a new investigation is asked for explicitly
    r = client.post("/api/scan/t-dep/findings/dep_001/validate", json={"max_attempts": 3})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "investigation_passed"
    again = _validate(client, "t-dep", "dep_001", max_attempts=3, new_investigation=True)
    assert again["investigation_id"] != runs[0]["investigation_id"] and again["first_attempt"] == 1


@needs_mongo
def test_attempt_limit_holds_across_clicks(api, tmp_path, monkeypatch):
    client, add_scan = api
    monkeypatch.setattr(settings, "INVESTIGATION_MAX_ATTEMPTS", 2)
    root, finding = _dep_repo(tmp_path)
    add_scan("t-limit", root, [finding])

    first = _validate(client, "t-limit", "dep_001", max_attempts=1)
    second = _validate(client, "t-limit", "dep_001", max_attempts=5)
    assert second["max_attempts"] == 1, "only what is left of the investigation's limit"
    assert [first["first_attempt"], second["first_attempt"]] == [1, 2] and second["stop_reason"] == "limit"
    for _ in range(2):  # refused every time, never a silent fresh investigation
        r = client.post("/api/scan/t-limit/findings/dep_001/validate", json={})
        assert r.status_code == 409 and r.json()["detail"]["code"] == "investigation_exhausted"
        assert "all 2 validation attempts" in r.json()["detail"]["message"]
    inv = _history(client, "t-limit", first["investigation_id"])
    assert inv["status"] == "exhausted" and len(inv["attempts"]) == 2

    fresh = _validate(client, "t-limit", "dep_001", new_investigation=True, max_attempts=1)
    assert fresh["investigation_id"] != first["investigation_id"] and fresh["first_attempt"] == 1


@needs_mongo
@pytest.mark.parametrize("where, phase", [("generation", "generating"), ("validation", "validating"),
                                          ("setup", "setup")])
def test_crash_is_recorded_and_the_next_click_continues(api, tmp_path, monkeypatch, where, phase):
    from services import finding_validation, repo_manager

    client, add_scan = api
    root, finding = _dep_repo(tmp_path)
    add_scan("t-crash", root, [finding])

    async def crash(self, *args, **kwargs):
        raise RuntimeError("disk full")

    def clone_crash(*args):
        raise RuntimeError("disk full")

    with monkeypatch.context() as m:
        if where == "setup":
            m.setattr(repo_manager, "clone_at_commit", clone_crash)
        else:
            m.setattr(finding_validation.FindingTarget, {"generation": "first_fix", "validation": "evaluate"}[where],
                      crash)
        crashed = _validate(client, "t-crash", "dep_001", max_attempts=1)
    assert crashed["state"] == "failed" and crashed["result"] == "ERROR"

    retry = _validate(client, "t-crash", "dep_001", max_attempts=1)
    assert retry["investigation_id"] == crashed["investigation_id"] and retry["first_attempt"] == 2
    records = _history(client, "t-crash", retry["investigation_id"])["attempts"]
    assert [(r["attempt_number"], r["status"]) for r in records] == [(1, "ERROR"), (2, "FAILED")]
    assert "disk full" in records[0]["failure_reason"] and f"(during {phase})" in records[0]["failure_reason"]
    assert records[0]["phase"] == phase
    assert records[1]["parent_attempt_id"] == records[0]["attempt_id"]


@needs_mongo
def test_chain_validation_resumes_from_best_code(api, make_repo):
    client, add_scan = api
    root = make_repo("fix_app")
    findings = fake_findings(root)
    base = baseline_for(root, findings)
    chain = chain_at(base, "login", 0)
    add_scan("t-chain", root, findings, base.chains)

    def validate(**body):
        r = client.post(f"/api/scan/t-chain/chains/{chain.id}/validate", json=body)
        assert r.status_code == 200, r.text
        return _wait(client, "t-chain", r.json())

    first = validate(max_attempts=1)
    second = validate(max_attempts=1)
    assert first["result"] == "FAILED" and second["result"] == "PASSED"
    assert second["first_attempt"] == 2 and second["best_attempt"] == 2
    # Attempt 2 only added what attempt 1 left open; the final code holds both changes
    assert all("INSERT INTO audit" in e["original"] for e in second["attempts"][0]["fix"]["edits"])
    final = "\n".join(e["replacement"] for e in second["final_fix"]["edits"])
    assert "cursor.execute(query, (username, password))" in final and "INSERT INTO audit" in final


@needs_mongo
def test_api_passes_similar_history_to_the_fix_generator(api, tmp_path, monkeypatch):
    """A second scan of the same problem gets the first scan's attempts as lessons."""
    client, add_scan = api
    root, finding = _dep_repo(tmp_path)
    add_scan("t-first", root, [finding])
    add_scan("t-second", root, [finding])
    _validate(client, "t-first", "dep_001", max_attempts=1)

    seen = []
    real = fix_validation.run_loop

    async def spy(target, *args, **kwargs):
        seen.append(target.lessons)
        return await real(target, *args, **kwargs)

    monkeypatch.setattr(fix_validation, "run_loop", spy)
    _validate(client, "t-second", "dep_001", max_attempts=1)
    assert "Upgrade flask to 1.0" in seen[0] and "GHSA-0002" in seen[0], "earlier failure and its reason"


# ---------- history informs the next fix ----------

@needs_mongo
def test_resumed_run_hands_earlier_attempts_to_the_generator(make_repo, tmp_path, monkeypatch):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)
    inv = _investigation()
    target = fix_validation.ChainTarget(chain, base, FakeScanner())
    first = asyncio.run(fix_validation.run_loop(target, tmp_path / "w1", 1, journal=_journal(inv, "v1")))

    seen = []
    real = fix_validation.ChainTarget.next_fix

    async def spy(self, current, history):
        seen.append(([a.attempt for a in history], current))
        return await real(self, current, history)

    monkeypatch.setattr(fix_validation.ChainTarget, "next_fix", spy)
    history = validation_history.history(inv["investigation_id"])
    resume = fix_validation.Resume(history, first.final_fix, history[0])
    second = asyncio.run(fix_validation.run_loop(target, tmp_path / "w2", 1, first_attempt=2, resume=resume,
                                                 journal=_journal(inv, "v2", 2)))

    assert seen[0][0] == [1], "attempt 1 (from the earlier run) is the generator's history"
    assert seen[0][1] == tmp_path / "w2" / "resumed", "and the generator works on the best code so far"
    assert second.attempts[0].attempt == 2 and second.status == ValidationStatus.PASS


@needs_mongo
def test_similar_fixes_and_failure_reasons_reach_the_llm_prompt(tmp_path, monkeypatch):
    from services import ai_enhancer, finding_validation

    # Another scan already validated fixes for the same rule: one failed, one passed; a SKIPPED one carries nothing
    other = _investigation(scan="older", key="finding:x", rule_id="python.lang.eval-injection")
    _record(other["investigation_id"], 1, ValidationStatus.FAIL, "The problem is still there: eval rule still matches")
    _record(other["investigation_id"], 2, ValidationStatus.PASS, "")
    inv = _investigation(scan="new", key="finding:y", rule_id="python.lang.eval-injection")
    lessons = validation_history.lessons(validation_history.similar(
        rule_id="python.lang.eval-injection", vuln_class=None, exclude_investigation=inv["investigation_id"]))
    assert lessons.index("fix 2") < lessons.index("fix 1"), "successful approaches first"
    assert "eval rule still matches" in lessons

    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("import os\n\ndef calc(expr):\n    return eval(expr)\n")
    finding = Vulnerability(id="y", title="eval", severity="high", scanner_severity="high", file="app.py", line=4,
                            rule_id="python.lang.eval-injection")
    prompts = []

    async def fake_llm(http, prompt):
        prompts.append(prompt)
        return json.dumps({"strategy": "literal_eval", "rationale": "r", "edits": [
            {"file": "app.py", "start_line": 4, "end_line": 4, "replacement": "    return ast.literal_eval(expr)"}]})

    monkeypatch.setattr(settings, "GROQ_API_KEY", "test-key")
    monkeypatch.setattr(ai_enhancer, "_groq_complete", fake_llm)
    target = finding_validation.FindingTarget(finding, root, ["python"], None, use_ai=True, lessons=lessons)
    earlier = [_attempt(1, ValidationStatus.FAIL, "The problem is still there: rule matches line 4")]
    fix = asyncio.run(target.next_fix(root, earlier))

    assert fix is not None and fix.origin == "ai"
    [prompt] = prompts
    assert "Lessons from validated fixes of similar problems" in prompt and "do not copy" in prompt
    assert "fix 2" in prompt and "eval rule still matches" in prompt
    assert "rule matches line 4" in prompt, "this investigation's own failures are in the prompt too"
    assert "Avoid approaches that the lessons show failing" in prompt


# ---------- a real restart ----------

@needs_mongo
def test_attempts_survive_a_killed_backend(tmp_path, fresh_stores):
    """Process 1 dies mid-attempt; process 2 (a restart) keeps attempt 1 and marks attempt 2 ERROR."""
    env = {**os.environ, "MONGODB_URI": MONGO_URI, "MONGODB_DATABASE": fresh_stores, "DB_PATH": str(tmp_path / "x.db")}
    common = f"""
import sys, os
sys.path.insert(0, {str(BACKEND)!r})
from models.schemas import ChainFix, ValidationAttempt, ValidationStatus
from services import fix_validation, validation_history
fix = ChainFix(strategy="s", break_point="op")
"""
    crash = common + """
inv = validation_history.open_investigation("s", "finding:f", max_attempts=10)
validation_history.claim(inv["investigation_id"], "run1")
a1 = validation_history.begin_attempt(inv["investigation_id"], "run1", 1)
attempt = ValidationAttempt(attempt=1, fix=fix, status=ValidationStatus.FAIL, summary="still open", code_hash="a" * 64)
attempt.record_status = fix_validation.record_status(attempt)
validation_history.finish_attempt(a1, attempt)
a2 = validation_history.begin_attempt(inv["investigation_id"], "run1", 2)
validation_history.set_fix(a2, fix)
print(inv["investigation_id"], flush=True)
os._exit(9)  # killed while attempt 2 runs
"""
    restart = common + """
import json
validation_history.connect()  # what the backend does at startup
inv_id = sys.argv[1]
print(json.dumps({"attempts": [r.model_dump() for r in validation_history.attempts(inv_id)],
                  "next": validation_history.claim(inv_id, "run2")}))
"""
    p1 = subprocess.run([sys.executable, "-c", textwrap.dedent(crash)], capture_output=True, text=True, cwd=tmp_path,
                        env=env)
    assert p1.returncode == 9, p1.stderr
    p2 = subprocess.run([sys.executable, "-c", textwrap.dedent(restart), p1.stdout.strip()], capture_output=True,
                        text=True, cwd=tmp_path, env=env)
    assert p2.returncode == 0, p2.stderr
    out = json.loads(p2.stdout)
    records = out["attempts"]
    assert [(r["attempt_number"], r["status"]) for r in records] == [(1, "FAILED"), (2, "ERROR")]
    assert records[0]["failure_reason"] == "still open" and records[0]["code_hash"] == "a" * 64
    assert "Interrupted" in records[1]["failure_reason"] and "(during applying)" in records[1]["failure_reason"]
    assert records[1]["parent_attempt_id"] == records[0]["attempt_id"]
    assert out["next"] == 3, "the claim left by the dead process was released; numbering continues"


# ---------- migration from the earlier SQLite store ----------

OLD_SQLITE_SCHEMA = """
CREATE TABLE scans (scan_id TEXT PRIMARY KEY, repo_url TEXT NOT NULL, repo_name TEXT NOT NULL, status TEXT NOT NULL,
    started_at TEXT NOT NULL, finished_at TEXT, error TEXT, total INTEGER DEFAULT 0, critical INTEGER DEFAULT 0,
    high INTEGER DEFAULT 0, state_json TEXT NOT NULL);
CREATE TABLE investigations (investigation_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, target_key TEXT NOT NULL,
    finding_id TEXT, chain_id TEXT, rule_id TEXT, vuln_class TEXT, repo_url TEXT, file TEXT, status TEXT NOT NULL,
    max_attempts INTEGER NOT NULL, active_validation_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE validation_attempts (attempt_id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL,
    validation_id TEXT NOT NULL, attempt_number INTEGER NOT NULL, parent_attempt_id TEXT, code_hash TEXT,
    finding_id TEXT, chain_id TEXT, rule_id TEXT, vuln_class TEXT, fix_origin TEXT, strategy TEXT,
    patch_json TEXT NOT NULL, diff TEXT, status TEXT NOT NULL, outcome TEXT, failure_reason TEXT, result_json TEXT,
    created_at TEXT NOT NULL, finished_at TEXT, UNIQUE (investigation_id, attempt_number));
"""


def _old_sqlite_history(path: Path) -> None:
    db = sqlite3.connect(path)
    db.executescript(OLD_SQLITE_SCHEMA)
    db.execute("INSERT INTO investigations VALUES ('inv1','scan1','finding:f1','f1',NULL,'R1',NULL,'https://github.com/a/b',"
               "'app.py','open',10,'oldrun','2026-10-01T10:00:00+00:00','2026-10-01T10:05:00+00:00')")
    rows = [("a1", 1, None, "FAILED", "fail", "still open", "2026-10-01T10:01:00+00:00", "2026-10-01T10:02:00+00:00"),
            ("a2", 2, "a1", "INCONCLUSIVE", "inconclusive", "patch stale", "2026-10-01T10:03:00+00:00",
             "2026-10-01T10:03:30+00:00"),
            ("a3", 3, "a2", "RUNNING", None, None, "2026-10-01T10:04:00+00:00", None)]
    for aid, n, parent, status, outcome, reason, created, finished in rows:
        result = _attempt(n).model_dump_json() if outcome else None
        db.execute("INSERT INTO validation_attempts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (aid, "inv1", "oldrun", n, parent, f"{n:064x}", "f1", None, "R1", None, "template", f"fix {n}",
                    json.dumps([e.model_dump() for e in _fix(f"fix {n}").edits]), f"+fix {n}", status, outcome, reason,
                    result, created, finished))
    state = {"validations": {"oldrun": {"investigation_id": "inv1", "started_at": "2026-10-01T10:00:00+00:00",
                                        "best_attempt": 1, "final_fix": _fix("best").model_dump()}}}
    db.execute("INSERT INTO scans VALUES ('scan1','u','n','complete','t',NULL,NULL,0,0,0,?)", (json.dumps(state),))
    db.commit()
    db.close()


@needs_mongo
def test_sqlite_history_migrates_to_mongodb_and_is_verified(tmp_path, fresh_stores):
    old = tmp_path / "old.db"
    _old_sqlite_history(old)
    before = hashlib.sha256(old.read_bytes()).hexdigest()
    env = {**os.environ, "MONGODB_URI": MONGO_URI, "MONGODB_DATABASE": fresh_stores}
    script = [sys.executable, str(BACKEND / "scripts" / "migrate_validation_history.py"), "--sqlite", str(old)]

    dry = subprocess.run(script + ["--dry-run"], capture_output=True, text=True, env=env)
    assert dry.returncode == 0 and "1 investigation(s), 3 attempt(s)" in dry.stdout and "nothing written" in dry.stdout
    assert validation_history._db().validation_attempts.count_documents({}) == 0

    run = subprocess.run(script, capture_output=True, text=True, env=env)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "3 inserted" in run.stdout and "Verified" in run.stdout
    again = subprocess.run(script, capture_output=True, text=True, env=env)
    assert again.returncode == 0 and "3 already present" in again.stdout, "re-running changes nothing"
    assert hashlib.sha256(old.read_bytes()).hexdigest() == before, "SQLite is never changed"

    inv = validation_history.get_investigation("inv1")
    assert (inv.status, inv.active_validation_id, inv.best_attempt) == ("open", None, 1)
    assert [(r.attempt_id, r.attempt_number, r.parent_attempt_id, r.status) for r in inv.attempts] == [
        ("a1", 1, None, "FAILED"), ("a2", 2, "a1", "INCONCLUSIVE"), ("a3", 3, "a2", "ERROR")]
    assert [r.code_hash for r in inv.attempts] == [f"{n:064x}" for n in (1, 2, 3)]
    assert inv.attempts[0].created_at == "2026-10-01T10:01:00+00:00"
    assert inv.attempts[1].finished_at == "2026-10-01T10:03:30+00:00"
    assert "Interrupted" in inv.attempts[2].failure_reason, "a row left RUNNING by the old process"
    assert validation_history.best("inv1")[0].strategy == "best"
    # The migrated investigation continues where it stopped
    assert validation_history.claim("inv1", "new-run") == 4


# ---------- history changes the rule-based strategy choice ----------

SQL_TEMPLATE = "template:sql_injection"


def _fake_llm(monkeypatch, prompts: list):
    """The LLM answers with a parameterized query for fix_app's login() (line 24)."""
    from services import ai_enhancer

    async def fake(http, prompt):
        prompts.append(prompt)
        return json.dumps({"strategy": "bind parameters", "break_point": "x", "rationale": "r", "edits": [
            {"file": "app.py", "start_line": 24, "end_line": 24,
             "replacement": "    cursor.execute(query, (username, password))"}]})

    monkeypatch.setattr(settings, "GROQ_API_KEY", "test-key")
    monkeypatch.setattr(ai_enhancer, "_groq_complete", fake)


_REPOS: dict = {}


def _first_fix(make_repo, stats, use_ai, history=()):
    from services import fix_planner

    key = id(make_repo)
    if key not in _REPOS:
        _REPOS.clear()
        root = make_repo("fix_app")
        _REPOS[key] = (root, baseline_for(root))
    root, base = _REPOS[key]
    chain = chain_at(base, "login", 0)
    return asyncio.run(fix_planner.next_fix(chain, base.analysis, root, list(history), use_ai, stats=stats))


def test_rule_based_baseline_is_unchanged_without_adverse_history(make_repo, monkeypatch):
    prompts: list = []
    _fake_llm(monkeypatch, prompts)
    for stats in ({}, {SQL_TEMPLATE: (0, 1)}, {SQL_TEMPLATE: (1, 5)}):  # no record, one failure, or it has passed
        fix = _first_fix(make_repo, stats, use_ai=True)
        assert (fix.strategy_id, fix.origin, fix.history_note) == (SQL_TEMPLATE, "template", "")
    assert not prompts, "the rule-based first attempt does not call the LLM"


def test_repeatedly_failing_template_goes_after_the_llm(make_repo, monkeypatch):
    prompts: list = []
    _fake_llm(monkeypatch, prompts)
    fix = _first_fix(make_repo, {SQL_TEMPLATE: (0, 2)}, use_ai=True)
    assert (fix.strategy_id, fix.origin) == ("ai", "ai") and len(prompts) == 1
    assert "Tried first because template:sql_injection failed 2 time(s)" in fix.history_note


def test_failing_template_stays_the_fallback(make_repo, monkeypatch):
    from services import ai_enhancer

    fix = _first_fix(make_repo, {SQL_TEMPLATE: (0, 3)}, use_ai=False)  # no LLM: the baseline still runs
    assert (fix.strategy_id, fix.origin, fix.history_note) == (SQL_TEMPLATE, "template", "")

    async def no_answer(http, prompt):
        return json.dumps({"strategy": "nothing", "edits": []})

    monkeypatch.setattr(settings, "GROQ_API_KEY", "test-key")
    monkeypatch.setattr(ai_enhancer, "_groq_complete", no_answer)
    fix = _first_fix(make_repo, {SQL_TEMPLATE: (0, 3)}, use_ai=True)  # the LLM is asked first but has no fix
    assert (fix.strategy_id, fix.origin) == (SQL_TEMPLATE, "template")
    assert fix.history_note.startswith("Used as the fallback although template:sql_injection failed 3 time(s)")


def test_own_investigation_failures_count(make_repo, monkeypatch):
    """Two evaluated failures of the template in this investigation: the retry asks the LLM first."""
    from services import fix_planner

    prompts: list = []
    _fake_llm(monkeypatch, prompts)
    own = [_attempt(1, strategy_id=SQL_TEMPLATE), _attempt(2, strategy_id=SQL_TEMPLATE)]
    assert fix_planner.strategy_record(SQL_TEMPLATE, {}, own) == (0, 2)
    stale = _attempt(3, ValidationStatus.INCONCLUSIVE, strategy_id=SQL_TEMPLATE)
    stale.checks.append(fix_validation.ValidationCheck(name="apply_patch", status="error"))
    errored = _attempt(4, ValidationStatus.INCONCLUSIVE, strategy_id=SQL_TEMPLATE)
    errored.record_status = AttemptStatus.ERROR
    assert fix_planner.strategy_record(SQL_TEMPLATE, {}, own + [stale, errored]) == (0, 2), "no evidence, not counted"
    assert fix_planner.avoid_reason(SQL_TEMPLATE, {}, own[:1]) is None
    assert fix_planner.avoid_reason(SQL_TEMPLATE, {}, own) is not None
    assert fix_planner.avoid_reason("ai", {"ai": (0, 9)}, []) is None, "free-form fixes are not ranked"


def test_secret_template_with_a_bad_record_goes_after_the_llm(tmp_path, monkeypatch):
    from services import ai_enhancer, finding_validation

    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text('import os\nAPI_KEY = "sk_live_abcdefghijklmnop1234"\n')
    finding = Vulnerability(id="s", title="secret", severity="high", scanner_severity="high", file="app.py", line=2,
                            rule_id="secret/stripe-key", category=FindingCategory.SECRET)

    async def fake(http, prompt):
        return json.dumps({"strategy": "load from vault", "rationale": "r", "edits": [
            {"file": "app.py", "start_line": 2, "end_line": 2, "replacement": 'API_KEY = os.getenv("API_KEY")'}]})

    monkeypatch.setattr(settings, "GROQ_API_KEY", "test-key")
    monkeypatch.setattr(ai_enhancer, "_groq_complete", fake)

    def first(stats, use_ai=True):
        target = finding_validation.FindingTarget(finding, root, ["python"], None, use_ai=use_ai, strategy_stats=stats)
        return asyncio.run(target.first_fix())

    assert first({}).strategy_id == "template:secret-env", "baseline"
    assert first({"template:secret-env": (0, 2)}).strategy_id == "ai"
    fallback = first({"template:secret-env": (0, 2)}, use_ai=False)
    assert fallback.strategy_id == "template:secret-env"
    assert fallback.history_note == "", "with no alternative, history changed nothing, so nothing is claimed"


@needs_mongo
def test_strategy_stats_come_from_comparable_evaluated_attempts():
    inv = _investigation(scan="a", key="chain:x", vuln_class="sql_injection", rule_id="R1")
    for n, status in enumerate((ValidationStatus.FAIL, ValidationStatus.INCONCLUSIVE, ValidationStatus.PASS), 1):
        _record(inv["investigation_id"], n, status, strategy_id=SQL_TEMPLATE if n < 3 else "ai")
    aid = validation_history.begin_attempt(inv["investigation_id"], "v", 4)  # SKIPPED: carries no evidence
    validation_history.set_fix(aid, _fix("dup", SQL_TEMPLATE))
    validation_history.close_attempt(aid, AttemptStatus.SKIPPED, "same code")
    other = _investigation(scan="b", key="chain:y", vuln_class="xss")
    _record(other["investigation_id"], 1, strategy_id="template:xss")

    assert validation_history.strategy_stats(rule_id=None, vuln_class="sql_injection") == {
        SQL_TEMPLATE: (0, 2), "ai": (1, 0)}
    assert validation_history.strategy_stats(rule_id="R1", vuln_class=None) == {SQL_TEMPLATE: (0, 2), "ai": (1, 0)}
    assert validation_history.strategy_stats(rule_id=None, vuln_class="sql_injection",
                                             exclude_investigation=inv["investigation_id"]) == {}
    [r] = [r for r in validation_history.attempts(inv["investigation_id"]) if r.attempt_number == 1]
    assert r.strategy_id == SQL_TEMPLATE


@needs_mongo
def test_api_history_changes_strategy_and_records_why(api, make_repo, monkeypatch):
    """Earlier scans' records reach both the strategy order and the LLM prompt, and the choice is persisted."""
    client, add_scan = api
    for i in (1, 2):  # the SQL template failed for this rule in two earlier scans, never passed
        old = _investigation(scan=f"old{i}", key="chain:c", vuln_class="sql_injection")
        _record(old["investigation_id"], 1, ValidationStatus.FAIL, "alternative path still open", SQL_TEMPLATE)
    prompts: list = []
    _fake_llm(monkeypatch, prompts)
    root = make_repo("fix_app")
    findings = fake_findings(root)
    base = baseline_for(root, findings)
    chain = chain_at(base, "login", 0)
    add_scan("t-strategy", root, findings, base.chains)

    r = client.post(f"/api/scan/t-strategy/chains/{chain.id}/validate", json={"max_attempts": 1})
    v = _wait(client, "t-strategy", r.json())
    [record] = _history(client, "t-strategy", v["investigation_id"])["attempts"]
    assert (record["strategy_id"], record["fix_origin"]) == ("ai", "ai")
    assert "template:sql_injection failed 2 time(s)" in record["selection_note"]
    assert "strategy template:sql_injection: passed 0, failed 2" in prompts[0]
    assert "alternative path still open" in prompts[0]
