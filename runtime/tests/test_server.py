import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

import server


@pytest.mark.parametrize("url, expected", [
    ("https://github.com/owner/repo", "https://github.com/owner/repo"),
    ("  https://github.com/owner/repo.git/ ", "https://github.com/owner/repo"),
    ("https://github.com/my-org/my.repo_1", "https://github.com/my-org/my.repo_1"),
])
def test_accepts_github_urls(url, expected):
    assert server.normalize_repo_url(url) == expected


@pytest.mark.parametrize("url", [
    "", "http://github.com/a/b", "https://gitlab.com/a/b", "https://github.com/a", "https://github.com/a/b/tree/main",
    "https://github.com/a/..", "file:///etc", "https://github.com/a/b?x=1", "--upload-pack=x",
])
def test_rejects_other_urls(url):
    with pytest.raises(server.CheckError):
        server.normalize_repo_url(url)


@pytest.fixture
def base_url():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def post(url: str, body: bytes) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as res:
            return res.status, json.load(res)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def test_page_and_health(base_url):
    with urllib.request.urlopen(base_url + "/") as res:
        assert res.status == 200 and b"Runtime error check" in res.read()
    with urllib.request.urlopen(base_url + "/health") as res:
        assert json.load(res)["status"] == "ok"


def test_check_rejects_bad_input(base_url):
    assert post(base_url + "/api/check", b"not json")[0] == 400
    status, data = post(base_url + "/api/check", json.dumps({"repo_url": "https://example.com/x/y"}).encode())
    assert status == 400 and "GitHub" in data["detail"]


def test_check_reports_problems(base_url, monkeypatch, tmp_path):
    def fake_clone(cmd, **kwargs):  # no network: "clone" a tiny repository into the target folder
        if cmd[1] == "clone":
            target = cmd[-1]
            import pathlib
            pathlib.Path(target).mkdir(parents=True)
            (pathlib.Path(target) / "app.py").write_text("print(missing)\n")
        class Done:
            returncode, stdout, stderr = 0, b"abc1234\n", b""
        return Done()

    monkeypatch.setattr(server.subprocess, "run", fake_clone)
    status, data = post(base_url + "/api/check", json.dumps({"repo_url": "https://github.com/o/r"}).encode())
    assert status == 200
    assert data["repo_name"] == "o/r" and data["commit"] == "abc1234"
    assert [p["rule"] for p in data["problems"]] == ["runtime/undefined-name"]
