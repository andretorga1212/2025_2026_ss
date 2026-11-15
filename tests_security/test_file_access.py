import pytest

import baseline_secure_coding_api as api

SECRET = "TOP-SECRET-OUTSIDE-MATERIALS"
ALLOWED = "allowed teaching material"


def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200


@pytest.fixture
def materials(tmp_path, monkeypatch):
    materials_dir = tmp_path / "materials"
    materials_dir.mkdir()
    (materials_dir / "notes.txt").write_text(ALLOWED, encoding="utf-8")
    (materials_dir / "sub").mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text(SECRET, encoding="utf-8")
    monkeypatch.setattr(api, "MATERIALS_DIR", materials_dir)
    return {"dir": materials_dir, "secret": secret}


def assert_not_disclosed(response):
    assert 400 <= response.status_code < 500
    assert SECRET.encode() not in response.data


# R6: legitimate download still works for an authenticated user
def test_authenticated_user_can_download_material(client, materials):
    login(client, "alice", "alicepw")
    response = client.get("/files?path=notes.txt")
    assert response.status_code == 200
    assert response.data.decode() == ALLOWED


# R1/R7: downloads require authentication
def test_anonymous_download_is_rejected(client, materials):
    response = client.get("/files?path=notes.txt")
    assert response.status_code == 401
    assert ALLOWED.encode() not in response.data


# R6: relative traversal out of the materials directory
def test_relative_traversal_is_blocked(client, materials):
    login(client, "alice", "alicepw")
    assert_not_disclosed(client.get("/files?path=../secret.txt"))


# Variation: absolute path (pathlib discards the base directory)
def test_absolute_path_is_blocked(client, materials):
    login(client, "alice", "alicepw")
    assert_not_disclosed(client.get(f"/files?path={materials['secret']}"))


# Variation: traversal hidden behind an existing subdirectory
def test_nested_traversal_is_blocked(client, materials):
    login(client, "alice", "alicepw")
    assert_not_disclosed(client.get("/files?path=sub/../../secret.txt"))
