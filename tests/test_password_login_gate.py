from agent_lite.browser.password_login import login_with_playwright


def test_missing_password_blocks(monkeypatch):
    monkeypatch.delenv("TEST_USER_A_PASSWORD", raising=False)
    monkeypatch.setenv("TEST_USER_A_EMAIL", "a@example.test")
    res, mat = login_with_playwright(
        identity_id="user_a",
        credential_ref="TEST_USER_A",
        login_url="https://example.test/login",
        allowed_hosts={"example.test"},
    )
    assert res.status == "blocked"
    assert mat is None
    assert "password" in res.reason
