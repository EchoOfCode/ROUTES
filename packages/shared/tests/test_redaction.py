from routes_shared.redaction import contains_secret_like, redact_structure, redact_text


def test_redacts_assignments():
    out = redact_text('const API_KEY = "abcd1234efgh5678ijkl"')
    assert "abcd1234efgh5678ijkl" not in out
    assert "abcd…[redacted]" in out


def test_redacts_known_formats():
    samples = [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_" + "a" * 36,
        "sk_live_" + "b" * 24,
        "postgres://admin:hunter2secret@db.example.com:5432/app",
    ]
    for s in samples:
        out = redact_text(f"value {s} end")
        assert s not in out
        assert "[redacted]" in out


def test_connection_string_keeps_host():
    out = redact_text("postgres://admin:hunter2secret@db.example.com/app")
    assert "hunter2secret" not in out
    assert "db.example.com" in out


def test_short_values_fully_masked():
    assert "pw12" not in redact_text('password = "pw12"')


def test_structure_and_truncation():
    data = {"a": ['token: "zzzzzzzzzzzzzzzz"'], "n": 3}
    out = redact_structure(data)
    assert "zzzzzzzzzzzzzzzz" not in out["a"][0]
    assert out["n"] == 3
    assert len(redact_text("x" * 1000, max_length=50)) == 50


def test_detection():
    assert contains_secret_like("AKIAIOSFODNN7EXAMPLE")
    assert not contains_secret_like("const x = 1")
