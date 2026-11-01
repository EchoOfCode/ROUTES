from routes_shared.redaction import (
    contains_secret_like,
    mask_string_literals,
    redact_for_llm,
    redact_structure,
    redact_text,
    restore,
    shannon_entropy,
)


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


# ------------------------------------------------- redact_for_llm() / restore()


def test_shannon_entropy_distinguishes_random_from_structured():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0
    assert shannon_entropy("Zx9Qp2Lm7Rk4Vt8Wn3Bc6Yd1Jh5Fs0Ae") > 4.0


def test_redact_for_llm_uses_numbered_placeholders_and_reuses_them():
    # Same secret value assigned to two different sensitive-looking names:
    # both are redacted (keyword detector), and since the value is identical
    # it gets the same placeholder both times.
    text = 'const apiSecret = "abcd1234efgh5678ijkl"; const backupSecret = "abcd1234efgh5678ijkl";'
    out, placeholder_map = redact_for_llm(text)
    assert "abcd1234efgh5678ijkl" not in out
    assert out.count("<SECRET_1>") == 2
    assert placeholder_map == {"<SECRET_1>": "abcd1234efgh5678ijkl"}


def test_redact_for_llm_entropy_catches_values_with_no_keyword_or_known_format():
    random_value = "Zx9Qp2Lm7Rk4Vt8Wn3Bc6Yd1Jh5Fs0Ae"
    text = f'const data = "{random_value}";'
    out, placeholder_map = redact_for_llm(text)
    assert random_value not in out
    assert "<SECRET_1>" in out
    assert placeholder_map["<SECRET_1>"] == random_value


def test_redact_for_llm_low_entropy_strings_pass_through():
    text = 'const greeting = "hello world this is fine";'
    out, placeholder_map = redact_for_llm(text)
    assert out == text
    assert placeholder_map == {}


def test_restore_round_trips_through_redact_for_llm():
    text = 'const apiSecret = "abcd1234efgh5678ijkl"; const data = "plain text value here";'
    out, placeholder_map = redact_for_llm(text)
    assert restore(out, placeholder_map) == text


def test_redact_for_llm_never_double_wraps_an_already_redacted_value():
    # The DB-URL connection-string regex replaces only the credentials; the
    # surrounding quoted literal (scheme + placeholder + host) is still 16+
    # chars and must not be wrapped in a second placeholder.
    text = 'const url = "postgresql://admin:S0meR4ndomP4ssw0rd!@db.internal.example.com:5432/app";'
    out, placeholder_map = redact_for_llm(text)
    assert "S0meR4ndomP4ssw0rd" not in out
    assert "db.internal.example.com" in out
    assert len(placeholder_map) == 1
    assert restore(out, placeholder_map) == text


def test_redact_for_llm_planted_secrets_corpus_zero_leaks():
    """S2 acceptance test: AWS key, JWT, DB URL, and a random high-entropy
    token with no keyword/known-format hint must all leak zero characters."""
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGhpc2lzZmFrZQ"
    db_url = "postgresql://admin:S0meR4ndomP4ssw0rd!@db.internal.example.com:5432/app"
    random_value = "Zx9Qp2Lm7Rk4Vt8Wn3Bc6Yd1Jh5Fs0Ae"  # no known format, no sensitive key name nearby

    snippet = (
        f'logger.info("debug header: {jwt}");\n'
        f'const data = "{random_value}";\n'
        f'const url = "{db_url}";\n'
        f"// reference key {aws_key} in comment\n"
    )

    redacted, placeholder_map = redact_for_llm(snippet)

    for secret in (aws_key, jwt, db_url, random_value):
        assert secret not in redacted
    assert redacted.count("<SECRET_") >= 4
    assert restore(redacted, placeholder_map) == snippet


# ------------------------------------------------- mask_string_literals (S10a)

def test_mask_string_literals_hides_a_positionally_passed_secret():
    """redact_text() needs a sensitive key name next to the literal; this does not."""
    code = 'const t = jwt.sign({ sub: "1" }, "hunter2-signing-value");'
    out = mask_string_literals(code)
    assert "hunter2-signing-value" not in out
    assert "jwt.sign" in out and '"1"' in out  # structure and short literals kept


def test_mask_string_literals_keeps_module_specifiers_readable():
    code = 'import jwt from "jsonwebtoken";\nconst c = require("child_process");'
    out = mask_string_literals(code)
    assert '"jsonwebtoken"' in out and '"child_process"' in out


def test_mask_string_literals_reveals_at_most_four_characters():
    out = mask_string_literals('const x = "S0meR4ndomP4ssw0rd";')
    assert "S0me…[redacted]" in out
    assert "R4ndom" not in out


def test_mask_string_literals_handles_quotes_and_escapes():
    assert "'" in mask_string_literals("const a = 'a-long-enough-value';")
    out = mask_string_literals(r'const a = "pre\"fix-long-value";')
    assert "fix-long-value" not in out


def test_mask_string_literals_leaves_short_literals_alone():
    code = 'res.status(404).send("nope");'
    assert mask_string_literals(code) == code


def test_redact_for_llm_keeps_sql_and_sentences_but_not_secrets_inside_them():
    sql = "SELECT id, name, slug, price FROM products WHERE is_active = TRUE AND name ILIKE '%${q}%' LIMIT 20"
    out, placeholder_map = redact_for_llm(f"const sql = `{sql}`;")
    assert sql in out and placeholder_map == {}
    # A known-format secret inside a sentence is still redacted.
    text = 'log("connecting with key AKIAIOSFODNN7EXAMPLE to the bucket now");'
    out, placeholder_map = redact_for_llm(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in out and restore(out, placeholder_map) == text
    # Two-word values are still entropy-checked.
    out, _ = redact_for_llm('const t = "Zx9Qp2Lm7Rk4 Vt8Wn3Bc6Yd1Jh5Fs0Ae";')
    assert "Zx9Qp2Lm7Rk4" not in out
