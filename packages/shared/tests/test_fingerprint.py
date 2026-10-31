from routes_shared.fingerprint import fingerprint, normalize_snippet


def test_normalize_snippet_strips_comments_and_whitespace():
    snippet = """
    const q = search; // user input
    /* block comment */
    pool.query(q);
    """
    assert normalize_snippet(snippet) == "constq=search;pool.query(q);"


def test_fingerprint_survives_reformatting():
    a = fingerprint("routes.sqli.pg-tainted-query", "app/api/search/route.ts", "pool.query(`SELECT * FROM x WHERE y = ${q}`)")
    b = fingerprint(
        "routes.sqli.pg-tainted-query",
        "app/api/search/route.ts",
        "pool.query(\n  `SELECT * FROM x WHERE y = ${q}`\n) // reformatted",
    )
    assert a == b


def test_fingerprint_changes_with_rule_file_or_content():
    base = fingerprint("routes.sqli.pg-tainted-query", "app/api/search/route.ts", "pool.query(q)")
    assert base != fingerprint("routes.sqli.pg-tainted-helper", "app/api/search/route.ts", "pool.query(q)")
    assert base != fingerprint("routes.sqli.pg-tainted-query", "app/api/other/route.ts", "pool.query(q)")
    assert base != fingerprint("routes.sqli.pg-tainted-query", "app/api/search/route.ts", "pool.query(other)")


def test_fingerprint_is_32_hex_chars():
    value = fingerprint("routes.sqli.pg-tainted-query", "a.ts", "x")
    assert len(value) == 32 and all(c in "0123456789abcdef" for c in value)
