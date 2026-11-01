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


def test_reanalysis_recognises_a_finding_whose_code_changed():
    from routes_shared.fingerprint import match_reanalysis

    sqli = ("routes.sqli.pg", "app/api/p/route.js", "/api/p", "GET")
    a01 = ("routes.a01.unprotected-db-route", "app/api/p/route.js", "/api/p", "GET")
    hdr = ("routes.config.headers", "next.config.js", "", "")
    baseline = {"s1": sqli, "a1": a01, "h1": hdr}

    fixed = match_reanalysis(baseline, {"s1"}, [("a2", a01), ("h1", hdr)])
    # The access-control finding was re-fingerprinted by the patch: still there, not resolved, not new.
    assert fixed["resolved"] == ["s1"] and fixed["new"] == [] and set(fixed["remaining"]) == {"a1", "h1"}
    assert fixed["carried"] == {"a2": "a1"} and fixed["targeted_still_present"] == []

    # The injection is re-fingerprinted rather than removed: that is NOT a fix.
    moved = match_reanalysis(baseline, {"s1"}, [("s2", sqli), ("a1", a01), ("h1", hdr)])
    assert moved["targeted_still_present"] == ["s1"] and "s1" not in moved["resolved"]

    # A genuinely different finding is new.
    xss = ("routes.xss.dom", "app/page.js", "", "")
    regressed = match_reanalysis(baseline, {"s1"}, [("a1", a01), ("h1", hdr), ("x1", xss)])
    assert regressed["new"] == ["x1"]
