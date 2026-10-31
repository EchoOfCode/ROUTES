from routes_core.testplan import NUMBER_SLEEP, SLEEP_LIMIT_MS, STRING_SLEEP, generate
from routes_shared.buildrun import TestPlan


def finding(endpoint, method, kind, name, status="potential", file="app/api/x/route.js", line=7):
    return {"type": "SQL Injection", "status": status, "file": file, "line": line, "endpoint": endpoint,
            "method": method, "technical_details": {"source": {"kind": kind, "name": name}}}


ROUTES = [{"path": "/api/products", "methods": ["GET"]}, {"path": "/api/products/[id]", "methods": ["GET"]},
          {"path": "/api/orders", "methods": ["POST"]}, {"path": "/api/health", "methods": ["GET"]}]


def by_id(plan):
    return {t["id"]: t for t in plan["tests"]}


def test_query_parameter_flow_gets_error_and_time_based_probes():
    g = generate(ROUTES, [finding("/api/products", "GET", "URL query parameter", "q")])
    tests = by_id(g.plan)
    quote = tests["sqli-01-quote"]
    assert quote["request"] == {"method": "GET", "path": "/api/products", "query": {"q": "'"}}
    assert 500 in quote["expect"]["status_not"] and "syntax error at or near" in quote["expect"]["body_not_contains"]
    sleep = tests["sqli-01-sleep"]
    assert sleep["request"]["query"] == {"q": STRING_SLEEP} and sleep["expect"]["max_ms"] == SLEEP_LIMIT_MS
    assert "sqli-01-sleep-num" not in tests and g.flows_covered == 1
    TestPlan.model_validate(g.plan)


def test_route_parameter_and_body_flows_are_placed_where_the_input_is_read():
    g = generate(ROUTES, [finding("/api/products/[id]", "GET", "route parameter", "id"),
                          finding("/api/orders", "POST", "request body", "coupon", line=9)])
    tests = by_id(g.plan)
    assert tests["sqli-01-quote"]["request"]["path"] == "/api/products/%27"
    assert tests["sqli-01-sleep-num"]["request"]["path"].startswith("/api/products/1%3B%20SELECT%20pg_sleep")
    body = tests["sqli-02-quote"]["request"]
    assert body["method"] == "POST" and body["json"] == {"coupon": "'"}
    TestPlan.model_validate(g.plan)


def test_flows_that_cannot_be_targeted_are_skipped_with_a_reason():
    g = generate(ROUTES, [finding(None, None, "URL query parameter", "q"),
                          finding("/api/x", "GET", "request data", ""),
                          finding("/api/x", "GET", "URL query parameter", "q", status="inconclusive")])
    assert g.flows_covered == 0 and g.flows_skipped == 3
    assert not [t for t in g.plan["tests"] if t["category"] == "security"]
    assert any("no HTTP route" in n for n in g.notes) and any("inconclusive" in n for n in g.notes)


def test_smoke_tests_cover_static_get_routes_only_and_payloads_are_non_destructive():
    g = generate(ROUTES, [finding("/api/products", "GET", "URL query parameter", "q")])
    smoke = [t["request"]["path"] for t in g.plan["tests"] if t["category"] == "functional"]
    assert smoke == ["/api/products", "/api/health"]
    assert any("dynamic segments" in n for n in g.notes) and any("POST" in n for n in g.notes)
    text = str(g.plan).upper()
    for word in ("DROP ", "DELETE ", "UPDATE ", "INSERT ", "TRUNCATE", "ALTER "):
        assert word not in text
    assert g.plan["health"]["path"] == "/" and 404 in g.plan["health"]["expect_status"]
    assert NUMBER_SLEEP.startswith("1;")
