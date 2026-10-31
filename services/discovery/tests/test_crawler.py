"""Discovery tests against the controlled sample website (no gateway: the
gateway's own enforcement is tested in infrastructure/network-gateway)."""

import asyncio
import threading
from urllib.parse import urlsplit

import pytest

from discovery.crawler.engine import Config, Crawler
from discovery.crawler.policy_files import validate_manifest
from discovery.tests.sample_site.server import Handler, serve


@pytest.fixture(scope="module")
def site():
    server = serve(0, "127.0.0.1")
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/"
    server.shutdown()


def crawl(url, renderer=None, max_pages=25):
    Handler.hits.clear()
    crawler = Crawler(Config(target_url=url, max_pages=max_pages, proxy_url=None), renderer=renderer)
    return asyncio.run(crawler.run())


@pytest.fixture(scope="module")
def result(site):
    out = crawl(site)
    out["_hits"] = list(Handler.hits)
    return out


def paths(result):
    return [urlsplit(p["url"]).path for p in result["pages"]]


def test_page_limit_enforced(result):
    assert len(result["pages"]) == 25
    assert result["page_limit_reached"] is True
    assert len([h for h in result["_hits"] if h.startswith("/products/")]) <= 25


def test_small_limit(site):
    out = crawl(site, max_pages=3)
    assert len(out["pages"]) == 3 and out["page_limit_reached"]


def test_stays_on_exact_hostname(result):
    hosts = {urlsplit(p["url"]).hostname for p in result["pages"]}
    assert hosts == {"127.0.0.1"}
    assert "external.example" in result["external_hosts"]
    assert "api.external.example" in result["external_hosts"]


def test_duplicate_urls_crawled_once(result):
    p = paths(result)
    assert p.count("/about") + p.count("/about/") == 1
    assert len([h for h in result["_hits"] if h.split("?")[0].rstrip("/") == "/about"]) == 1


def test_redirects(result):
    # Internal redirect to an already-inspected page is not recorded twice.
    assert paths(result).count("/about") == 1
    ext = next(p for p in result["pages"] if p["url"].endswith("/redirect-external"))
    assert "outside" in ext["error"]
    assert not any("landing" in h for h in result["_hits"])


def test_respects_robots_and_avoids_destructive_links(result):
    hits = result["_hits"]
    assert not any(h.startswith("/private/") for h in hits)
    assert any("/private/admin" in u for u in result["robots"]["blocked_urls"])
    assert "/logout" not in hits
    assert not any(h.startswith("POST") for h in hits)  # forms are never submitted


def test_manifest_detected(result):
    m = result["manifest"]
    assert m["detected"] and m["valid"]
    assert m["data"]["supported_assessments"] == ["sqli"]


def test_forms_and_auth_pages(result):
    by_path = {urlsplit(p["url"]).path: p for p in result["pages"]}
    assert by_path["/login"]["is_login"] and not by_path["/login"]["is_registration"]
    assert by_path["/register"]["is_registration"]
    login_form = next(f for f in result["forms"] if f["action"].endswith("/api/auth/login"))
    assert login_form["method"] == "POST"
    assert {f["name"] for f in login_form["fields"]} == {"email", "password"}
    form_eps = [e for e in result["endpoints"] if e["origin"] == "form"]
    assert any(e["path"] == "/api/auth/login" and e["method"] == "POST" for e in form_eps)


def test_query_parameters_and_js_endpoints(result):
    eps = {(e["method"], e["path"], e["origin"]): e for e in result["endpoints"]}
    assert set(eps[("GET", "/search", "link_query")]["parameters"]) == {"q", "page"}
    assert ("GET", "/api/products", "js_reference") in eps
    assert eps[("GET", "/api/products", "js_reference")]["parameters"] == ["category"]
    assert ("POST", "/api/cart", "js_reference") in eps
    assert ("DELETE", "/api/users/", "js_reference") in eps
    assert ("GET", "/api/search", "js_reference") in eps


def test_openapi(result):
    assert result["openapi"][0]["title"] == "Sample Shop API"
    eps = {(e["method"], e["path"]) for e in result["endpoints"] if e["origin"] == "openapi"}
    assert ("GET", "/api/products/{id}") in eps and ("POST", "/api/orders") in eps


def test_technology_detection_keeps_evidence(result):
    techs = {t["name"]: t for t in result["technologies"]}
    assert techs["Next.js"]["confidence"] == "high"
    assert techs["Next.js"]["evidence"]
    assert result["stack"]["framework"] == "Next.js"
    assert result["stack"]["runtime"] == "Node.js"
    assert result["stack"]["database"] == "Unknown"  # never inferred from the framework


def test_unreachable_site_is_fatal():
    out = crawl("http://127.0.0.1:9/")
    assert out["fatal"] and out["reachable"] is False and "could not be reached" in out["error"]


def test_js_rendered_page(site):
    from discovery.browser.render import Renderer

    renderer = Renderer("127.0.0.1", None)
    renderer._browser = None
    out = crawl(site, renderer=renderer, max_pages=12)
    app = next(p for p in out["pages"] if urlsplit(p["url"]).path == "/app")
    assert app["rendered"] is True
    eps = {(e["method"], e["path"]) for e in out["endpoints"]}
    assert ("GET", "/api/items") in eps
    assert any(urlsplit(p["url"]).path == "/app/settings" for p in out["pages"]) or app["links_count"] >= 1
    assert not any(h.startswith("POST") for h in Handler.hits)


@pytest.mark.parametrize("status,body,detected,valid", [
    (404, b"", False, False),
    (200, b"not json", False, False),
    (200, b"[1,2]", False, False),
    (200, b'{"routes_enabled": false, "integration": "routes", "supported_assessments": [], "version": "1"}', True, False),
    (200, b'{"routes_enabled": true, "integration": "routes", "supported_assessments": ["sqli", "rce"], "version": "1.0",'
          b' "evil": "<script>"}', True, True),
])
def test_manifest_validation(status, body, detected, valid):
    info = validate_manifest(status, body, "application/json")
    assert info["detected"] is detected and info["valid"] is valid
    if info["data"]:
        assert "evil" not in info["data"]
        assert set(info["data"]["supported_assessments"]) <= {"sqli"}
