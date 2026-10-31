"""Controlled sample website for discovery tests and the compose `testing` profile.

Deliberately small and deterministic. It contains: a ROUTES manifest, robots
and sitemap files, forms (search, login, registration), a JavaScript-rendered
page, API references in a bundle, an OpenAPI document, internal/external
redirects and enough product pages to exercise the 25-page limit.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LAYOUT = """<!doctype html><html><head><title>{title}</title>
<script src="/_next/static/chunks/main-abc123.js" defer></script></head>
<body><div id="__next"><nav><a href="/">Home</a> <a href="/about">About</a> <a href="/login">Sign in</a>
<a href="/register">Create account</a> <a href="/search?q=shoes&page=1">Search shoes</a>
<a href="/products">Products</a> <a href="/app">App</a> <a href="https://external.example/partner">Partner</a>
<a href="/logout">Log out</a> <a href="mailto:hello@example.com">Mail</a> <a href="/redirect-internal">Moved</a>
<a href="/redirect-external">Elsewhere</a> <a href="/private/admin">Admin</a> <a href="/about#team">Team</a>
<a href="/about/">About again</a></nav>
<main>{body}</main></div></body></html>"""

PAGES = {
    "/": ("Sample Shop", "<h1>Welcome to the sample shop</h1><p>" + "Lorem ipsum dolor sit amet. " * 20 + "</p>"),
    "/about": ("About us", "<h1>About</h1><p>" + "We sell things. " * 30 + "</p>"),
    "/login": ("Sign in", '<form method="post" action="/api/auth/login"><input name="email" type="email" required>'
                          '<input name="password" type="password" required><button>Sign in</button></form>'),
    "/register": ("Create account", '<form method="post" action="/api/auth/register"><input name="email" type="email">'
                                    '<input name="password" type="password"><input name="confirm" type="password">'
                                    '<button>Sign up</button></form>'),
    "/search": ("Search", '<form action="/search" method="get"><input name="q"><select name="sort"><option>new</option>'
                          '</select></form><p>' + "Results. " * 30 + "</p>"),
    "/products": ("Products", "<ul>" + "".join(f'<li><a href="/products/{i}">Product {i}</a></li>' for i in range(1, 41))
                  + "</ul><p>" + "Catalogue. " * 20 + "</p>"),
}

APP_SHELL = """<!doctype html><html><head><title>App</title></head><body>
<div id="root"></div><noscript>You need to enable JavaScript to run this app.</noscript>
<script>
  document.getElementById('root').innerHTML = '<h1>Dashboard</h1><a href="/app/settings">Settings</a>';
  fetch('/api/items?limit=5').then(function () {});
</script></body></html>"""

BUNDLE = """!function(){var a="/api/search";fetch("/api/products?category=all");
axios.post("/api/cart",{id:1});fetch(`/api/users/${id}`,{method:"DELETE"});
var ext="https://api.external.example/v1/track";var React={};}();"""

OPENAPI = {"openapi": "3.0.0", "info": {"title": "Sample Shop API", "version": "1.2.0"},
           "paths": {"/api/products/{id}": {"get": {"summary": "Get product",
                                                     "parameters": [{"name": "id", "in": "path"}]}},
                     "/api/orders": {"post": {"summary": "Create order", "requestBody": {}}}}}

MANIFEST = {"routes_enabled": True, "integration": "routes", "supported_assessments": ["sqli"], "version": "1.0"}


class Handler(BaseHTTPRequestHandler):
    server_version = "SampleServer/1.0"
    hits: list[str] = []

    def log_message(self, *args):  # quiet
        pass

    def _send(self, status, body, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "Next.js")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_POST(self):  # the crawler must never submit forms
        Handler.hits.append("POST " + self.path)
        self._send(405, "no")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        Handler.hits.append(self.path)
        path = self.path.split("?", 1)[0]
        host = self.headers.get("Host", "localhost")
        if path == "/.well-known/routes.json":
            return self._send(200, json.dumps(MANIFEST), "application/json")
        if path == "/robots.txt":
            return self._send(200, f"User-agent: *\nDisallow: /private/\nSitemap: http://{host}/sitemap.xml\n", "text/plain")
        if path == "/sitemap.xml":
            urls = "".join(f"<url><loc>http://{host}{p}</loc></url>" for p in ("/about", "/products/3"))
            urls += "<url><loc>https://other-host.example/x</loc></url>"
            return self._send(200, f'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>',
                              "application/xml")
        if path == "/openapi.json":
            return self._send(200, json.dumps(OPENAPI), "application/json")
        if path == "/_next/static/chunks/main-abc123.js":
            return self._send(200, BUNDLE, "application/javascript")
        if path == "/redirect-internal":
            return self._send(301, "", headers={"Location": "/about"})
        if path == "/redirect-external":
            return self._send(302, "", headers={"Location": "https://external.example/landing"})
        if path in ("/app", "/app/"):
            return self._send(200, APP_SHELL)
        if path == "/app/settings":
            return self._send(200, LAYOUT.format(title="Settings", body="<p>" + "Settings. " * 20 + "</p>"))
        if path == "/logout":
            return self._send(200, "logged out")
        if path.startswith("/private/"):
            return self._send(200, LAYOUT.format(title="Private", body="secret area"))
        if path.startswith("/products/") and path[10:].isdigit():
            n = int(path[10:])
            return self._send(200, LAYOUT.format(title=f"Product {n}", body=f"<p>{'Product details. ' * 20}</p>"))
        normalised = path.rstrip("/") or "/"
        if normalised in PAGES:
            title, body = PAGES[normalised]
            return self._send(200, LAYOUT.format(title=title, body=body))
        return self._send(404, LAYOUT.format(title="Not found", body="Not found"))


def serve(port: int = 8080, host: str = "0.0.0.0") -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"sample site on :{port}", flush=True)
    serve(port).serve_forever()
