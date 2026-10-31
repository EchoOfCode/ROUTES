"""Evidence-based technology detection.

Every detection keeps the evidence that produced it. Nothing is inferred
without evidence: in particular the database stays "Unknown" unless the site
itself exposes database-specific output (e.g. an error message).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

STRONG, WEAK = 2, 1


@dataclass
class Tech:
    name: str
    category: str
    score: int = 0
    version: str | None = None
    evidence: list[str] = field(default_factory=list)

    def add(self, evidence: str, strength: int, version: str | None = None) -> None:
        if evidence not in self.evidence and len(self.evidence) < 10:
            self.evidence.append(evidence[:300])
            self.score += strength
        if version and not self.version:
            self.version = version[:50]

    @property
    def confidence(self) -> str:
        return "high" if self.score >= 3 else "medium" if self.score >= 2 else "low"


# (header, regex, name, category, strength)
HEADER_RULES = [
    ("x-powered-by", r"next\.js\s*([\d.]+)?", "Next.js", "framework", STRONG),
    ("x-powered-by", r"express", "Express", "framework", STRONG),
    ("x-powered-by", r"php/?([\d.]+)?", "PHP", "language", STRONG),
    ("x-powered-by", r"asp\.net", "ASP.NET", "framework", STRONG),
    ("x-powered-by", r"nuxt", "Nuxt", "framework", STRONG),
    ("x-aspnet-version", r"([\d.]+)", "ASP.NET", "framework", STRONG),
    ("x-nextjs-cache", r".", "Next.js", "framework", STRONG),
    ("x-nextjs-prerender", r".", "Next.js", "framework", STRONG),
    ("x-nextjs-matched-path", r".", "Next.js", "framework", STRONG),
    ("x-nextjs-stale-time", r".", "Next.js", "framework", STRONG),
    ("x-vercel-id", r".", "Vercel", "hosting", STRONG),
    ("x-vercel-cache", r".", "Vercel", "hosting", STRONG),
    ("server", r"^vercel", "Vercel", "hosting", STRONG),
    ("x-nf-request-id", r".", "Netlify", "hosting", STRONG),
    ("server", r"netlify", "Netlify", "hosting", STRONG),
    ("cf-ray", r".", "Cloudflare", "cdn", STRONG),
    ("server", r"cloudflare", "Cloudflare", "cdn", STRONG),
    ("x-amz-cf-id", r".", "Amazon CloudFront", "cdn", STRONG),
    ("fly-request-id", r".", "Fly.io", "hosting", STRONG),
    ("x-render-origin-server", r".", "Render", "hosting", STRONG),
    ("x-github-request-id", r".", "GitHub Pages", "hosting", WEAK),
    ("x-drupal-cache", r".", "Drupal", "cms", STRONG),
    ("x-generator", r"drupal\s*([\d.]+)?", "Drupal", "cms", STRONG),
    ("x-shopify-stage", r".", "Shopify", "ecommerce", STRONG),
    ("server", r"nginx/?([\d.]+)?", "nginx", "web_server", STRONG),
    ("server", r"openresty/?([\d.]+)?", "OpenResty", "web_server", STRONG),
    ("server", r"apache/?([\d.]+)?", "Apache HTTP Server", "web_server", STRONG),
    ("server", r"microsoft-iis/?([\d.]+)?", "Microsoft IIS", "web_server", STRONG),
    ("server", r"caddy", "Caddy", "web_server", STRONG),
    ("server", r"litespeed", "LiteSpeed", "web_server", STRONG),
    ("server", r"gunicorn/?([\d.]+)?", "Gunicorn", "web_server", STRONG),
    ("server", r"uvicorn", "Uvicorn", "web_server", STRONG),
    ("server", r"werkzeug/?([\d.]+)?", "Werkzeug", "web_server", STRONG),
    ("server", r"kestrel", "Kestrel", "web_server", STRONG),
]

COOKIE_RULES = [
    (r"^PHPSESSID=", "PHP", "language"),
    (r"^JSESSIONID=", "Java", "language"),
    (r"^laravel_session=", "Laravel", "framework"),
    (r"^XSRF-TOKEN=.*", None, None),
    (r"^csrftoken=", "Django", "framework"),
    (r"^ASP\.NET_SessionId=", "ASP.NET", "framework"),
    (r"^connect\.sid=", "Express", "framework"),
    (r"^_[a-z0-9_]+_session=", "Ruby on Rails", "framework"),
    (r"^wordpress_", "WordPress", "cms"),
]

# (regex over HTML, name, category, strength)
HTML_RULES = [
    (r'<div[^>]+id="__next"', "Next.js", "framework", STRONG),
    (r"/_next/static/", "Next.js", "framework", STRONG),
    (r'id="__NEXT_DATA__"', "Next.js", "framework", STRONG),
    (r"self\.__next_f", "Next.js", "framework", STRONG),
    (r"/_nuxt/", "Nuxt", "framework", STRONG),
    (r"window\.__NUXT__", "Nuxt", "framework", STRONG),
    (r'ng-version="([\d.]+)"', "Angular", "ui_library", STRONG),
    (r"data-reactroot", "React", "ui_library", STRONG),
    (r"\sdata-v-[0-9a-f]{6,}", "Vue.js", "ui_library", WEAK),
    (r"/wp-content/", "WordPress", "cms", STRONG),
    (r"/wp-includes/", "WordPress", "cms", STRONG),
    (r"/_astro/", "Astro", "framework", STRONG),
    (r"__sveltekit|/_app/immutable/", "SvelteKit", "framework", STRONG),
    (r"__remixContext", "Remix", "framework", STRONG),
    (r"___gatsby", "Gatsby", "framework", STRONG),
    (r"cdn\.shopify\.com", "Shopify", "ecommerce", STRONG),
    (r'name="csrfmiddlewaretoken"', "Django", "framework", STRONG),
    (r'name="__VIEWSTATE"', "ASP.NET", "framework", STRONG),
    (r"googletagmanager\.com/gtag|google-analytics\.com/", "Google Analytics", "analytics", STRONG),
    (r"googletagmanager\.com/gtm\.js", "Google Tag Manager", "analytics", STRONG),
    (r"plausible\.io/js", "Plausible Analytics", "analytics", STRONG),
    (r"js\.stripe\.com", "Stripe.js", "payments", STRONG),
    (r"www\.google\.com/recaptcha", "reCAPTCHA", "security", STRONG),
    (r"challenges\.cloudflare\.com/turnstile", "Cloudflare Turnstile", "security", STRONG),
]

GENERATOR_RULES = [
    (r"wordpress\s*([\d.]+)?", "WordPress", "cms"),
    (r"drupal\s*([\d.]+)?", "Drupal", "cms"),
    (r"joomla", "Joomla", "cms"),
    (r"hugo\s*([\d.]+)?", "Hugo", "framework"),
    (r"jekyll\s*v?([\d.]+)?", "Jekyll", "framework"),
    (r"gatsby\s*([\d.]+)?", "Gatsby", "framework"),
    (r"ghost\s*([\d.]+)?", "Ghost", "cms"),
    (r"astro\s*v?([\d.]+)?", "Astro", "framework"),
    (r"docusaurus\s*v?([\d.]+)?", "Docusaurus", "framework"),
    (r"wix\.com", "Wix", "website_builder"),
    (r"squarespace", "Squarespace", "website_builder"),
    (r"webflow", "Webflow", "website_builder"),
    (r"next\.js", "Next.js", "framework"),
    (r"nuxt", "Nuxt", "framework"),
]

SCRIPT_URL_RULES = [
    (r"jquery[.-]?([\d.]+\d)?(?:\.min)?\.js", "jQuery", "javascript_library"),
    (r"/_next/static/chunks/", "Next.js", "framework"),
    (r"/_nuxt/", "Nuxt", "framework"),
    (r"react(?:-dom)?(?:\.production)?(?:\.min)?\.js", "React", "ui_library"),
    (r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js", "Vue.js", "ui_library"),
    (r"bootstrap(?:\.bundle)?(?:\.min)?\.js", "Bootstrap", "ui_library"),
]

BUNDLE_RULES = [
    (r"__SECRET_INTERNALS_DO_NOT_USE_OR_WARN_YOU_WILL_BE_FIRED|react-dom\.production|ReactDOM", "React", "ui_library"),
    (r"__VUE__|Vue\.createApp|createApp\([^)]*\)\.mount", "Vue.js", "ui_library"),
    (r"@angular/core|ɵɵdefineComponent", "Angular", "ui_library"),
    (r"__NEXT_P|next/dist/|__next_app__", "Next.js", "framework"),
    (r"svelte/internal|SvelteComponent", "Svelte", "ui_library"),
]

# Only explicit, database-specific output counts as database evidence.
DATABASE_ERROR_RULES = [
    (r"SQLSTATE\[|PDOException", "Database (via PHP PDO)", None),
    (r"PG::[A-Z][A-Za-z]+Error|psql: error|postgresql[^<]{0,40}error|relation \"[^\"]+\" does not exist", "PostgreSQL", None),
    (r"You have an error in your SQL syntax|mysqli?_|MySQL server version", "MySQL", None),
    (r"ORA-\d{5}", "Oracle Database", None),
    (r"SQLite(?:3)?::|sqlite3\.OperationalError|SQLITE_ERROR", "SQLite", None),
    (r"Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string", "Microsoft SQL Server", None),
    (r"MongoServerError|MongoError", "MongoDB", None),
]

LANGUAGE_FOR = {
    "Next.js": ("JavaScript", "Node.js"), "Nuxt": ("JavaScript", "Node.js"), "Express": ("JavaScript", "Node.js"),
    "Remix": ("JavaScript", "Node.js"), "SvelteKit": ("JavaScript", "Node.js"), "Gatsby": ("JavaScript", None),
    "Astro": ("JavaScript", None), "Docusaurus": ("JavaScript", None),
    "WordPress": ("PHP", None), "Laravel": ("PHP", None), "Drupal": ("PHP", None), "Joomla": ("PHP", None),
    "Django": ("Python", None), "ASP.NET": ("C#", ".NET"), "Ruby on Rails": ("Ruby", None), "Hugo": ("Go", None),
    "Jekyll": ("Ruby", None),
}
# Frameworks preferred over UI libraries when choosing the headline framework.
FRAMEWORK_CATEGORIES = ("framework", "cms", "website_builder", "ecommerce")


class Detector:
    def __init__(self) -> None:
        self.techs: dict[str, Tech] = {}
        self.database: Tech | None = None

    def _hit(self, name: str, category: str, evidence: str, strength: int, version: str | None = None) -> None:
        tech = self.techs.setdefault(name, Tech(name=name, category=category))
        tech.add(evidence, strength, version)

    def headers(self, headers: dict[str, str], cookies: list[str], url: str) -> None:
        for header, pattern, name, category, strength in HEADER_RULES:
            value = headers.get(header)
            if value is None:
                continue
            m = re.search(pattern, value, re.I)
            if m:
                version = m.group(1) if m.groups() and m.group(1) else None
                self._hit(name, category, f"HTTP header {header}: {value[:80]}", strength, version)
        for cookie in cookies:
            for pattern, name, category in COOKIE_RULES:
                if name and re.search(pattern, cookie, re.I):
                    self._hit(name, category, f"Cookie name {cookie.split('=', 1)[0][:60]}", WEAK + 1)

    def html(self, html: str, url: str, generator: str | None) -> None:
        sample = html[:500_000]
        for pattern, name, category, strength in HTML_RULES:
            m = re.search(pattern, sample, re.I)
            if m:
                version = m.group(1) if m.groups() and m.group(1) else None
                self._hit(name, category, f"Page markup on {url[:120]} contains {m.group(0)[:60]!r}", strength, version)
        if "__NEXT_DATA__" in sample:
            self._hit("React", "ui_library", "Next.js pages render with React", WEAK)
        if generator:
            for pattern, name, category in GENERATOR_RULES:
                m = re.search(pattern, generator, re.I)
                if m:
                    version = m.group(1) if m.groups() and m.group(1) else None
                    self._hit(name, category, f'<meta name="generator" content="{generator[:80]}">', STRONG + 1, version)
        for pattern, name, _ in DATABASE_ERROR_RULES:
            m = re.search(pattern, sample, re.I)
            if m:
                self.database = self.database or Tech(name=name, category="database")
                self.database.add(f"Database error text on {url[:120]}: {m.group(0)[:80]!r}", STRONG)

    def script_url(self, url: str) -> None:
        for pattern, name, category in SCRIPT_URL_RULES:
            m = re.search(pattern, url, re.I)
            if m:
                version = m.group(1) if m.groups() and m.group(1) else None
                self._hit(name, category, f"Script {url[-120:]}", STRONG if name != "React" else WEAK + 1, version)

    def bundle(self, js: str, url: str) -> None:
        sample = js[:2_000_000]
        for pattern, name, category in BUNDLE_RULES:
            if re.search(pattern, sample):
                self._hit(name, category, f"JavaScript bundle {url[-100:]} contains {name} runtime code", WEAK + 1)

    def openapi(self, url: str) -> None:
        self._hit("OpenAPI", "api_specification", f"Specification served at {url[:200]}", STRONG + 1)

    # ------------------------------------------------------------- output
    def results(self) -> list[dict]:
        items = sorted(self.techs.values(), key=lambda t: (-t.score, t.name))
        out = [{"name": t.name, "category": t.category, "version": t.version, "confidence": t.confidence,
                "evidence": t.evidence} for t in items if t.score > 0]
        if self.database:
            d = self.database
            out.append({"name": d.name, "category": "database", "version": None, "confidence": d.confidence,
                        "evidence": d.evidence})
        return out

    def summary(self) -> dict:
        frameworks = [t for t in self.techs.values() if t.category in FRAMEWORK_CATEGORIES]
        frameworks.sort(key=lambda t: (-t.score, t.name))
        framework = frameworks[0] if frameworks else None
        if framework is None:
            libs = sorted((t for t in self.techs.values() if t.category == "ui_library"), key=lambda t: -t.score)
            framework = libs[0] if libs else None
        language, runtime = LANGUAGE_FOR.get(framework.name, (None, None)) if framework else (None, None)
        if language is None:
            for name in ("PHP", "Java"):
                if name in self.techs:
                    language = name
        if framework and framework.category == "ui_library" and language is None:
            language = "JavaScript"
        return {
            "framework": framework.name if framework else "Unknown",
            "language": language or "Unknown",
            "runtime": runtime or ("Node.js" if "Express" in self.techs else "Unknown"),
            "database": self.database.name if self.database else "Unknown",
            "confidence": framework.confidence if framework else "low",
        }
