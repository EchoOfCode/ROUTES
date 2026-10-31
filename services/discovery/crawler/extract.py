"""HTML extraction: links, forms, scripts and page classification."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from selectolax.lexbor import LexborHTMLParser as HTMLParser

from discovery.crawler.urls import normalise

LOGIN_WORDS = re.compile(r"\b(log ?in|sign ?in|signin|login)\b", re.I)
REGISTER_WORDS = re.compile(r"\b(register|sign ?up|signup|create (an )?account|join)\b", re.I)


@dataclass
class ExtractedForm:
    action: str
    method: str
    fields: list[dict]


@dataclass
class Extracted:
    title: str | None = None
    links: list[str] = field(default_factory=list)
    forms: list[ExtractedForm] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    meta_generator: str | None = None
    text_length: int = 0
    is_login: bool = False
    is_registration: bool = False
    js_shell: bool = False


def extract(html: str, page_url: str) -> Extracted:
    tree = HTMLParser(html)
    out = Extracted()
    base_el = tree.css_first("base[href]")
    base = normalise(base_el.attributes.get("href") or "", page_url) if base_el else None
    base = base or page_url

    title = tree.css_first("title")
    out.title = (title.text(strip=True)[:300] if title else None) or None
    gen = tree.css_first('meta[name="generator"]')
    out.meta_generator = (gen.attributes.get("content") or "")[:200] if gen else None

    seen = set()
    for node in tree.css("a[href], area[href], link[rel~=alternate][href], iframe[src], frame[src]"):
        href = node.attributes.get("href") or node.attributes.get("src") or ""
        url = normalise(href, base)
        if url and url not in seen:
            seen.add(url)
            out.links.append(url)

    for node in tree.css("script"):
        src = node.attributes.get("src")
        if src:
            url = normalise(src, base)
            if url and url not in out.scripts:
                out.scripts.append(url)
        else:
            text = node.text() or ""
            if text.strip() and (node.attributes.get("type") or "text/javascript") not in ("application/ld+json",):
                out.inline_scripts.append(text[:200_000])
    for node in tree.css('link[rel="modulepreload"][href], link[rel="preload"][as="script"][href]'):
        url = normalise(node.attributes.get("href") or "", base)
        if url and url not in out.scripts:
            out.scripts.append(url)

    has_password = False
    password_fields = 0
    for form in tree.css("form"):
        action = normalise(form.attributes.get("action") or "", base) or page_url
        method = (form.attributes.get("method") or "GET").upper()
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "DIALOG"):
            method = "GET"
        fields = []
        for inp in form.css("input, select, textarea, button[name]"):
            kind = (inp.attributes.get("type") or inp.tag).lower()
            if kind in ("submit", "button", "image", "reset") and not inp.attributes.get("name"):
                continue
            if kind == "password":
                has_password = True
                password_fields += 1
            fields.append({
                "name": (inp.attributes.get("name") or inp.attributes.get("id") or None),
                "type": kind[:40],
                "required": "required" in inp.attributes,
            })
        out.forms.append(ExtractedForm(action=action, method=method, fields=fields[:100]))

    body = tree.body
    text = body.text(separator=" ", strip=True) if body else ""
    out.text_length = len(text)
    page_hint = f"{page_url} {out.title or ''}"
    form_text = " ".join((f.text(separator=" ", strip=True) or "")[:500] for f in tree.css("form"))
    if has_password and (REGISTER_WORDS.search(page_hint) or REGISTER_WORDS.search(form_text) or password_fields >= 2):
        out.is_registration = True
    elif has_password:
        out.is_login = True
    elif LOGIN_WORDS.search(page_url.rsplit("/", 1)[-1]):
        out.is_login = True
    elif REGISTER_WORDS.search(page_url.rsplit("/", 1)[-1]):
        out.is_registration = True

    out.js_shell = _looks_like_js_shell(tree, out)
    return out


def _looks_like_js_shell(tree: HTMLParser, ex: Extracted) -> bool:
    """Heuristic: little server-rendered content but client bundles present."""
    if not ex.scripts and not ex.inline_scripts:
        return False
    root = tree.css_first("#root, #app, #__next, #__nuxt, [data-reactroot], app-root, #svelte")
    root_empty = root is not None and len((root.text(strip=True) or "")) < 20 and len(root.css("a")) == 0
    noscript = any("enable javascript" in (n.text() or "").lower() for n in tree.css("noscript"))
    return (root_empty or noscript or ex.text_length < 80) and len(ex.links) < 5
