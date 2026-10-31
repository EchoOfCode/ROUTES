"""A02 (cryptographic failures / misconfiguration) detection tests.

Each fixture injects extra files into the nextjs-pg repository and runs the
real analyzer, so these exercise the bundled Semgrep rules as Semgrep actually
evaluates them rather than asserting on the YAML.
"""

import json

import pytest

from .test_analysis import run_fixture

A02_SOURCE = """\
import crypto from "crypto";
import jwt from "jsonwebtoken";

export function hashPassword(password: string) {
  return crypto.createHash("md5").update(password).digest("hex");
}

export function hashLegacy(body: { password: string }) {
  return crypto.createHash("sha1").update(body.password).digest("hex");
}

export function hashStrong(password: string) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

export function etagFor(buf: Buffer) {
  return crypto.createHash("md5").update(buf).digest("hex");
}

export const signed = jwt.sign({ sub: "1" }, "hunter2-signing-value");
export const signedFallback = jwt.sign({ sub: "1" }, process.env.JWT_SECRET || "fallback-value");
export const signedProperly = jwt.sign({ sub: "1" }, process.env.JWT_SECRET as string);

export const authOptions = { providers: [], secret: "committed-auth-value" };
export const authOptionsEnv = { providers: [], secret: process.env.NEXTAUTH_SECRET };

export const resetToken = Math.random().toString(36).substring(2);
export const otpPayload = { otp: Math.random() };
export const retryDelay = Math.random() * 1000;
export const sortWeight = Math.random();
"""

CONFIGURED_HEADERS = """\
module.exports = {
  async headers() {
    return [{
      source: "/:path*",
      headers: [
        { key: "Content-Security-Policy", value: "default-src 'self'" },
        { key: "Strict-Transport-Security", value: "max-age=63072000" },
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "X-Frame-Options", value: "DENY" },
        { key: "Referrer-Policy", value: "no-referrer" },
      ],
    }];
  },
};
"""

MIDDLEWARE_HEADERS = """\
import { NextResponse } from "next/server";

export function middleware() {
  const res = NextResponse.next();
  res.headers.set("Content-Security-Policy", "default-src 'self'");
  res.headers.set("Strict-Transport-Security", "max-age=63072000");
  res.headers.set("X-Content-Type-Options", "nosniff");
  res.headers.set("X-Frame-Options", "DENY");
  res.headers.set("Referrer-Policy", "no-referrer");
  return res;
}
"""


@pytest.fixture(scope="module")
def a02(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("a02")
    return run_fixture("nextjs-pg", tmp, extra={"lib/a02.ts": A02_SOURCE})


@pytest.fixture(scope="module")
def headers_in_config(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("a02-headers-config")
    return run_fixture("nextjs-pg", tmp, extra={"next.config.js": CONFIGURED_HEADERS})


@pytest.fixture(scope="module")
def headers_in_middleware(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("a02-headers-mw")
    return run_fixture("nextjs-pg", tmp, extra={"middleware.ts": MIDDLEWARE_HEADERS})


def lines_for(result, rule_id, file="lib/a02.ts"):
    return sorted(f["line"] for f in result["findings"] if f["rule_id"] == rule_id and f["file"] == file)


def one(result, rule_id):
    return next(f for f in result["findings"] if f["rule_id"] == rule_id)


# ------------------------------------------------------------ password hashing

def test_password_hashed_with_md5_and_sha1_is_reported(a02):
    assert lines_for(a02, "routes.crypto.password-weak-hash") == [5, 9]


def test_strong_hash_on_a_password_is_not_reported(a02):
    assert 13 not in lines_for(a02, "routes.crypto.password-weak-hash")


def test_weak_hash_on_a_non_secret_stays_a_low_severity_finding(a02):
    # An MD5 etag is not a password problem, so the generic rule still covers it.
    assert lines_for(a02, "routes.crypto.weak-hash") == [17]
    assert one(a02, "routes.crypto.weak-hash")["severity"] == "low"


def test_password_hashing_is_not_reported_by_both_hash_rules(a02):
    weak = set(lines_for(a02, "routes.crypto.weak-hash"))
    password = set(lines_for(a02, "routes.crypto.password-weak-hash"))
    assert not (weak & password)


def test_password_hash_finding_is_high_severity_and_names_a_real_fix(a02):
    f = one(a02, "routes.crypto.password-weak-hash")
    assert (f["severity"], f["confidence"]) == ("high", "high")
    assert any(alg in f["recommendation"].lower() for alg in ("bcrypt", "scrypt", "argon2"))


# ----------------------------------------------------------------- jwt secrets

def test_hardcoded_and_fallback_jwt_secrets_are_reported(a02):
    assert lines_for(a02, "routes.crypto.weak-jwt-secret") == [20, 21]


def test_jwt_secret_read_only_from_the_environment_is_not_reported(a02):
    assert 22 not in lines_for(a02, "routes.crypto.weak-jwt-secret")


def test_hardcoded_and_fallback_auth_secrets_are_reported(a02):
    assert lines_for(a02, "routes.crypto.hardcoded-auth-secret") == [24]


def test_auth_secret_read_only_from_the_environment_is_not_reported(a02):
    assert 25 not in lines_for(a02, "routes.crypto.hardcoded-auth-secret")


# --------------------------------------------------------------- weak randomness

def test_math_random_for_a_token_or_otp_is_reported(a02):
    assert lines_for(a02, "routes.crypto.math-random-token") == [27, 28]


def test_math_random_for_a_delay_or_weight_is_not_reported(a02):
    reported = lines_for(a02, "routes.crypto.math-random-token")
    assert 29 not in reported and 30 not in reported


# ------------------------------------------------------------ security headers

def test_missing_security_headers_reported_for_a_bare_next_config(a02):
    # The fixture's next.config.js only sets images.domains.
    f = one(a02, "routes.config.missing-security-headers")
    assert f["file"] == "next.config.js"
    assert f["severity"] == "medium"
    assert f["technical_details"]["missing_headers"] == [
        "content-security-policy", "referrer-policy", "strict-transport-security",
        "x-content-type-options", "x-frame-options",
    ]
    assert "does not define a headers() function" in f["evidence_summary"]


def test_security_headers_check_is_not_a_semgrep_finding(a02):
    assert one(a02, "routes.config.missing-security-headers")["technical_details"]["engine"] == "next-config-check"


def test_no_finding_when_headers_are_set_in_next_config(headers_in_config):
    assert not [f for f in headers_in_config["findings"] if f["rule_id"] == "routes.config.missing-security-headers"]


def test_no_finding_when_headers_are_set_in_middleware(headers_in_middleware):
    assert not [f for f in headers_in_middleware["findings"]
                if f["rule_id"] == "routes.config.missing-security-headers"]


# -------------------------------------------------- snippet / fingerprint fixes

def test_semgrep_snippets_contain_real_source(a02):
    """Semgrep >= 1.18 puts "requires login" in extra.lines; we read the file."""
    semgrep_findings = [f for f in a02["findings"] if f["technical_details"].get("engine") == "semgrep"]
    assert semgrep_findings
    assert not [f for f in semgrep_findings if "requires login" in f["technical_details"]["snippet"]]
    assert "createHash" in one(a02, "routes.crypto.password-weak-hash")["technical_details"]["snippet"]


def test_two_matches_of_one_rule_in_one_file_are_kept_apart(a02):
    """Fingerprints are (rule, file, snippet); identical snippets would collapse."""
    found = [f for f in a02["findings"]
             if f["rule_id"] == "routes.crypto.password-weak-hash" and f["file"] == "lib/a02.ts"]
    assert len(found) == 2
    assert len({f["fingerprint"] for f in found}) == 2


def test_injected_secret_values_never_leave_the_sandbox(a02):
    dump = json.dumps(a02)
    for value in ("hunter2-signing-value", "committed-auth-value", "fallback-value"):
        assert value not in dump, f"{value} leaked into the analyzer result"
