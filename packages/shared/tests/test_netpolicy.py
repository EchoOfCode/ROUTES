import pytest

from routes_shared.netpolicy import (
    UrlPolicyError,
    all_addresses_allowed,
    is_blocked_ip,
    parse_target_url,
    same_host,
)


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.3.4",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fd00:ec2::254",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "64:ff9b::a00:1",
        "2002:7f00:1::",  # 6to4 wrapping 127.0.0.1
        "not-an-ip",
    ],
)
def test_blocked_ips(ip):
    assert is_blocked_ip(ip)


@pytest.mark.parametrize("ip", ["93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_ips_allowed(ip):
    assert not is_blocked_ip(ip)


def test_all_addresses_strict():
    assert all_addresses_allowed(["1.1.1.1"])
    assert not all_addresses_allowed(["1.1.1.1", "10.0.0.1"])
    assert not all_addresses_allowed([])


def test_parse_target_url_normalises():
    t = parse_target_url("Example.COM/path?q=1#x")
    assert t.url == "https://example.com/path"
    assert t.hostname == "example.com"
    assert t.port == 443
    assert t.origin == "https://example.com"


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "ftp://example.com",
        "file:///etc/passwd",
        "http://user:pass@example.com",
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data",
        "http://10.1.2.3",
        "https://example.com:22",
        "http://printer.local",
        "http://intranet",
    ],
)
def test_parse_target_url_rejects(raw):
    with pytest.raises(UrlPolicyError):
        parse_target_url(raw)


def test_dev_allow_hosts():
    t = parse_target_url("http://sample-site:8080/", dev_allow_hosts=frozenset({"sample-site"}))
    assert t.hostname == "sample-site"
    assert t.port == 8080


def test_same_host_is_exact():
    assert same_host("https://example.com/a", "example.com")
    assert same_host("http://EXAMPLE.com./a", "example.com")
    assert not same_host("https://www.example.com/a", "example.com")
    assert not same_host("https://example.com.evil.net/", "example.com")
    assert not same_host("javascript:alert(1)", "example.com")
