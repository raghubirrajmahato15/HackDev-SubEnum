import pytest

from hackdev_subenum.resolver import (
    detect_wildcard_ip,
    is_wildcard_false_positive,
    resolve_hostname_sync,
    resolve_many,
)


def test_detect_wildcard_ip_all_same_ip():
    canaries = {
        "wc1.example.com": ["10.0.0.1"],
        "wc2.example.com": ["10.0.0.1"],
        "wc3.example.com": ["10.0.0.1"],
    }
    assert detect_wildcard_ip(canaries) == "10.0.0.1"


def test_detect_wildcard_ip_different_ips_means_no_wildcard():
    canaries = {
        "wc1.example.com": ["10.0.0.1"],
        "wc2.example.com": ["10.0.0.2"],
    }
    assert detect_wildcard_ip(canaries) is None


def test_detect_wildcard_ip_any_unresolved_means_no_wildcard():
    canaries = {
        "wc1.example.com": ["10.0.0.1"],
        "wc2.example.com": [],
    }
    assert detect_wildcard_ip(canaries) is None


def test_detect_wildcard_ip_empty_input():
    assert detect_wildcard_ip({}) is None


def test_is_wildcard_false_positive():
    assert is_wildcard_false_positive(["10.0.0.1"], "10.0.0.1") is True
    assert is_wildcard_false_positive(["10.0.0.1", "10.0.0.2"], "10.0.0.1") is False
    assert is_wildcard_false_positive([], "10.0.0.1") is False
    assert is_wildcard_false_positive(["10.0.0.1"], None) is False


def test_resolve_hostname_sync_real_localhost_resolution():
    # A real (non-mocked) resolution proving the DNS layer actually works.
    ips = resolve_hostname_sync("localhost")
    assert "127.0.0.1" in ips


def test_resolve_hostname_sync_nonexistent_returns_empty():
    ips = resolve_hostname_sync("this-definitely-does-not-exist-hackdev-test.invalid")
    assert ips == []


@pytest.mark.asyncio
async def test_resolve_many_real_localhost():
    results = await resolve_many(["localhost"], threads=2, rate=0)
    assert "127.0.0.1" in results["localhost"]
