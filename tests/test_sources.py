from hackdev_subenum.sources import parse_crtsh_json, parse_otx_json, parse_wayback_json


def test_parse_crtsh_json_extracts_and_dedupes():
    data = [
        {"name_value": "www.example.com\napi.example.com"},
        {"name_value": "*.dev.example.com"},
        {"name_value": "www.example.com"},  # duplicate
    ]
    result = parse_crtsh_json(data, "example.com")
    assert result == {"www.example.com", "api.example.com", "dev.example.com"}


def test_parse_crtsh_json_filters_unrelated_domains():
    data = [{"name_value": "www.evil.com\nwww.example.com"}]
    result = parse_crtsh_json(data, "example.com")
    assert result == {"www.example.com"}


def test_parse_crtsh_json_handles_malformed_input():
    assert parse_crtsh_json("not a list", "example.com") == set()
    assert parse_crtsh_json([{"unexpected": "field"}], "example.com") == set()
    assert parse_crtsh_json([123, None, {"name_value": None}], "example.com") == set()


def test_parse_otx_json_extracts_hostnames():
    data = {"passive_dns": [{"hostname": "api.example.com", "address": "1.2.3.4"}]}
    assert parse_otx_json(data, "example.com") == {"api.example.com"}


def test_parse_otx_json_handles_malformed_input():
    assert parse_otx_json([], "example.com") == set()
    assert parse_otx_json({"passive_dns": "not a list"}, "example.com") == set()
    assert parse_otx_json({"passive_dns": [{"hostname": None}]}, "example.com") == set()


def test_parse_wayback_json_extracts_hosts_from_urls():
    data = [
        ["original"],
        ["http://dev.example.com/path?x=1"],
        ["https://api.example.com:8080/"],
        ["https://evil.com/example.com"],
    ]
    result = parse_wayback_json(data, "example.com")
    assert result == {"dev.example.com", "api.example.com"}


def test_parse_wayback_json_handles_missing_header_or_empty():
    assert parse_wayback_json([], "example.com") == set()
    assert parse_wayback_json([["original"]], "example.com") == set()
    assert parse_wayback_json("not a list", "example.com") == set()
