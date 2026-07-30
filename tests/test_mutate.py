from hackdev_subenum.mutate import generate_mutations


def test_generate_mutations_produces_prefix_and_suffix_variants():
    result = generate_mutations(["api.example.com"], "example.com", cap=1000)
    assert "dev-api.example.com" in result
    assert "api-dev.example.com" in result
    assert "api-v2.example.com" in result


def test_generate_mutations_excludes_existing_subdomains():
    result = generate_mutations(["dev-api.example.com", "api.example.com"], "example.com", cap=1000)
    assert "dev-api.example.com" not in result


def test_generate_mutations_respects_cap():
    result = generate_mutations(["api.example.com", "web.example.com"], "example.com", cap=5)
    assert len(result) == 5


def test_generate_mutations_zero_cap_returns_empty():
    assert generate_mutations(["api.example.com"], "example.com", cap=0) == []


def test_generate_mutations_is_deterministic_and_sorted():
    r1 = generate_mutations(["api.example.com"], "example.com", cap=1000)
    r2 = generate_mutations(["api.example.com"], "example.com", cap=1000)
    assert r1 == r2
    assert r1 == sorted(r1)


def test_generate_mutations_custom_prefixes_suffixes():
    result = generate_mutations(
        ["foo.example.com"], "example.com", cap=100, prefixes=["x-"], suffixes=["-y"]
    )
    assert result == ["foo-y.example.com", "x-foo.example.com"]
