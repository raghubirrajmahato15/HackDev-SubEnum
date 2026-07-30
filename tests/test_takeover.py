from hackdev_subenum.takeover import evaluate_takeover, matches_vulnerable_service


def test_matches_vulnerable_service_exact_and_subdomain():
    assert matches_vulnerable_service("myapp.herokuapp.com") == "herokuapp.com"
    assert matches_vulnerable_service("foo.github.io") == "github.io"
    assert matches_vulnerable_service("github.io") == "github.io"


def test_matches_vulnerable_service_no_match():
    assert matches_vulnerable_service("www.legit-company.com") is None
    assert matches_vulnerable_service(None) is None
    assert matches_vulnerable_service("notgithub.io.evil.com") is None


def test_evaluate_takeover_flags_dangling_cname():
    finding = evaluate_takeover(
        "old.example.com", "deleted-app.herokuapp.com", cname_resolves=False
    )
    assert finding is not None
    assert finding.service == "herokuapp.com"
    assert "NXDOMAIN" in finding.evidence


def test_evaluate_takeover_flags_via_body_fingerprint():
    finding = evaluate_takeover(
        "old.example.com",
        "myapp.herokuapp.com",
        cname_resolves=True,
        http_body="<html>Heroku | No such app</html>",
    )
    assert finding is not None
    assert finding.service == "herokuapp.com"


def test_evaluate_takeover_no_finding_when_cname_resolves_and_no_marker():
    finding = evaluate_takeover(
        "app.example.com",
        "myapp.herokuapp.com",
        cname_resolves=True,
        http_body="<html>Welcome to my totally real app</html>",
    )
    assert finding is None


def test_evaluate_takeover_ignores_non_vulnerable_cname():
    finding = evaluate_takeover("www.example.com", "cdn.legit-vendor.com", cname_resolves=False)
    assert finding is None
