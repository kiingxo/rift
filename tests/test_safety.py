import pytest

from rift.config import ScanConfig
from rift.safety import (
    ScopeError,
    ensure_ip_allowed,
    host_is_allowlisted,
    load_allowlist,
    save_extra_domains,
    validate_allowlist_entry,
    validate_target,
)

HOST = "app.example.com"
CONFIG = ScanConfig(allowlist=(HOST,))


def test_a_fresh_scan_has_no_built_in_domain():
    assert ScanConfig().allowlist == ()


def test_an_allowlisted_host_includes_its_subdomains():
    assert validate_target(f"https://{HOST}/login", CONFIG).startswith(f"https://{HOST}/login")
    assert validate_target(f"https://api.{HOST}/login", CONFIG).startswith(f"https://api.{HOST}/")


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/login",
        f"https://{HOST}.evil.com/login",
        f"https://not{HOST}/login",
        "https://evil-app.example.com.example/login",
        "http://127.0.0.1/login",
        "http://localhost/login",
        "http://169.254.169.254/latest/meta-data",
        "http://metadata.google.internal/",
        "http://10.1.2.3/",
        "https://user:secret@app.example.com/login",
        "file:///etc/passwd",
        "https://2130706433/",
        f"https://{HOST}:8443/login",
        f"https://{HOST}/logo.png",
        f"https://{HOST}/api/orders",
    ],
)
def test_out_of_scope_urls_are_rejected(url):
    with pytest.raises(ScopeError):
        validate_target(url, CONFIG)


def test_login_is_allowed_and_fragments_are_removed():
    assert validate_target(f"https://{HOST}/login#session", CONFIG) == f"https://{HOST}/login"


@pytest.mark.parametrize("path", ["/logout", "/unsubscribe", "/subscribe", "/register"])
def test_state_changing_paths_are_not_scanned(path):
    with pytest.raises(ScopeError):
        validate_target(f"https://{HOST}{path}", CONFIG)


def test_suffix_confusion_does_not_match_the_allowlist():
    assert host_is_allowlisted(f"{HOST}.evil.com", CONFIG.allowlist) is False
    assert host_is_allowlisted(f"not{HOST}", CONFIG.allowlist) is False
    assert host_is_allowlisted(f"api.{HOST}", CONFIG.allowlist) is True


def test_metadata_stays_blocked_in_lab_mode_even_if_allowlisted():
    lab = ScanConfig(allowlist=("metadata.google.internal", "169.254.169.254"), allow_internal=True)
    with pytest.raises(ScopeError, match="metadata"):
        validate_target("http://metadata.google.internal/", lab)
    with pytest.raises(ScopeError, match="metadata"):
        validate_target("http://169.254.169.254/", lab)
    with pytest.raises(ScopeError, match="metadata"):
        ensure_ip_allowed("::ffff:169.254.169.254", allow_internal=True)


@pytest.mark.parametrize(
    "ip",
    ["127.0.0.1", "10.1.1.1", "192.168.1.20", "172.16.4.4", "::1", "100.64.1.1", "224.0.0.1", "0.0.0.0"],
)
def test_non_public_addresses_are_blocked_outside_the_lab(ip):
    with pytest.raises(ScopeError):
        ensure_ip_allowed(ip, allow_internal=False)


def test_lab_mode_allows_loopback_but_not_metadata_or_multicast():
    ensure_ip_allowed("127.0.0.1", allow_internal=True)
    ensure_ip_allowed("10.0.0.8", allow_internal=True)
    with pytest.raises(ScopeError):
        ensure_ip_allowed("169.254.169.254", allow_internal=True)
    with pytest.raises(ScopeError):
        ensure_ip_allowed("100.100.100.200", allow_internal=True)
    with pytest.raises(ScopeError):
        ensure_ip_allowed("fd00:ec2::254", allow_internal=True)
    with pytest.raises(ScopeError):
        ensure_ip_allowed("224.0.0.1", allow_internal=True)


def test_public_dns_address_is_allowed():
    ensure_ip_allowed("8.8.8.8", allow_internal=False)
    ensure_ip_allowed("2001:4860:4860::8888", allow_internal=False)


def test_allowlist_entries_reject_urls_wildcards_and_ips():
    with pytest.raises(ScopeError):
        validate_allowlist_entry("https://example.com/path")
    with pytest.raises(ScopeError):
        validate_allowlist_entry("*.example.com")
    with pytest.raises(ScopeError):
        validate_allowlist_entry("127.0.0.1")
    assert validate_allowlist_entry("Example.COM") == "example.com"


def test_saved_domains_round_trip(tmp_path):
    path = tmp_path / "allowlist.local.txt"
    save_extra_domains(["example.com", HOST], path)
    assert load_allowlist(path) == ("example.com", HOST)


def test_clearing_saved_domains_leaves_the_allowlist_empty(tmp_path):
    path = tmp_path / "allowlist.local.txt"
    save_extra_domains(["example.com"], path)
    save_extra_domains([], path)
    assert load_allowlist(path) == ()
