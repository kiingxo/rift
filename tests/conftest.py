import pytest


@pytest.fixture(autouse=True)
def isolate_scanner_config(monkeypatch, tmp_path):
    monkeypatch.delenv("REDIRECT_SCANNER_ALLOWLIST", raising=False)
    monkeypatch.delenv("REDIRECT_SCANNER_ALLOW_INTERNAL", raising=False)
    monkeypatch.delenv("RIFT_ALLOWLIST", raising=False)
    monkeypatch.delenv("RIFT_ALLOW_INTERNAL", raising=False)
    monkeypatch.setattr(
        "rift.safety.local_allowlist_path",
        lambda: tmp_path / "allowlist.local.txt",
    )
