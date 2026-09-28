"""path.py's `enc()` mirrors one rule from papi's path grammar (platform-
contract §1) -- these vectors are taken directly from that grammar's own
worked examples, so a drift in either place is caught here."""

from __future__ import annotations

from rwdiscovery.path import enc


def test_enc_percent_encodes_colon_and_preserves_case():
    assert enc("system:controller:job-controller") == "system%3Acontroller%3Ajob-controller"


def test_enc_lower_name_case():
    assert enc("ACME-Repo", name_case="lower") == "acme-repo"


def test_enc_passes_through_ordinary_characters():
    assert enc("api-7d9f") == "api-7d9f"
