"""Iterates packs/kubernetes/vectors/chain_vectors.json -- raw object ->
chain -- per platform-contract §1's identity rule and this repo's own
Kubernetes chain-building rules (chain.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rwdiscovery.chain import chain_for_object, cluster_chain

VECTORS_PATH = Path(__file__).resolve().parent.parent / "packs" / "kubernetes" / "vectors" / "chain_vectors.json"


def _load_vectors() -> list[dict]:
    return json.loads(VECTORS_PATH.read_text())


@pytest.mark.parametrize("vector", _load_vectors(), ids=lambda v: v["description"])
def test_chain_vector(vector):
    expected = [tuple(pair) for pair in vector["expect"]["chain"]]
    if vector["object"] is None:
        chain = cluster_chain(vector["clusterName"])
    else:
        chain, _spec = chain_for_object(vector["clusterName"], vector["object"])
    assert [tuple(item) for item in chain] == expected
