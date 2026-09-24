"""build_api_client: the kubeconfig and its derived files stay inside the
request's workdir, and an optional named `context` selects which of the
kubeconfig's contexts to build the client from (instead of
current-context)."""

from __future__ import annotations

import base64
import shutil
from pathlib import Path

import pytest

from rwdiscovery.credentials import KubeconfigError, build_api_client

# Synthetic, not a real CA: the client only writes it to a file here.
_FAKE_CA = base64.b64encode(b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n").decode()

KUBECONFIG = f"""
apiVersion: v1
kind: Config
clusters:
- name: c
  cluster:
    server: https://127.0.0.1:6443
    certificate-authority-data: {_FAKE_CA}
users:
- name: u
  user:
    token: synthetic-token
contexts:
- name: ctx
  context: {{cluster: c, user: u}}
current-context: ctx
"""

# Two clusters/contexts, so a test can prove `context=` actually changed
# which cluster the built client points at, not merely that it didn't error.
MULTI_CONTEXT_KUBECONFIG = f"""
apiVersion: v1
kind: Config
clusters:
- name: cluster-one
  cluster:
    server: https://127.0.0.1:6443
    certificate-authority-data: {_FAKE_CA}
- name: cluster-two
  cluster:
    server: https://127.0.0.1:6444
    certificate-authority-data: {_FAKE_CA}
users:
- name: u
  user:
    token: synthetic-token
contexts:
- name: ctx-one
  context: {{cluster: cluster-one, user: u}}
- name: ctx-two
  context: {{cluster: cluster-two, user: u}}
current-context: ctx-one
"""


def test_a_second_request_with_the_same_ca_does_not_reuse_the_first_requests_files(tmp_path: Path):
    first = tmp_path / "req-1"
    second = tmp_path / "req-2"
    build_api_client(KUBECONFIG, first)
    # The task host wipes a request's scope directory when the request ends.
    shutil.rmtree(first)

    api = build_api_client(KUBECONFIG, second)

    ca_file = Path(api.configuration.ssl_ca_cert)
    assert ca_file.exists()
    assert second in ca_file.parents


def test_the_raw_kubeconfig_file_is_removed_after_loading(tmp_path: Path):
    build_api_client(KUBECONFIG, tmp_path)
    assert not list(tmp_path.glob(".kubeconfig-*"))


def test_no_context_given_uses_current_context(tmp_path: Path):
    api = build_api_client(MULTI_CONTEXT_KUBECONFIG, tmp_path)
    assert api.configuration.host == "https://127.0.0.1:6443"


def test_named_context_selects_its_own_cluster_over_current_context(tmp_path: Path):
    api = build_api_client(MULTI_CONTEXT_KUBECONFIG, tmp_path, context="ctx-two")
    assert api.configuration.host == "https://127.0.0.1:6444"


def test_unknown_context_raises_a_clear_kubeconfig_error(tmp_path: Path):
    with pytest.raises(KubeconfigError, match="no-such-context"):
        build_api_client(MULTI_CONTEXT_KUBECONFIG, tmp_path, context="no-such-context")
    # No leftover raw kubeconfig file from the failed attempt.
    assert not list(tmp_path.glob(".kubeconfig-*"))
