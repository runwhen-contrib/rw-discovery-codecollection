"""Sanitizer tests. This is what a security reviewer
reads first, so every rule gets its own test rather than one big fixture."""

from __future__ import annotations

import base64
import hashlib

from rwdiscovery.sanitize import (
    SanitizeOptions,
    mask_and_truncate_string,
    mask_credential_shapes,
    sanitize,
)


def test_drops_managed_fields():
    obj = {
        "kind": "Deployment",
        "metadata": {"name": "api", "managedFields": [{"manager": "kubectl"}]},
        "spec": {},
    }
    document, _ = sanitize(obj)
    assert "managedFields" not in document["metadata"]


def test_drops_last_applied_annotation():
    obj = {
        "kind": "Deployment",
        "metadata": {
            "name": "api",
            "annotations": {
                "kubectl.kubernetes.io/last-applied-configuration": '{"secret":"leak"}',
                "team": "payments",
            },
        },
        "spec": {},
    }
    document, _ = sanitize(obj)
    assert "kubectl.kubernetes.io/last-applied-configuration" not in document["metadata"]["annotations"]
    assert document["metadata"]["annotations"]["team"] == "payments"


def test_status_split_from_document():
    obj = {
        "kind": "Deployment",
        "metadata": {"name": "api"},
        "spec": {"replicas": 3},
        "status": {"readyReplicas": 3},
    }
    document, status = sanitize(obj)
    assert "status" not in document
    assert status == {"readyReplicas": 3}


def test_secret_data_and_string_data_removed_key_names_kept():
    obj = {
        "kind": "Secret",
        "apiVersion": "v1",
        "type": "Opaque",
        "metadata": {"name": "db-creds", "namespace": "acme-payments"},
        "data": {"password": "aHVudGVyMg=="},
        "stringData": {"username": "acme_app"},
    }
    document, _ = sanitize(obj)
    assert "data" not in document
    assert "stringData" not in document
    assert document["secretKeys"] == ["password", "username"]
    assert document["type"] == "Opaque"


def test_configmap_values_stored_in_full_by_default():
    obj = {
        "kind": "ConfigMap",
        "metadata": {"name": "acme-app-config", "namespace": "acme-payments"},
        "data": {"nginx.conf": "proxy_read_timeout 300;\nserver_name acme.internal;"},
    }
    document, _ = sanitize(obj)
    assert document["data"]["nginx.conf"] == "proxy_read_timeout 300;\nserver_name acme.internal;"
    expected_hash = hashlib.sha256(document["data"]["nginx.conf"].encode()).hexdigest()
    assert document["dataHashes"]["nginx.conf"] == {
        "size": len(document["data"]["nginx.conf"]),
        "sha256": expected_hash,
    }


def test_configmap_keys_only_mode_drops_values_and_stores_size_only_no_hash():
    """`keysOnly` is stricter than the default masked/unmasked split below:
    every value's hash is dropped, not just masked ones -- the hosted,
    multi-tenant install this mode exists for wants no fingerprint of the
    value at all."""
    obj = {
        "kind": "ConfigMap",
        "metadata": {"name": "acme-app-config", "namespace": "acme-payments"},
        "data": {"key.txt": "some value"},
    }
    document, _ = sanitize(obj, SanitizeOptions(config_map_values="keysOnly"))
    assert "data" not in document
    assert document["dataHashes"]["key.txt"]["size"] == len(b"some value")
    assert "sha256" not in document["dataHashes"]["key.txt"]


def test_configmap_unmasked_value_keeps_size_and_hash():
    obj = {
        "kind": "ConfigMap",
        "metadata": {"name": "acme-app-config", "namespace": "acme-payments"},
        "data": {"region": "us-east-1"},
    }
    document, _ = sanitize(obj)
    assert document["dataHashes"]["region"] == {
        "size": len(b"us-east-1"),
        "sha256": hashlib.sha256(b"us-east-1").hexdigest(),
    }


def test_configmap_value_masked_by_key_name_gets_size_only_no_hash():
    obj = {
        "kind": "ConfigMap",
        "metadata": {"name": "acme-app-config", "namespace": "acme-payments"},
        "data": {"password": "hunter2"},
    }
    document, _ = sanitize(obj)
    assert document["data"]["password"] == "***MASKED:credential***"
    assert document["dataHashes"]["password"] == {"size": len(b"hunter2")}


def test_configmap_value_masked_by_credential_shape_gets_size_only_no_hash():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQdLp6uT9c2y8IyOFPFJKfhCEG_ppEZmvo"
    obj = {
        "kind": "ConfigMap",
        "metadata": {"name": "acme-app-config", "namespace": "acme-payments"},
        "data": {"bootstrap.conf": f"token={jwt}"},
    }
    document, _ = sanitize(obj)
    assert jwt not in document["data"]["bootstrap.conf"]
    assert "sha256" not in document["dataHashes"]["bootstrap.conf"]
    assert document["dataHashes"]["bootstrap.conf"]["size"] == len(f"token={jwt}".encode())


def test_configmap_binary_data_masked_by_key_name_gets_size_only_no_hash():
    payload = b"whatever-bytes"
    obj = {
        "kind": "ConfigMap",
        "metadata": {"name": "acme-bin-config", "namespace": "acme-payments"},
        "binaryData": {"api_token": base64.b64encode(payload).decode()},
    }
    document, _ = sanitize(obj)
    assert document["binaryDataHashes"]["api_token"] == {"size": len(payload)}


def test_configmap_binary_data_keys_only_mode_drops_hash_too():
    payload = b"\x00\x01\x02binary"
    obj = {
        "kind": "ConfigMap",
        "metadata": {"name": "acme-bin-config", "namespace": "acme-payments"},
        "binaryData": {"blob.bin": base64.b64encode(payload).decode()},
    }
    document, _ = sanitize(obj, SanitizeOptions(config_map_values="keysOnly"))
    assert document["binaryDataHashes"]["blob.bin"] == {"size": len(payload)}


def test_configmap_values_are_never_truncated_but_are_masked():
    long_value = "x" * (20 * 1024)  # 20 KiB, over the generic 16 KiB cap
    obj = {
        "kind": "ConfigMap",
        "metadata": {"name": "acme-big-config", "namespace": "acme-payments"},
        "data": {"blob.txt": long_value},
    }
    document, _ = sanitize(obj)
    assert document["data"]["blob.txt"] == long_value  # not truncated
    assert "***TRUNCATED" not in document["data"]["blob.txt"]


def test_configmap_binary_data_reduced_to_size_and_hash():
    payload = b"\x00\x01\x02binary"
    obj = {
        "kind": "ConfigMap",
        "metadata": {"name": "acme-bin-config", "namespace": "acme-payments"},
        "binaryData": {"blob.bin": base64.b64encode(payload).decode()},
    }
    document, _ = sanitize(obj)
    assert "binaryData" not in document
    assert document["binaryDataHashes"]["blob.bin"] == {
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def test_env_value_masked_by_narrow_name_password():
    obj = {
        "kind": "Deployment",
        "metadata": {"name": "acme-api", "namespace": "acme-payments"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "api",
                            "env": [
                                {"name": "DB_PASSWORD", "value": "hunter2"},
                                {"name": "LOG_LEVEL", "value": "info"},
                            ],
                        }
                    ]
                }
            }
        },
    }
    document, _ = sanitize(obj)
    env = document["spec"]["template"]["spec"]["containers"][0]["env"]
    by_name = {e["name"]: e["value"] for e in env}
    assert by_name["DB_PASSWORD"] == "***MASKED:credential***"
    assert by_name["LOG_LEVEL"] == "info"


def test_broad_words_are_not_whole_masked():
    """`key`, `auth`, `conn`, `dsn` are deliberately not in
    the narrow list -- they name hosts/connection strings, not secrets."""
    obj = {
        "kind": "Deployment",
        "metadata": {"name": "acme-api", "namespace": "acme-payments"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "api",
                            "env": [
                                {"name": "AUTH_URL", "value": "https://auth.acme.internal"},
                                {"name": "DB_CONN_STRING", "value": "host=acme-db port=5432"},
                            ],
                        }
                    ]
                }
            }
        },
    }
    document, _ = sanitize(obj)
    env = document["spec"]["template"]["spec"]["containers"][0]["env"]
    by_name = {e["name"]: e["value"] for e in env}
    assert by_name["AUTH_URL"] == "https://auth.acme.internal"
    assert by_name["DB_CONN_STRING"] == "host=acme-db port=5432"


def test_value_from_is_kept_untouched():
    obj = {
        "kind": "Deployment",
        "metadata": {"name": "acme-api", "namespace": "acme-payments"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "api",
                            "env": [
                                {
                                    "name": "DB_PASSWORD",
                                    "valueFrom": {"secretKeyRef": {"name": "acme-db-creds", "key": "password"}},
                                }
                            ],
                        }
                    ]
                }
            }
        },
    }
    document, _ = sanitize(obj)
    env0 = document["spec"]["template"]["spec"]["containers"][0]["env"][0]
    assert env0["valueFrom"]["secretKeyRef"]["name"] == "acme-db-creds"
    assert "value" not in env0


def test_url_dsn_userinfo_password_masked_host_kept():
    dsn = "postgres://app:s3cr3t-p4ss@acme-orders-db.acme-payments.svc:5432/orders"
    masked = mask_credential_shapes(dsn)
    assert masked == "postgres://app:****@acme-orders-db.acme-payments.svc:5432/orders"


def test_pem_block_masked():
    pem = "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0B\n-----END PRIVATE KEY-----"
    assert mask_credential_shapes(pem) == "***MASKED:pem***"


def test_jwt_masked():
    """Not prefixed with a narrow key name (`token=...` is now its own,
    more specific key=value-line rule, tested separately below) -- this is
    purely the standalone JWT-shape pattern."""
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQdLp6uT9c2y8IyOFPFJKfhCEG_ppEZmvo"
    result = mask_credential_shapes(f"Authorization: Bearer {jwt}")
    assert jwt not in result
    assert "***MASKED:jwt***" in result


def test_aws_access_key_masked():
    text = "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"
    result = mask_credential_shapes(text)
    assert "AKIAABCDEFGHIJKLMNOP" not in result
    assert "***MASKED:cloud-key***" in result


def test_hex_digest_not_masked_as_high_entropy():
    """git shas and image digests are all-lowercase hex and must survive --
    masking them would hide exactly the references dependency rules need."""
    sha = "a3f5c9d21e7b408f9c6d1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d"
    assert mask_credential_shapes(sha) == sha


def test_ordinary_prose_not_mangled():
    prose = "This ConfigMap configures the nginx reverse proxy for the payments service."
    assert mask_credential_shapes(prose) == prose


def test_multiline_config_value_masks_password_lines_leaves_others_intact():
    """A ConfigMap value that is itself a small `.env`-shaped blob: only the
    password-like lines' values are masked, in every supported line form;
    URLs, hosts and reference lines survive untouched."""
    blob = (
        "DB_HOST=acme-orders-db.acme-payments.svc\n"
        "DB_PASSWORD=hunter2\n"
        "log.level: info\n"
        "auth.token: abc123\n"
        "region = us-east-1\n"
    )
    masked = mask_credential_shapes(blob)
    assert "DB_HOST=acme-orders-db.acme-payments.svc" in masked
    assert "DB_PASSWORD=***MASKED:credential***" in masked
    assert "hunter2" not in masked
    assert "log.level: info" in masked
    assert "auth.token: ***MASKED:credential***" in masked
    assert "abc123" not in masked
    assert "region = us-east-1" in masked


def test_multiline_config_value_masks_quoted_json_style_password():
    blob = '{"username": "acme_app", "password": "hunter2"}'
    masked = mask_credential_shapes(blob)
    assert '"username": "acme_app"' in masked
    assert '"password": "***MASKED:credential***"' in masked
    assert "hunter2" not in masked


def test_multiline_config_value_does_not_mask_urls_or_reference_lines():
    """`password_reset_url` and `secretName` both contain a narrow word as a
    SUBSTRING, but neither's last dotted/underscored segment is one --
    exactly the false positive the JSON/env key CONTAINS rule would produce
    if reused here verbatim."""
    blob = (
        "endpoint=https://acme.example.com/api\n"
        "password_reset_url: https://acme.example.com/reset\n"
        "secretName: acme-tls\n"
    )
    assert mask_credential_shapes(blob) == blob


def test_key_value_line_masking_does_not_break_dsn_userinfo_masking():
    """A DSN's `scheme://` and `user:pass@` colons never have a space after
    them, so the key=value line rules must never fire inside one -- the
    existing userinfo-specific masking is what handles it."""
    dsn = "postgres://app:s3cr3t-p4ss@acme-orders-db.acme-payments.svc:5432/orders"
    assert mask_credential_shapes(dsn) == "postgres://app:****@acme-orders-db.acme-payments.svc:5432/orders"


def test_configmap_value_with_embedded_password_line_is_masked_and_gets_no_hash():
    """Item 1 (no hash for a masked value) and item 2 (line-level password
    masking) together, end to end through `sanitize()`."""
    blob = "DB_HOST=acme-orders-db.svc\nDB_PASSWORD=hunter2\n"
    obj = {
        "kind": "ConfigMap",
        "metadata": {"name": "acme-app-env", "namespace": "acme-payments"},
        "data": {"app.env": blob},
    }
    document, _ = sanitize(obj)
    assert "hunter2" not in document["data"]["app.env"]
    assert "DB_PASSWORD=***MASKED:credential***" in document["data"]["app.env"]
    assert "DB_HOST=acme-orders-db.svc" in document["data"]["app.env"]
    assert "sha256" not in document["dataHashes"]["app.env"]
    assert document["dataHashes"]["app.env"]["size"] == len(blob.encode())


def test_other_string_over_16kb_truncated_with_hash():
    long_value = "a" * (17 * 1024)
    masked = mask_and_truncate_string(long_value)
    assert masked.startswith("***TRUNCATED:size=")
    assert str(len(long_value.encode())) in masked


def test_configmap_data_key_named_password_still_whole_masked():
    """The narrow key-name rule applies to ConfigMap data keys too, not
    just env var names."""
    obj = {
        "kind": "ConfigMap",
        "metadata": {"name": "acme-app-config", "namespace": "acme-payments"},
        "data": {"password": "hunter2", "region": "us-east-1"},
    }
    document, _ = sanitize(obj)
    assert document["data"]["password"] == "***MASKED:credential***"
    assert document["data"]["region"] == "us-east-1"


# --- references must survive, and nothing bypasses the walk ---


def test_uids_and_owner_reference_uids_survive():
    """`metadata.uid` and `ownerReferences[].uid` are the `owner_reference`
    strategy's join key (platform-contract §2). UUIDs clear the entropy
    threshold, so the high-entropy pass must not treat them as tokens."""
    uid = "3f2b1c9e-8a7d-4e6f-b5c4-1a2b3c4d5e6f"
    owner_uid = "9c8b7a6f-5e4d-4c3b-a291-0f1e2d3c4b5a"
    obj = {
        "kind": "ReplicaSet",
        "metadata": {
            "name": "acme-api-7d9f8c6b5d",
            "uid": uid,
            "ownerReferences": [{"kind": "Deployment", "name": "acme-api", "uid": owner_uid}],
        },
        "spec": {},
    }
    document, _ = sanitize(obj)
    assert document["metadata"]["uid"] == uid
    assert document["metadata"]["ownerReferences"][0]["uid"] == owner_uid


def test_long_generated_object_names_survive():
    name = "prometheus-kube-prometheus-stack-prometheus-rulefiles-0"
    obj = {
        "kind": "StatefulSet",
        "metadata": {"name": name},
        "spec": {"template": {"spec": {"volumes": [{"name": "rules", "configMap": {"name": name}}]}}},
    }
    document, _ = sanitize(obj)
    assert document["metadata"]["name"] == name
    assert document["spec"]["template"]["spec"]["volumes"][0]["configMap"]["name"] == name


def test_mixed_case_high_entropy_token_is_still_masked():
    token = "Zx9kQ2mP7vL4nR8sT1wY6bC3dF5gH0jKq"
    assert mask_credential_shapes(f"key {token} end") == "key ***MASKED:token*** end"


def test_secret_name_references_survive_the_narrow_name_rule():
    """`secretName` contains "secret", but its value names an object -- the
    `uses_secret` rules (pack.yaml) read exactly these fields."""
    deployment = {
        "kind": "Deployment",
        "metadata": {"name": "acme-api"},
        "spec": {"template": {"spec": {"volumes": [{"name": "tls", "secret": {"secretName": "acme-api-tls"}}]}}},
    }
    ingress = {"kind": "Ingress", "metadata": {"name": "acme"}, "spec": {"tls": [{"secretName": "acme-tls"}]}}
    certificate = {"kind": "Certificate", "metadata": {"name": "acme"}, "spec": {"secretName": "acme-cert"}}
    assert sanitize(deployment)[0]["spec"]["template"]["spec"]["volumes"][0]["secret"]["secretName"] == "acme-api-tls"
    assert sanitize(ingress)[0]["spec"]["tls"][0]["secretName"] == "acme-tls"
    assert sanitize(certificate)[0]["spec"]["secretName"] == "acme-cert"
    # ...while a key that holds the secret itself is still whole-masked.
    assert sanitize({"kind": "X", "spec": {"clientSecret": "hunter2"}})[0]["spec"]["clientSecret"] == (
        "***MASKED:credential***"
    )


def test_status_is_sanitized_too():
    """`status` is returned separately but still leaves the cluster -- an
    operator-written CRD status can carry a DSN or a token."""
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQdLp6uT9c2y8IyOFPFJKfhCEG_ppEZmvo"
    obj = {
        "kind": "Database",
        "metadata": {"name": "orders"},
        "spec": {},
        "status": {
            "connection": "postgres://app:s3cr3t@orders-db.acme-payments.svc:5432/orders",
            "bootstrapToken": jwt,
            "report": "r" * (17 * 1024),
        },
    }
    _, status = sanitize(obj)
    assert status["connection"] == "postgres://app:****@orders-db.acme-payments.svc:5432/orders"
    assert jwt not in str(status)
    assert status["report"].startswith("***TRUNCATED:size=")


def test_secret_metadata_is_walked_and_key_names_kept_verbatim():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQdLp6uT9c2y8IyOFPFJKfhCEG_ppEZmvo"
    obj = {
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {
            "name": "acme-db-creds",
            "annotations": {
                "kubectl.kubernetes.io/last-applied-configuration": '{"data":{"password":"aHVudGVyMg=="}}',
                "acme.example/bootstrap": jwt,
            },
        },
        "data": {"password": "aHVudGVyMg==", "secret-token": "dG9r"},
    }
    document, _ = sanitize(obj)
    annotations = document["metadata"]["annotations"]
    assert "kubectl.kubernetes.io/last-applied-configuration" not in annotations
    # A Secret's annotation values are blanked outright (not just generically
    # masked) unless the key is one of a short, safe-by-convention allowlist
    # -- see test_secret_annotation_values_blanked_except_allowlisted_prefixes.
    assert annotations["acme.example/bootstrap"] == "***MASKED:secret-annotation***"
    assert jwt not in str(annotations)
    assert document["secretKeys"] == ["password", "secret-token"]


def test_secret_annotation_values_blanked_except_allowlisted_prefixes():
    """kapp's `kapp.k14s.io/original` (and similar 'last full manifest'
    conventions) can carry the WHOLE Secret, base64 data included -- a short
    base64 value embedded in a big JSON blob is far below the generic
    masker's high-entropy length floor, so it must never reach generic
    masking for a Secret's annotations at all."""
    obj = {
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {
            "name": "acme-db-creds",
            "annotations": {
                "kapp.k14s.io/original": '{"kind":"Secret","data":{"password":"aHVudGVyMg=="}}',
                "kubernetes.io/service-account.name": "acme-sa",
                "cert-manager.io/certificate-name": "acme-tls",
                "meta.helm.sh/release-name": "acme",
                "app.kubernetes.io/managed-by": "Helm",
                "helm.sh/hook": "pre-install",
            },
        },
        "data": {"password": "aHVudGVyMg=="},
    }
    document, _ = sanitize(obj)
    annotations = document["metadata"]["annotations"]
    assert annotations["kapp.k14s.io/original"] == "***MASKED:secret-annotation***"
    assert "aHVudGVyMg==" not in str(annotations)
    assert annotations["kubernetes.io/service-account.name"] == "acme-sa"
    assert annotations["cert-manager.io/certificate-name"] == "acme-tls"
    assert annotations["meta.helm.sh/release-name"] == "acme"
    assert annotations["app.kubernetes.io/managed-by"] == "Helm"
    assert annotations["helm.sh/hook"] == "pre-install"


def test_configmap_metadata_is_walked():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQdLp6uT9c2y8IyOFPFJKfhCEG_ppEZmvo"
    obj = {
        "kind": "ConfigMap",
        "metadata": {"name": "acme-app-config", "annotations": {"acme.example/token": jwt}},
        "data": {"region": "us-east-1"},
    }
    document, _ = sanitize(obj)
    assert jwt not in str(document["metadata"])
    assert document["data"] == {"region": "us-east-1"}


def test_name_value_pairs_outside_env_are_masked_by_name():
    """Argo CD helm parameters, Tekton params, ... share env's `{name,
    value}` shape; the `name` is the credential signal for `value`."""
    obj = {
        "kind": "Application",
        "metadata": {"name": "acme"},
        "spec": {
            "source": {
                "helm": {
                    "parameters": [
                        {"name": "postgresql.auth.password", "value": "hunter2"},
                        {"name": "image.tag", "value": "1.2.3"},
                    ]
                }
            }
        },
    }
    document, _ = sanitize(obj)
    params = {p["name"]: p["value"] for p in document["spec"]["source"]["helm"]["parameters"]}
    assert params["postgresql.auth.password"] == "***MASKED:credential***"
    assert params["image.tag"] == "1.2.3"
