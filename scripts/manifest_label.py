#!/usr/bin/env python3
"""Reads capabilities/k8s-discovery/manifest.yaml and prints the values the
Dockerfile bakes in as OCI labels, so the labels can never drift from the
manifest they describe -- the image itself carries its own manifest as an
OCI label, so the catalog can read it straight off the pushed image.

The final `image:` digest is a separate story -- it doesn't exist until
this image has been pushed, so it is resolved by CI *after* the push
(`docker buildx imagetools inspect`, the same two-step rw-checks-
codecollection's build-push.yaml uses for its own manifests) and is never
one of the values this script prints.

Usage (from the Dockerfile build, via `--build-arg`s computed from this
script's output):

    python3 scripts/manifest_label.py >> "$GITHUB_ENV"   # capability=..., capability_version=..., manifest_b64=...
    docker build \
      --build-arg CAPABILITY=$capability \
      --build-arg CAPABILITY_VERSION=$capability_version \
      --build-arg MANIFEST_B64=$manifest_b64 \
      -f Dockerfile.k8s-discovery .
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "capabilities" / "k8s-discovery" / "manifest.yaml"


def main() -> None:
    manifest_text = MANIFEST_PATH.read_text()
    manifest = yaml.safe_load(manifest_text)
    manifest_b64 = base64.b64encode(manifest_text.encode()).decode()

    for key, value in (
        ("capability", manifest["capability"]),
        ("capability_version", manifest["version"]),
        ("manifest_b64", manifest_b64),
    ):
        print(f"{key}={value}")


if __name__ == "__main__":
    sys.exit(main())
