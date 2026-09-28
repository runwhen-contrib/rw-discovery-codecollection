#!/usr/bin/env bash
# Regenerate requirements.txt from requirements.in.
#
# Runs inside the image's own base so the dependency resolution matches
# what the image installs -- resolving on a developer's macOS/arm64 host
# would pin different platform-specific wheels than linux/amd64 needs.
#
# --generate-hashes records a sha256 for every artifact of every pinned
# version, which is what `pip install --require-hashes` verifies at build
# time.
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm --platform linux/amd64 \
  -v "$PWD:/w" -w /w \
  python:3.12-slim \
  sh -c '
    set -e
    pip install --quiet --no-cache-dir uv
    uv pip compile requirements.in \
      --generate-hashes \
      --universal \
      --output-file requirements.txt
  '
echo "wrote requirements.txt"
