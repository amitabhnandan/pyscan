#!/usr/bin/env bash
# Scanner container entrypoint.
#
# 1. Prove the sandbox is network-isolated (hard fail otherwise).
# 2. Prove the local model endpoint answers.
# 3. Hand off to the pyscan CLI with whatever args compose passed.
set -euo pipefail

echo "[entrypoint] verifying network isolation ..."
python3 -m pyscan check-egress

echo "[entrypoint] verifying local model endpoint ..."
python3 -m pyscan check-model

echo "[entrypoint] starting hunt: $*"
exec python3 -m pyscan "$@" --output-dir /scan/output
