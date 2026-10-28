#!/usr/bin/env bash
# Build the offline bundle on a machine WITH internet. The bundle is then
# mounted read-only into the air-gapped scan container. Nothing here runs at
# scan time -- this is the one place network access is expected.
#
# Produces, under ./offline-bundle:
#   semgrep-rules/   -- cached semgrep registry rulesets
#   cve-corpus/      -- (optional) advisory text you stage here
#
# The model weights are handled separately (download once, mount read-only);
# see sandbox/README.md.
set -euo pipefail

BUNDLE_DIR="${1:-./offline-bundle}"

log() { printf '[bundle] %s\n' "$*"; }

mkdir -p "${BUNDLE_DIR}/semgrep-rules" "${BUNDLE_DIR}/cve-corpus"

# --- semgrep rules -------------------------------------------------------
# semgrep normally downloads registry rule sets at scan time. Offline that
# fails, so save them now as plain YAML files; run_semgrep passes these files
# instead of the registry names.
log "caching semgrep rule sets"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RULES_OUT="$(cd "${BUNDLE_DIR}" && pwd)/semgrep-rules"
( cd "${REPO_ROOT}" && python3 -m pyscan cache-semgrep-rules --out "${RULES_OUT}" )

cat > "${BUNDLE_DIR}/README.txt" <<EOF
Offline bundle for pyscan. Mount read-only at /opt/offline-bundle.
  semgrep-rules/ cached rulesets; point SEMGREP_RULES_CACHE here
  cve-corpus/   stage exported CVE/advisory text here for recon-cve-mapper,
                then set product-config.json "cve_corpus_dir" to this path
Built $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

log "bundle ready at ${BUNDLE_DIR}"
ls -R "${BUNDLE_DIR}" | head -40
