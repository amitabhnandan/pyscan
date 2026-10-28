# Offline security-scan sandbox.
#
# Built ONCE on a machine with internet, then run with no network access.
# Everything the scan needs -- Python, ripgrep, semgrep, and the framework
# itself -- is baked into the image. The model
# weights are NOT in this image; they are served by a separate container (see
# compose.yaml) so the image stays small and the weights can be swapped.
#
# The scan container joins an internal-only Docker network, so even if a scan
# tried to reach the internet it could not.

FROM python:3.11-slim

# --- system tools the roles rely on -------------------------------------
# ripgrep: fast source search used by the search tool
RUN apt-get update && apt-get install -y --no-install-recommends \
        ripgrep \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- semgrep (pinned) ----------------------------------------------------
# Installed at build time while the network is available. Rules are cached
# separately by prepare-offline-bundle.sh into /opt/semgrep-rules and pointed
# at via SEMGREP_RULES_CACHE so no registry fetch happens at scan time.
RUN pip install --no-cache-dir semgrep==1.90.0

# --- framework -----------------------------------------------------------
WORKDIR /opt/pyscan
COPY pyscan/ ./pyscan/
COPY agents/ ./agents/
COPY runtime-prompts/ ./runtime-prompts/
COPY security-review-master-plan.md ./
COPY prompts/ ./prompts/
# Repository CVE corpora built with `pyscan build-cve-corpus` (read offline).
COPY cve-corpus/ ./cve-corpus/

# Pre-bundled inputs (cached semgrep rules, optional CVE corpus)
# are mounted at run time from ./offline-bundle (see prepare-offline-bundle.sh),
# not copied here, so the image does not need rebuilding to refresh them.

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/pyscan \
    PYSCAN_LLM_BASE_URL=http://model:8000/v1 \
    PYSCAN_LLM_MODEL=qwen3-coder-next-32k

COPY sandbox/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
