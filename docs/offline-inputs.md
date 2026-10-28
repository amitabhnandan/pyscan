# Offline inputs

pyscan scans with no internet access. Data that an online scanner
would fetch live are instead staged on disk before a scan, and the roles read
them locally.

## 1. CVE knowledge -> a CVE corpus built for the repository

`recon-cve-mapper` builds `.hunt/cve-inventory.md` from a CVE corpus on disk,
never from the network during the scan. pyscan builds that corpus for each
target repository from the [OSV](https://osv.dev) database:

1. **Find the libraries the repository uses.** Nothing from the target is run.
   - Manifests: `requirements*.txt`, `pyproject.toml`, `uv.lock` and installed
     `*.dist-info` metadata in virtual environments.
   - A scan of the source for imports, which catches libraries used but not
     declared. Python imports are mapped to their PyPI packages (skipping the
     standard library and the repo's own modules). Their version is unknown, so they get full advisory history.
2. **Look them up in OSV:** advisories affecting the exact versions in use,
   plus each library's advisory history. Duplicate GHSA/PYSEC records are
   merged.
3. **Write the PyPI folder:**

```
cve-corpus/<product_key>/
  python/
    INDEX.md               versions in use, advisories affecting them, and
                           where each library was found
    packages/<library>.md  a library's advisories, affected and fixed versions
```

The corpus lives inside the pyscan repo and can be committed, so a scan can
reuse it offline.

**When it is built.** At the start of `pyscan run` (recon modes), pyscan
looks for `cve_corpus_dir` from the product config, else
`cve-corpus/<product_key>/`. If a language the repository uses has no corpus
and the run has network access (`--allow-egress`), it builds it before recon;
the capability check shows this as `[build]`, and building sends library
names and versions to api.osv.dev. Pass `--no-cve-build` to skip it.

**Offline runs** (the sandbox) cannot reach OSV, so build the corpus first on a
machine with internet and bring it along:

```bash
python3 -m pyscan build-cve-corpus --product-config product-config.json \
    --source-repo /path/to/code
```

Rebuild it before each scan to pick up new advisories.

**A hand-staged corpus** also works: point `cve_corpus_dir` at a folder of
text, Markdown or JSON (NVD exports, vendor bulletins, prior review notes).
Without language subfolders it is passed to the mapper as-is.

With no corpus at all, the mapper builds a **class-history inventory**: the
vulnerability classes common to the product's category and visible frameworks,
marked as such. It is weaker than real advisory data.

## 2. Semgrep rules -> cached rulesets

Semgrep's `p/...` rule sets normally come from its online registry. For
offline scans, save them once as plain YAML files:

```bash
python3 -m pyscan cache-semgrep-rules     # needs internet
```

This writes `offline-bundle/semgrep-rules/p_<name>.yml` (git-ignored: registry
rules are under the Semgrep Rules License). `prepare-offline-bundle.sh` runs it
too. pyscan uses the cache from `SEMGREP_RULES_CACHE`, else
`offline-bundle/semgrep-rules/` when it exists; the compose file sets
`SEMGREP_RULES_CACHE` for the sandbox.

In an offline run, `run_semgrep` passes only the cached files, never registry
names, and switches off semgrep's version check and metrics, so semgrep makes
no network calls. Rule sets without a cached file are skipped and reported;
with none cached, `run_semgrep` reports degraded coverage and the hunt relies
on `search` and `read_file`. The capability check lists any uncached rule
sets before the run starts. Online runs (`--allow-egress`) use the cache too
when present.

## 3. Git history -> optional summary

If the target is a git checkout, recon starts by running a few read-only
`git log` queries and writes `.hunt/git-history.md`: the most frequently
changed and recently added Python files over the last 18 months,
commits whose subject suggests a security fix, and reverts. Tests and docs
are left out. recon-test-gap uses it to find new code without tests, and
hunt briefs point to it (the hardening-gap pass starts from the security-fix
commits and checks sibling code for the same flaw).

The model has no git tool; pyscan runs git itself, with the target's
config ignored where it could run commands (fsmonitor, hooks, pager,
external diff). Without a `.git` folder or a git binary the step is skipped
and the capability check shows `[skip]`, not a gap.

## What the model never does

The model has exactly one network peer: the local inference endpoint. It cannot
browse, download, or resolve DNS. Every fact it uses comes from the source tree,
the staged corpus, or the recon artifacts already on disk.
