# Product context

The product config tells every role what the product is, what an attacker
would want from it, and where outside input gets in. pyscan copies these
fields into each role's instructions, so they steer what recon maps first,
what the red team chases, and how the blue team judges reachability.

Without them the hunt treats every file the same and has to guess what
matters. The capability check reports `product context` as missing while
`highest_value_asset` or `known_entry_points` still hold template text.

Write plain, specific sentences. Name real things in the code (routes,
services, tools, data stores) so the model can find them with `search`.

## Fields

### `product_name`, `product_key`, `product_aliases`, `product_versions`

- `product_name`: the name people use for it.
- `product_key`: short, stable id (letters, digits, `-`). Names the CVE
  corpus folder `cve-corpus/<product_key>/`.
- `product_aliases`: other names it or its main components go by, as they
  might appear in advisories or code (package names, service names).
- `product_versions`: the version or branch being reviewed.

### `highest_value_asset` (one string)

The worst realistic outcome for the business if an attacker succeeds. Not
"the data" or "the server": say **what** they get and **why it matters**,
naming the secrets, data, or capabilities involved. The hunt ranks targets by
how close they get to this.

- Weak: `"Customer data"`
- Strong: `"Read access to every tenant's invoices in the billing Postgres
  database, and the Stripe secret key in the app config, which allows
  issuing refunds"`

### `known_entry_points` (list of strings)

Every way outside input reaches the product, one per item, with **who can
use it** and **what authentication applies**. Include non-HTTP inputs: queues,
webhooks, scheduled jobs reading external data, files, CLI arguments, and,
for AI systems, any untrusted text that reaches a model (tickets, chat
messages, documents, logs, web pages).

Format each as: `<interface> -- <who can reach it> -- <auth> -- <what it does>`

- `"Web API (port 8080, routes in app/api/) -- employees on the corporate
  network -- SSO login, session cookie -- account and order management"`
- `"Support-ticket importer (jobs/import_tickets.py) -- anyone who can open a
  ticket -- none on the ticket text -- ticket text is summarised by an LLM
  that can call internal tools"`

### `extra_context_lines` (list of strings)

Anything else that changes what counts as a vulnerability:

- **Deployment and exposure:** where it runs, what is internet-facing,
  network restrictions, what sits in front (gateway, VPN, ingress auth).
- **Trust boundaries:** which parties are trusted (operators, admins) and
  which are not (end users, ticket authors, external services, LLM output).
- **Privileges the product holds:** cloud roles, cluster access, tokens it
  can use, commands it can run on someone's behalf.
- **Known or accepted risks and out-of-scope areas**, so the hunt does not
  spend its budget re-finding them.
- **Security controls you rely on** (e.g. "all tool calls need user
  approval"), so the blue team checks them instead of assuming them.

### `threat_model_doc` (path, optional)

A readable threat model, if one exists. Recon uses it to weight the map; it
is a priority input, not a scope limit.

### Other fields

`source_roots`, `cve_corpus_dir`, `default_hunt_mode` and the rest
are described in `docs/local-runner.md`. `bootstrap_lines` holds setup notes
for the operator and rarely matters to the hunt.

## Template

Copy into `product-config.json` and replace every `<...>`:

```json
{
  "product_key": "<short-id>",
  "product_name": "<Product name>",
  "product_aliases": ["<package or service name>", "<other name>"],
  "product_versions": "<version, branch, or commit being reviewed>",
  "source_roots": ["<folder>", "<folder>"],

  "highest_value_asset": "<what an attacker gets in the worst realistic case, naming the secrets, data, or capabilities, and why it matters>",

  "known_entry_points": [
    "<interface> -- <who can reach it> -- <auth> -- <what it does>",
    "<interface> -- <who can reach it> -- <auth> -- <what it does>"
  ],

  "extra_context_lines": [
    "Deployment: <where it runs; what is internet-facing; what sits in front>",
    "Trusted: <operators/admins/services treated as trusted>",
    "Untrusted: <end users, external content, model output, ...>",
    "Privileges held: <tokens, cloud roles, cluster access, commands it can run>",
    "Controls relied on: <auth, approval steps, sandboxing, network policy>",
    "Accepted risks / out of scope: <...>"
  ],

  "threat_model_doc": "not available",
  "cve_corpus_dir": "not available",
  "default_hunt_mode": "FULL_48H",
  "default_optional_keywords": "not enabled"
}
```
