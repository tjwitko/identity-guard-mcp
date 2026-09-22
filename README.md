# identity-guard-mcp

[![release](https://img.shields.io/github/v/release/tjwitko/identity-guard-mcp)](https://github.com/tjwitko/identity-guard-mcp/releases/latest)
[![license](https://img.shields.io/github/license/tjwitko/identity-guard-mcp)](LICENSE)

An MCP server that checks whether your workloads authenticate by proving **who they are** rather
than by presenting **something they hold**.

Passwords, static cloud keys and shared tokens are the finding, wherever they are stored. A password
fetched from a secret manager is still a password — sourcing it well changes where it lives, not
what it is.

It reads application code, Kubernetes manifests and Dockerfiles. No external scanner, no cloud
credentials, no network.

---

## Why this is not a secret scanner

A secret scanner answers a negative — *is there a credential-shaped string here?* — by matching
values. This asks a positive: **does this workload have an identity to authenticate with?**

A file containing no credential at all can still fail, because it calls an API with a shared token
or runs as the `default` ServiceAccount. No amount of pattern matching finds that.

The sharpest illustration: a connection string like `postgresql://user:password@db:5432/app` is
correctly *allowlisted* by a secret scanner — nothing leaked, that is plainly a placeholder. Here it
is a finding, because the question is whether this is password authentication, and it is, whatever
the value turns out to be. One real project shipped exactly that line as a default in application
code and it fell through both scanners.

---

## Getting started

### Requirements

**Node.js 20 or newer.** Nothing else — no scanner binary to install.

### Install

```bash
npm install --save-dev github:tjwitko/identity-guard-mcp#v1.0.0
```

### Register it with an MCP client

```json
{
  "mcpServers": {
    "identity-guard": {
      "command": "node",
      "args": ["/absolute/path/to/identity-guard-mcp/index.mjs"],
      "env": { "SCAN_ROOT": "/absolute/path/to/your/project" }
    }
  }
}
```

---

## The tool

### `check_auth_posture`

| parameter | required | description |
|---|---|---|
| `directory` | yes | Path to scan, resolved within `SCAN_ROOT` |

Returns JSON:

```json
{
  "root": "/path/scanned",
  "clean": false,
  "counts": { "blocking": 2, "advisory": 1, "filesScanned": 34 },
  "findings": [
    {
      "category": "auth.password",
      "message": "a database connection is authenticating with a password",
      "file": "app/db.py",
      "line": 22,
      "heuristic": false
    }
  ],
  "exemptions": [{ "path": "bootstrap", "reason": "SPIRE upstream CA, issued by nothing" }],
  "refusedExemptions": [],
  "allowances": [{ "file": "rules/code.mjs", "line": 91, "reason": "rule definition" }]
}
```

`clean` is keyed on blocking findings only.

---

## What it finds

**Blocking** — code authenticating with material it holds:

| rule | catches |
|---|---|
| `auth.static-cloud-key` | an AWS SDK given `aws_access_key_id` / `accessKeyId` |
| `auth.password` | a database driver taking a `password` argument |
| `auth.connection-string-password` | `scheme://user:pass@host` in code — placeholder or not |
| `auth.basic` | `HTTPBasicAuth`, `auth=(u,p)`, `Authorization: Basic` |
| `auth.dockerfile-credential` | `ENV`/`ARG` named `*PASSWORD*`, `*TOKEN*`, `*SECRET*` |
| `identity.default-sa` | a workload running as the `default` ServiceAccount |
| `identity.secret-as-auth` | a Secret holding credentials, or injected as env |

**Advisory** — `identity.unbound`: a non-default ServiceAccount with nothing in the manifests
binding it to an identity.

That one can never block, and the reason is worth stating: **EKS Pod Identity associates a role
through the AWS API and leaves no trace in YAML.** Treating absence of evidence as evidence of
absence would fail every correct Pod Identity deployment. It is the only heuristic rule here.

### What counts as an identity

Verified against current provider documentation rather than recalled:

- `eks.amazonaws.com/role-arn` — AWS IRSA
- `iam.gke.io/gcp-service-account` — GKE Workload Identity
- `azure.workload.identity/client-id` — Azure AD Workload Identity
- a SPIFFE SVID via CSI — `csi.spiffe.io` or `spiffe.csi.cert-manager.io`
- the Workload API socket reached directly — `/run/spire`, `SPIFFE_ENDPOINT_SOCKET`

Manifests are parsed with a real YAML parser, and ServiceAccounts are indexed across the whole scan
before workloads are evaluated — a Deployment and the ServiceAccount it names are routinely in
different files, and a per-file check reports every correctly-bound workload as unbound.

---

## Exceptions

Two mechanisms, because directory-wide is too blunt for the common case. **Both are reported on
every run.** A control with no legitimate way to say "this one, for this reason" gets bypassed
wholesale instead.

**Line-level** — append `// identity-guard:allow <reason>` to the line. For code that necessarily
contains the pattern: a rule definition, a test, a documentation example. This repository needs it
to pass its own scan.

**Directory-level** — drop a `.identity-exception` file whose first line is the reason. For
irreducible cases: a SPIRE server's own upstream CA, a third-party API that issues nothing but
static keys, a bootstrap path.

Two deliberate constraints on the directory form, both from an agent run that defeated an earlier
version:

- A blank or comment-only file exempts **nothing**. Told to remove an exemption, a model emptied the
  file instead, and an empty file used to exempt the directory.
- An exception at the **scan root is refused** and reported in `refusedExemptions`. At the root, the
  scope of "this one directory" is the entire project. A repository that genuinely is one bootstrap
  path must place the file per directory. That is the intended cost.

---

## Configuration

| variable | default | purpose |
|---|---|---|
| `SCAN_ROOT` | the process's working directory at startup | bounds every scan; `directory` must resolve inside it |

Only `PATH`, `HOME` and `SCAN_ROOT` survive startup. Everything else in `process.env` is deleted.

---

## Limitations

- **Static analysis cannot tell whether code uses the identity it was given.** A pod can mount an
  SVID and still authenticate with a password read from somewhere else. That gap needs a reviewer or
  an integration test.
- **Rules are literal, not semantic.** Call-site patterns for known connectors. A novel wrapper
  around a password login will pass.
- **The Terraform half lives elsewhere.** `aws.iam.access-key-created` and
  `aws.iam.user-as-service-identity` are in
  [terraform-guard-mcp](https://github.com/tjwitko/terraform-guard-mcp), where the plan engine
  already is.
- **This is the software half.** What makes passwords impossible is the platform: SPIRE issuing
  SVIDs, mTLS `STRICT` with authorization keyed on SPIFFE IDs, databases with password auth disabled
  at the server, an SCP denying `iam:CreateAccessKey`. A scanner that finds no password is weaker
  than a database that accepts none.

---

## Development

```bash
npm install
npm test          # 39 tests
```

---

## Part of agent-gate

This is one of four control servers behind
[agent-gate](https://github.com/tjwitko/agent-gate), which runs them together and fails a build on
what they find. It works standalone with any MCP client.

## License

[Apache License 2.0](LICENSE) © 2026 Tom Witkowski
