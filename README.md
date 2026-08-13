# identity-guard-mcp

Enforces workload identity: services authenticate by proving **who they are**, not by presenting
**something they hold**. Passwords, static cloud keys and shared tokens are unacceptable
regardless of where they are stored — a password fetched from a secret manager is still a
password.

One tool, `check_auth_posture(directory)`, over application code, Kubernetes manifests and
Dockerfiles.

## Why this is not secret-guard

`secret-guard` answers a negative — "is there a credential-shaped string here?" — by matching
values. This asks a positive: "does this workload have an identity to authenticate with?" A file
containing no credential at all still fails, because it calls an API with a shared token or runs
as the default ServiceAccount. Pattern matching cannot answer that.

## Two kinds of finding

**Blocking** — code that authenticates with material it holds:

| rule | catches |
|---|---|
| `auth.static-cloud-key` | an AWS SDK given `aws_access_key_id` / `accessKeyId` |
| `auth.password-connect` | a database driver taking a `password` argument |
| `auth.basic` | `HTTPBasicAuth`, `auth=(u,p)`, `Authorization: Basic` |
| `auth.dockerfile-credential` | `ENV`/`ARG` named `*PASSWORD*`, `*TOKEN*`, `*SECRET*` |
| `identity.default-sa` | a workload running as the `default` ServiceAccount |
| `identity.secret-as-auth` | a Secret holding credentials, or injected as env |

**Advisory** — `identity.unbound`: a non-default ServiceAccount with nothing in the manifests
binding it to an identity. This cannot block, because **EKS Pod Identity associates a role through
the AWS API and leaves no trace in YAML** — treating absence of evidence as evidence of absence
would fail every correct Pod Identity deployment.

## What counts as an identity

Verified against current provider docs rather than memory:

- `eks.amazonaws.com/role-arn` (AWS IRSA)
- `iam.gke.io/gcp-service-account` (GKE Workload Identity)
- `azure.workload.identity/client-id` (Azure AD Workload Identity)
- a SPIFFE SVID via CSI — `csi.spiffe.io` (spiffe/spiffe-csi) or
  `spiffe.csi.cert-manager.io` (cert-manager/csi-driver-spiffe)
- the Workload API socket reached directly (`/run/spire`, `SPIFFE_ENDPOINT_SOCKET`)

## Exceptions

Two mechanisms, because directory-wide is too blunt for the common case.

**Line-level** — append `// identity-guard:allow <reason>` to the line. Use this for code that
necessarily contains the pattern: a rule definition, a test, a doc example. The reason is echoed
in every report.

**Directory-level**

Some credentials are irreducible: a SPIRE server's own upstream CA, a third-party API that issues
nothing but static keys, a bootstrap path. Drop a `.identity-exception` file in that directory
whose first line is the reason. The directory is skipped and **the exemption is reported on every
run** — a policy with no legitimate way to say "this one, for this reason" gets bypassed
wholesale, which is exactly how `.gitleaksignore` became a way to silence real findings.

## Install

```sh
npm install
```

```json
{"command": "node", "args": ["/absolute/path/to/identity-guard-mcp/index.mjs"]}
```

`SCAN_ROOT` (default: the server's cwd) bounds every scan.

## Honest limitations

- **Static analysis cannot tell whether the code uses the identity it was given.** A pod can mount
  an SVID and still authenticate with a password read from somewhere else. That gap needs a
  reviewer or an integration test.
- **Rules are literal, not semantic.** Call-site patterns for known connectors, in the same
  deliberately-narrow style as terraform-guard's source scan. A novel wrapper around a password
  login will pass.
- **This is the software half.** What actually makes passwords impossible is the platform: SPIRE
  issuing SVIDs, mTLS `STRICT` with authorization keyed on SPIFFE IDs, databases with password
  auth disabled at the server, and an SCP denying `iam:CreateAccessKey`. A scanner that finds no
  password is weaker than a database that accepts none.
