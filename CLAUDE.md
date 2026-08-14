# CLAUDE.md

An MCP server exposing `check_auth_posture`: enforces that workloads authenticate with an issued
identity (SPIFFE SVID, IRSA, EKS Pod Identity, GKE/Azure Workload Identity) rather than with
credentials they hold. Fourth server in the same family as `dep-audit-mcp`, `terraform-guard-mcp`
and `secret-guard-mcp`.

## Architecture

Calling model → `check_auth_posture` → `lib/scan.mjs` walks the tree → `rules/code.mjs` (text
patterns), `rules/kubernetes.mjs` (parsed YAML) → findings split into blocking and advisory.
No external binary; `yaml` is the only non-MCP dependency.

## Key files

- `lib/scan.mjs` — the walker, the two-pass manifest handling, `.identity-exception`
- `rules/kubernetes.mjs` — the positive half; the interesting logic
- `rules/code.mjs` — the anti-pattern half
- `rules/taxonomy.mjs` — categories, and the verified annotation/CSI-driver lists
- `test/rules.test.mjs` — 23 tests

## Things to know

- **The positive half is the hard half, and it is why this is not part of secret-guard.**
  secret-guard matches values; this asserts the presence of wiring. A file with no credentials in
  it can still fail, and no amount of pattern matching finds that.
- **`identity.unbound` must never block.** EKS Pod Identity binds a role to a ServiceAccount
  through the AWS API, leaving nothing in the manifest — so "no annotation here" is genuinely not
  proof of misconfiguration, and blocking on it would fail correct deployments. It is the only
  `heuristic: true` rule, the same treatment secret-guard gives entropy hits. There is a test
  asserting the flag; don't "tighten" it.
- **ServiceAccounts are indexed across the whole scan before workloads are evaluated.** A
  Deployment and the ServiceAccount it names are routinely in different files; a per-file check
  reported every correctly-bound workload as unbound. Found by writing the cross-file test.
- **Manifests are parsed with a real YAML parser, not regex.** Multi-document, deeply nested,
  whitespace-significant — a verdict derived from line matching would be wrong often enough to be
  worse than nothing. Same reasoning that keeps terraform-guard on `terraform show -json`.
- **A password in a connection string is flagged even when it is obviously a placeholder**, and
  that is the sharpest illustration of how this server differs from secret-guard. secret-guard
  asks "is this a leaked secret?" and correctly allowlists `user:password@` — nothing leaked.
  This asks "is this password authentication?" and the answer is yes regardless of whether the
  value is real, interpolated or a stand-in. Found by running the scanner over six real generated
  projects: one had `postgresql://user:password@db_host:5432/auditdb` as a default in application
  code and it fell through BOTH scanners.
- **`password=` is flagged even when the value comes from an environment variable or a secret
  manager.** That is the policy, not an oversight: sourcing a password well changes where it is
  stored, not what it is. Expect to explain this; it is the rule people push back on.
- **`ARG NPM_TOKEN` with no default was missed by the first Dockerfile regex** — nothing follows
  the name to match on, and that is the *usual* way to pass a build secret via `--build-arg`.
  Also `ENV A=1 B=2` declares two variables in one instruction. Both are why the Dockerfile scan
  is line-based rather than one pattern.
- **Two escape hatches, and the line-level one is the important one.** `identity-guard:allow
  <reason>` on the line handles the self-referential cases — a rule file necessarily contains the
  patterns it detects, a test necessarily contains the thing under test. Excusing whole
  directories for that would also hide genuine violations sitting next to them; this repo needed
  the line form to pass its own gate. Both are reported on every run.
- **`.identity-exception` shipped with the rules, not after.** A control with no legitimate escape
  hatch gets bypassed wholesale — the `.gitleaksignore` lesson. Exemptions are reported on every
  run so an opt-out is never silent.
- **The Terraform half lives in terraform-guard**, where the plan engine already is:
  `aws.iam.access-key-created` and `aws.iam.user-as-service-identity`. Those two are a different
  shape from every other rule there — they refuse a resource *type* rather than checking
  attributes, because a resource whose purpose is minting a permanent credential has no secure
  configuration.
- **Not covered:** whether the code actually *uses* the identity it was handed. A pod can mount an
  SVID and still log in with a password. That is a reviewer or integration-test question.
