import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { parseAllDocuments } from "yaml";

import { resolveScanPath } from "../lib/paths.mjs";
import { scanCode, scanDockerfile } from "../rules/code.mjs";
import { scanKubernetes, indexServiceAccounts } from "../rules/kubernetes.mjs";
import { scanProject, EXCEPTION_FILE } from "../lib/scan.mjs";

const ids = (f) => f.map((x) => x.ruleId).sort();
const parse = (y) => parseAllDocuments(y).map((d) => d.toJS());

function k8s(yaml) {
  const docs = parse(yaml);
  return scanKubernetes(docs, indexServiceAccounts(docs), "m.yaml");
}

function withDir(files) {
  const dir = mkdtempSync(path.join(tmpdir(), "identity-guard-"));
  for (const [rel, contents] of Object.entries(files)) {
    const full = path.join(dir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, contents);
  }
  return dir;
}

// ---------------------------------------------------------------------------
// Code: authenticating with something you hold
// ---------------------------------------------------------------------------

test("flags an AWS SDK given static key material, once per call site", () => {
  const f = scanCode(`s3 = boto3.client("s3", aws_access_key_id="A", aws_secret_access_key="B")`, "a.py"); // identity-guard:allow test material
  assert.deepEqual(ids(f), ["auth.static-cloud-key"]);
});

// The policy is about what the credential IS, not where it is kept. A password read from a
// secret manager is still a password, so sourcing it well must not silence the rule.
test("flags a database password even when it comes from the environment", () => {
  const f = scanCode(`conn = psycopg2.connect(host="db", password=os.environ["DB_PASS"])`, "a.py"); // identity-guard:allow test material
  assert.deepEqual(ids(f), ["auth.password-connect"]);
});

test("flags HTTP Basic authentication", () => {
  assert.deepEqual(ids(scanCode(`requests.get(u, auth=("svc", "pw"))`, "a.py")), ["auth.basic"]); // identity-guard:allow test material
  assert.deepEqual(ids(scanCode(`headers = {"Authorization": "Basic abc"}`, "a.js")), ["auth.basic"]); // identity-guard:allow test material
});

// `password` appearing in an unrelated structure is not an authentication call, and a scanner
// that cries wolf on ordinary code is one people switch off.
test("does not flag a password field far from any connection call", () => {
  assert.deepEqual(scanCode(`FORM_FIELDS = {"password": "the label shown to users"}`, "a.py"), []); // identity-guard:allow test material
});

test("ignores commented-out code", () => {
  assert.deepEqual(scanCode(`# conn = psycopg2.connect(password="x")\n`, "a.py"), []); // identity-guard:allow test material
  assert.deepEqual(scanCode(`"""example: boto3.client(aws_access_key_id="X")"""\n`, "a.py"), []);
});

test("clean code that relies on the credential chain passes", () => {
  assert.deepEqual(scanCode(`s3 = boto3.client("s3")\nconn = connect_with_iam_token()`, "a.py"), []);
});

test("flags credential material baked into an image", () => {
  const f = scanDockerfile("FROM x\nENV DB_PASSWORD=hunter2\nARG NPM_TOKEN\nENV PORT=8000\n", "Dockerfile");
  assert.deepEqual(ids(f), ["auth.dockerfile-credential", "auth.dockerfile-credential"]);
  assert.equal(f.find((x) => x.line === 2).severity, "critical"); // ENV persists into the image
  assert.equal(f.find((x) => x.line === 3).severity, "high");     // ARG only into the build cache
});

// ---------------------------------------------------------------------------
// Kubernetes: does the workload have an identity at all?
// ---------------------------------------------------------------------------

test("flags a workload running as the default ServiceAccount", () => {
  const f = k8s(`
apiVersion: apps/v1
kind: Deployment
metadata: { name: legacy }
spec:
  template:
    spec:
      containers: [{ name: app, image: x }]
`);
  assert.deepEqual(ids(f), ["identity.default-sa"]);
  assert.equal(f[0].heuristic, false);
});

test("accepts a ServiceAccount bound by an IRSA annotation", () => {
  assert.deepEqual(k8s(`
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  annotations: { eks.amazonaws.com/role-arn: "arn:aws:iam::1:role/app" }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: app }
spec:
  template:
    spec:
      serviceAccountName: app-sa
      containers: [{ name: app, image: x }]
`), []);
});

// Both shipping SPIFFE CSI drivers, verified against their repos rather than recalled.
for (const driver of ["csi.spiffe.io", "spiffe.csi.cert-manager.io"]) {
  test(`accepts an SVID mounted via ${driver}`, () => {
    assert.deepEqual(k8s(`
apiVersion: apps/v1
kind: Deployment
metadata: { name: app }
spec:
  template:
    spec:
      serviceAccountName: app-sa
      containers: [{ name: app, image: x }]
      volumes:
        - name: svid
          csi: { driver: ${driver}, readOnly: true }
`), []);
  });
}

// EKS Pod Identity associates a role to a ServiceAccount through the AWS API and leaves nothing
// in the manifest. Blocking on "no annotation" would fail a correct Pod Identity deployment, so
// this must report without blocking.
test("an unbound ServiceAccount is advisory, not blocking", () => {
  const f = k8s(`
apiVersion: apps/v1
kind: Deployment
metadata: { name: app }
spec:
  template:
    spec:
      serviceAccountName: app-sa
      containers: [{ name: app, image: x }]
`);
  assert.deepEqual(ids(f), ["identity.unbound"]);
  assert.equal(f[0].heuristic, true, "must not block: Pod Identity binds outside the manifest");
});

// A Deployment and the ServiceAccount it names are routinely in different files. A per-file check
// would report every correctly-bound workload in the codebase as unbound.
test("resolves a ServiceAccount defined in a different file", () => {
  const dir = withDir({
    "k8s/sa.yaml": `apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  annotations: { iam.gke.io/gcp-service-account: app@p.iam.gserviceaccount.com }
`,
    "k8s/deploy.yaml": `apiVersion: apps/v1
kind: Deployment
metadata: { name: app }
spec:
  template:
    spec:
      serviceAccountName: app-sa
      containers: [{ name: app, image: x }]
`,
  });
  try {
    assert.deepEqual(scanProject(dir).findings, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("flags Secrets used as authentication material", () => {
  const f = k8s(`
apiVersion: v1
kind: Secret
metadata: { name: db }
stringData: { password: hunter2 }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: app }
spec:
  template:
    spec:
      serviceAccountName: app-sa
      containers:
        - name: app
          image: x
          env:
            - name: DB_PASS
              valueFrom: { secretKeyRef: { name: db, key: password } }
          envFrom:
            - secretRef: { name: db }
      volumes:
        - name: svid
          csi: { driver: csi.spiffe.io }
`);
  assert.equal(f.filter((x) => x.ruleId === "identity.secret-as-auth").length, 3);
});

// A Secret holding non-credential configuration is not what this policy is about.
test("does not flag a Secret carrying non-credential config", () => {
  assert.deepEqual(k8s(`
apiVersion: v1
kind: Secret
metadata: { name: tuning }
stringData: { max_connections: "50" }
`), []);
});

// ---------------------------------------------------------------------------
// Exceptions and containment
// ---------------------------------------------------------------------------

// Some credentials are irreducible — a SPIRE upstream CA, a third-party API that issues nothing
// but static keys. A policy with no legitimate way to say "this one, for this reason" gets
// bypassed wholesale, which is exactly how .gitleaksignore became a way to silence real findings.
test("an exception file exempts a directory and is reported, never silent", () => {
  const dir = withDir({
    "vendor-api/client.py": `requests.get(u, auth=("svc", "key"))`, // identity-guard:allow test material
    [`vendor-api/${EXCEPTION_FILE}`]: "Vendor issues static API keys only; rotated quarterly, ticket SEC-441.\n",
    "app/main.py": `s3 = boto3.client("s3")`,
  });
  try {
    const r = scanProject(dir);
    assert.deepEqual(r.findings, []);
    assert.equal(r.exemptions.length, 1);
    assert.match(r.exemptions[0].reason, /Vendor issues static API keys/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The three tests below all come from one agent run. Blocked from committing, the model wrote an
// exception file; told in review to delete it, it emptied the file instead, because it had no
// delete tool. Both moves exempted the entire project, and the validator reported PASS on a tree
// that still failed the check.
test("an exception file with no stated reason does not exempt anything", () => {
  for (const contents of ["", "\n\n", "# Identity exceptions\n# identity.default-sa\n"]) {
    const dir = withDir({
      "vendor-api/client.py": `requests.get(u, auth=("svc", "key"))`, // identity-guard:allow test material
      [`vendor-api/${EXCEPTION_FILE}`]: contents,
    });
    try {
      const r = scanProject(dir);
      assert.deepEqual(r.exemptions, [], `exempted on ${JSON.stringify(contents)}`);
      assert.ok(r.findings.length > 0, `findings suppressed on ${JSON.stringify(contents)}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("a comment line above a real reason still exempts", () => {
  const dir = withDir({
    "vendor-api/client.py": `requests.get(u, auth=("svc", "key"))`, // identity-guard:allow test material
    [`vendor-api/${EXCEPTION_FILE}`]: "# reviewed 2026-08-19\nVendor issues static keys only, ticket SEC-441.\n",
  });
  try {
    const r = scanProject(dir);
    assert.equal(r.exemptions.length, 1);
    assert.match(r.exemptions[0].reason, /ticket SEC-441/);
    assert.deepEqual(r.findings, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// An exception is scoped to one directory for a stated reason. At the root that scope is the whole
// project, which is not a narrower claim than "turn the check off" -- it is the same claim.
test("an exception at the scan root is refused, reported, and exempts nothing", () => {
  const dir = withDir({
    "app/main.py": `requests.get(u, auth=("svc", "key"))`, // identity-guard:allow test material
    [EXCEPTION_FILE]: "Whole project is a bootstrap path.\n",
  });
  try {
    const r = scanProject(dir);
    assert.deepEqual(r.exemptions, []);
    assert.equal(r.refusedExemptions.length, 1);
    assert.match(r.refusedExemptions[0].reason, /bootstrap path/);
    assert.ok(r.findings.length > 0);
    assert.equal(r.clean, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// local-delegate-mcp's agent loop hardcodes this basename in GUARD_CONFIG_FILES to stop a model
// writing its own exemption, and local-copilot-stack's validate.mjs hardcodes it again in the
// suppression list. Neither can import it without taking a load-order risk on an optional sibling
// repo, so this test is the thing that catches a rename. Change all three together.
test("the exception filename is pinned — two sibling repos hardcode it", () => {
  assert.equal(EXCEPTION_FILE, ".identity-exception");
});

test("refuses to scan outside the scan root", () => {
  assert.throws(() => resolveScanPath("../../../.aws", "/srv/project"), /refuses to scan outside/);
  assert.throws(() => resolveScanPath("/srv/project-other/x", "/srv/project"), /refuses to scan outside/);
  assert.equal(resolveScanPath("k8s", "/srv/project"), "/srv/project/k8s");
});

test("unparseable YAML is skipped rather than reported as a violation", () => {
  const dir = withDir({ "broken.yaml": "a: [1,\n  b: :::\n" });
  try {
    assert.equal(scanProject(dir).clean, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("clean and violating fixtures behave as documented", () => {
  const here = path.dirname(new URL(import.meta.url).pathname);
  const clean = scanProject(path.join(here, "..", "fixtures", "compliant"));
  assert.equal(clean.clean, true);
  assert.equal(clean.findings.length, 0);

  const bad = scanProject(path.join(here, "..", "fixtures", "violating"));
  assert.equal(bad.clean, false);
  assert.ok(bad.counts.blocking >= 6, `expected several blocking findings, got ${bad.counts.blocking}`);
});

// Reading these keys out of an assume-role response is how short-lived credentials reach a
// subprocess — the compliant pattern, and textually identical to passing static ones in. Found
// against terraform-guard's own STS module, which this rule flagged four times while being the
// most compliant file in that repo.
test("does not flag credentials plumbed out of an STS assume-role response", () => {
  assert.deepEqual(scanCode(`
const { Credentials } = await sts.send(new AssumeRoleCommand(input));
return { accessKeyId: Credentials.AccessKeyId, secretAccessKey: Credentials.SecretAccessKey };
`, "creds.mjs"), []);
});

test("still flags static keys handed to an SDK", () => {
  assert.deepEqual(
    ids(scanCode(`const s3 = new S3({ accessKeyId: "AKIA...", secretAccessKey: "..." });`, "a.js")), // identity-guard:allow test material
    ["auth.static-cloud-key"]
  );
});

// The rule that six real projects were needed to find. secret-guard allowlists `user:password@`
// as a placeholder — correctly, since nothing leaked — so a DSN written into application code
// fell through both scanners. The questions differ: "is this a leaked secret" versus "is this
// password authentication". A placeholder answers no to the first and yes to the second.
//
// Two of these carry an inline `gitleaks:allow` rather than a .gitleaksignore fingerprint. They
// must look like real passwords -- the test exists to prove the rule fires on real ones and not
// only on placeholders -- but fingerprints pin a line number, so inserting a test anywhere above
// silently unpins them and the next commit fails on unchanged material. That happened. Inline
// also puts the exemption where a reviewer reads the material it covers. All four carry it, not
// just the two gitleaks happens to flag today -- uniform treatment of identical test material
// beats an exemption list shaped by which patterns one scanner version matched.
test("flags a password in a connection string, placeholder or not", () => {
  for (const dsn of [
    'postgresql://user:password@db_host:5432/auditdb', // identity-guard:allow test material; gitleaks:allow
    'postgresql://admin:REALpw123@db.internal/app', // identity-guard:allow test material; gitleaks:allow
    'redis://:${REDIS_PASSWORD}@cache:6379', // identity-guard:allow test material; gitleaks:allow
    'https://svc:token@api.internal/v1', // identity-guard:allow test material; gitleaks:allow
  ]) {
    assert.deepEqual(
      ids(scanCode(`DATABASE_URL = "${dsn}"`, "a.py")),
      ["auth.connection-string-password"],
      dsn
    );
  }
});

test("does not flag connection strings with no password component", () => {
  for (const dsn of ["sqlite:///./audit.db", "postgresql://user@host/db", "https://api.internal/v1"]) {
    assert.deepEqual(scanCode(`URL = "${dsn}"`, "a.py"), [], dsn);
  }
});

// A connection string is credential material even though its key is named "url". Found in a real
// generated project: DATABASE_URL taken from a Secret via secretKeyRef with key "url", carrying a
// postgresql:// DSN with the password inside it. The key-name check did not match, so a password
// reached the pod through a path this rule inspects but did not recognise.
test("flags a connection-string Secret key, not just a credential-named one", () => {
  for (const key of ["url", "uri", "dsn", "connection_string", "DATABASE_URL"]) {
    const f = k8s(`
apiVersion: apps/v1
kind: Deployment
metadata: { name: app }
spec:
  template:
    spec:
      serviceAccountName: app-sa
      containers:
        - name: app
          image: x
          env:
            - name: DATABASE_URL
              valueFrom: { secretKeyRef: { name: db, key: ${key} } }
      volumes:
        - name: svid
          csi: { driver: csi.spiffe.io }
`).filter((x) => x.ruleId === "identity.secret-as-auth");
    assert.equal(f.length, 1, `key "${key}" should be treated as credential material`);
  }
});

// `host` and `port` name an address, not a credential, and flagging them would be the noise that
// gets a scanner switched off.
test("does not flag Secret keys that name an address rather than a credential", () => {
  for (const key of ["host", "port", "ca_cert", "region"]) {
    const f = k8s(`
apiVersion: apps/v1
kind: Deployment
metadata: { name: app }
spec:
  template:
    spec:
      serviceAccountName: app-sa
      containers:
        - name: app
          image: x
          env:
            - name: CFG
              valueFrom: { secretKeyRef: { name: db, key: ${key} } }
      volumes:
        - name: svid
          csi: { driver: csi.spiffe.io }
`).filter((x) => x.ruleId === "identity.secret-as-auth");
    assert.equal(f.length, 0, `key "${key}" should not be treated as credential material`);
  }
});

test("a Secret whose own key is a connection string is authentication material", () => {
  const f = k8s(`
apiVersion: v1
kind: Secret
metadata: { name: db }
stringData: { url: "postgresql://user:pw@host/db" } # identity-guard:allow test material
`);
  assert.equal(f.filter((x) => x.ruleId === "identity.secret-as-auth").length, 1);
});
