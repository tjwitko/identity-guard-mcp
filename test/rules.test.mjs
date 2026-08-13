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
