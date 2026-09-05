import test from "node:test";
import assert from "node:assert/strict";
import { parseAllDocuments } from "yaml";

import { scanKubernetes } from "../rules/kubernetes.mjs";

// --- rule-scoped allowances in manifests ----------------------------------
// identity.secret-as-auth blocked two deliverables for holding an HMAC signing secret that the
// task itself requires — "the provider rotates its signing secret every quarter". The rule is right
// in general and cannot tell an inbound signature secret from an outbound cloud credential, so a
// manifest needs a way to say "this one, for this reason". Directory-level exemption was the only
// mechanism and is far too blunt: it would exempt the whole k8s/ directory, static cloud keys and
// all.
const SECRET_ENV = (allow) => `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-receiver
spec:
  template:
    spec:
      serviceAccountName: webhook-receiver
      containers:
      - name: webhook-receiver
        ${allow}
        env:
        - name: WEBHOOK_SIGNING_SECRET
          valueFrom:
            secretKeyRef:
              name: webhook-secrets
              key: signing-secret
`;

const parse = (yaml) => parseAllDocuments(yaml).map((d) => d.toJS({ maxAliasCount: 100 }));
const ids = (f) => f.map((x) => x.ruleId);

test("an allowance with a reason suppresses that rule in that file", () => {
  const collected = { allowances: [], refused: [] };
  const src = SECRET_ENV("# identity-guard:allow identity.secret-as-auth  inbound HMAC from the provider");
  const findings = scanKubernetes(parse(src), new Map(), "k8s/deployment.yaml", src, collected);
  assert.ok(!ids(findings).includes("identity.secret-as-auth"));
  assert.equal(collected.allowances.length, 1);
  assert.match(collected.allowances[0].reason, /inbound HMAC/);
});

test("an allowance covers only the rule it names", () => {
  const collected = { allowances: [], refused: [] };
  const src = SECRET_ENV("# identity-guard:allow identity.secret-as-auth  inbound HMAC from the provider");
  const findings = scanKubernetes(parse(src), new Map(), "k8s/deployment.yaml", src, collected);
  // The ServiceAccount is still unbound, and that is a different rule.
  assert.ok(ids(findings).includes("identity.unbound"));
});

// A marker with no reason is refused and reported, for the reason the exception file already
// requires one: a run once wrote an exception of nothing but comments, then emptied it to satisfy
// a review, and the validator reported PASS both times.
test("an allowance with no reason is refused, not honoured", () => {
  const collected = { allowances: [], refused: [] };
  const src = SECRET_ENV("# identity-guard:allow identity.secret-as-auth");
  const findings = scanKubernetes(parse(src), new Map(), "k8s/deployment.yaml", src, collected);
  assert.ok(ids(findings).includes("identity.secret-as-auth"), "an unreasoned opt-out must not work");
  assert.equal(collected.allowances.length, 0);
  assert.equal(collected.refused.length, 1);
});

test("no allowance leaves the finding in place", () => {
  const collected = { allowances: [], refused: [] };
  const src = SECRET_ENV("");
  const findings = scanKubernetes(parse(src), new Map(), "k8s/deployment.yaml", src, collected);
  assert.ok(ids(findings).includes("identity.secret-as-auth"));
  assert.equal(collected.allowances.length, 0);
});

test("an allowance does not leak across files", () => {
  const collected = { allowances: [], refused: [] };
  const allowed = SECRET_ENV("# identity-guard:allow identity.secret-as-auth  inbound HMAC");
  const plain = SECRET_ENV("");
  scanKubernetes(parse(allowed), new Map(), "k8s/a.yaml", allowed, collected);
  const second = scanKubernetes(parse(plain), new Map(), "k8s/b.yaml", plain, collected);
  assert.ok(ids(second).includes("identity.secret-as-auth"));
});
