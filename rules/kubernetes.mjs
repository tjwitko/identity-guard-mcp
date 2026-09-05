import { IDENTITY_ANNOTATIONS, SPIFFE_CSI_DRIVERS, SPIFFE_SOCKET_HINTS } from "./taxonomy.mjs";

// The positive half of the policy: does this workload have an identity to authenticate WITH?
//
// Parsed with a real YAML parser rather than regex. Manifests are multi-document, deeply nested
// and whitespace-significant; a security verdict derived from line matching would be wrong often
// enough to be worse than nothing. This is the same reasoning that keeps terraform-guard on
// `terraform show -json` instead of reading HCL.

const WORKLOAD_KINDS = new Set([
  "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet", "ReplicationController",
]);

// Where the pod spec lives differs by kind, and CronJob buries it two templates deep.
function podSpecOf(doc) {
  if (!doc || typeof doc !== "object") return null;
  if (doc.kind === "Pod") return doc.spec || null;
  if (doc.kind === "CronJob") return doc.spec?.jobTemplate?.spec?.template?.spec || null;
  return doc.spec?.template?.spec || null;
}

// A connection string is credential material even though its name says "url". Found in a real
// generated project: DATABASE_URL pulled from a Secret via secretKeyRef with key "url", carrying
// postgresql://user:PASSWORD@host/db. The key-name check below did not match, so a password
// arrived in the pod through a path this rule inspects but did not recognise — the same defect
// the connection-string rule in rules/code.mjs exists for, reaching the workload by a different
// route. `endpoint`/`host` are deliberately absent: those routinely name a bare address with no
// credential in it, and flagging them would be the noise that gets a scanner switched off.
const CONNECTION_STRING_KEY = /(^|[_-])(url|uri|dsn|conn(ection)?([_-]?string)?)$/i;

const CREDENTIAL_KEY = /(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|credential)/i;

function isCredentialKey(key) {
  return typeof key === "string" && (CREDENTIAL_KEY.test(key) || CONNECTION_STRING_KEY.test(key));
}

function hasSpiffeVolume(podSpec) {
  for (const v of podSpec.volumes || []) {
    if (v?.csi?.driver && SPIFFE_CSI_DRIVERS.includes(v.csi.driver)) return true;
    const hostPath = v?.hostPath?.path || "";
    if (SPIFFE_SOCKET_HINTS.some((h) => hostPath.includes(h))) return true;
  }
  const serialized = JSON.stringify(podSpec);
  return SPIFFE_SOCKET_HINTS.some((h) => serialized.includes(h));
}

// A Helm template's `name: {{ include "app.fullname" . }}` parses into an object, not a string, and
// interpolating it produced findings reading `Deployment/[object Object]` that named no workload
// anyone could look up. Say what it is instead: the finding is still real, the name is just not
// knowable before the chart is rendered.
function readableName(value) {
  if (typeof value === "string" && value.trim() !== "") return value;
  if (value == null) return "(unnamed)";
  return "(templated name)";
}

function containersOf(podSpec) {
  // Neither list is guaranteed to be a list. A Helm chart parses as YAML but is not Kubernetes:
  // `containers: {{ toYaml .Values.containers }}` yields a scalar, and spreading it threw a
  // TypeError that aborted the whole scan — taking the repository's pre-commit validation down with
  // it, since this is what `workload identity` calls. Nothing here may assume a shape.
  const list = (v) => (Array.isArray(v) ? v.filter((c) => c && typeof c === "object") : []);
  return [...list(podSpec.containers), ...list(podSpec.initContainers)];
}

// An opt-out, scoped to a rule and a file. Line-scoped would be wrong here: these findings are
// about a resource assembled from many lines, and the parsed documents carry no line numbers at
// all. The rule id must be named, so an allowance is a statement about one thing rather than a
// blanket over the manifest.
//
//   # identity-guard:allow identity.secret-as-auth  inbound HMAC from the payment provider
//
// A reason is required, for the reason the directory-level exception already requires one: a run
// once wrote an exception file of nothing but comments, then emptied it to satisfy a review, and
// the validator reported PASS both times. A marker with no reason is REFUSED and reported as
// refused -- silence is what this design exists to prevent.
// [ \t]*, not \s*: \s crosses newlines, so a marker with no reason swallowed the line break and
// captured the NEXT line as its justification -- "# identity-guard:allow identity.secret-as-auth"
// followed by "env:" was honoured as an allowance whose stated reason was "env:". An opt-out that
// invents its own reason from the following line is worse than one that fails open, because it
// reads as deliberate in the report. Same shape as a proximity window crossing a clause boundary.
const K8S_ALLOW = /#[ \t]*identity-guard:allow[ \t]+([\w.-]+)[ \t]*(.*)$/gm;

export function kubernetesAllowances(source = "") {
  const allowed = new Map();
  const refused = [];
  K8S_ALLOW.lastIndex = 0;
  let m;
  while ((m = K8S_ALLOW.exec(source))) {
    const reason = (m[2] || "").trim();
    if (!reason) refused.push({ ruleId: m[1], reason: "no reason given" });
    else allowed.set(m[1], reason);
  }
  return { allowed, refused };
}

export function scanKubernetes(docs, serviceAccounts, file, source = "", collected = null) {
  const findings = [];
  const { allowed, refused } = kubernetesAllowances(source);
  for (const r of refused) {
    collected?.refused.push({ ...r, file });
  }
  const add = (f) => {
    if (allowed.has(f.ruleId)) {
      collected?.allowances.push({ ruleId: f.ruleId, file, reason: allowed.get(f.ruleId) });
      return;
    }
    findings.push({ file, heuristic: false, ...f });
  };

  for (const doc of docs) {
    if (!doc || typeof doc !== "object") continue;

    // A Secret whose keys are credential material is the thing the policy exists to remove.
    if (doc.kind === "Secret") {
      const keys = [...Object.keys(doc.data || {}), ...Object.keys(doc.stringData || {})];
      const credKeys = keys.filter((k) => isCredentialKey(k));
      if (credKeys.length) {
        add({
          ruleId: "identity.secret-as-auth",
          category: "identity.secret-as-auth",
          severity: "high",
          name: readableName(doc.metadata?.name),
          message: `Secret "${readableName(doc.metadata?.name)}" carries authentication material (${credKeys.join(", ")})`,
          remediation:
            "a Secret is a distribution mechanism for a shared credential, which is what workload " +
            "identity replaces. Bind the ServiceAccount to a cloud identity (IRSA / GKE / Azure " +
            "Workload Identity) or issue an SVID, and authenticate with that instead.",
        });
      }
    }

    if (!WORKLOAD_KINDS.has(doc.kind)) continue;
    const podSpec = podSpecOf(doc);
    if (!podSpec) continue;

    const workload = `${doc.kind}/${readableName(doc.metadata?.name)}`;
    const sa = podSpec.serviceAccountName || podSpec.serviceAccount;

    if (!sa || sa === "default") {
      add({
        ruleId: "identity.default-sa",
        category: "identity.default-sa",
        severity: "critical",
        name: workload,
        message: `${workload} runs as the default ServiceAccount, so it has no identity of its own`,
        remediation:
          "give it a dedicated ServiceAccount and bind that to an identity — an IRSA/GKE/Azure " +
          "annotation, an EKS Pod Identity association, or a SPIFFE SVID via the CSI driver.",
      });
    } else {
      const spiffe = hasSpiffeVolume(podSpec);
      const annotations = serviceAccounts.get(sa) || null;
      const bound = annotations && IDENTITY_ANNOTATIONS.some((a) => a in annotations);

      if (!spiffe && !bound) {
        add({
          ruleId: "identity.unbound",
          category: "identity.unbound",
          severity: "medium",
          // EKS Pod Identity associates a role to a ServiceAccount through the AWS API, leaving
          // no trace in the manifest. So "no evidence here" genuinely is not proof, and this must
          // not block or it fails correct Pod Identity setups.
          heuristic: true,
          name: workload,
          message:
            `${workload} uses ServiceAccount "${readableName(sa)}", but nothing in these manifests binds it to ` +
            `an identity (no IRSA/GKE/Azure annotation, no SPIFFE volume)`,
          remediation:
            "annotate the ServiceAccount, mount an SVID via the SPIFFE CSI driver, or — if this " +
            "is EKS Pod Identity, which binds outside the manifest — record that so the check " +
            "can be satisfied deliberately rather than by silence.",
        });
      }
    }

    // Credential-shaped Secret references reaching the container as environment.
    for (const c of containersOf(podSpec)) {
      for (const ef of c.envFrom || []) {
        if (ef?.secretRef?.name) {
          add({
            ruleId: "identity.secret-as-auth",
            category: "identity.secret-as-auth",
            severity: "high",
            name: `${workload}/${c.name || "?"}`,
            message: `container "${c.name || "?"}" loads every key of Secret "${ef.secretRef.name}" as environment`,
            remediation:
              "envFrom pulls whatever the Secret holds, so its contents are invisible here and " +
              "grow silently. Authenticate with the workload's identity instead of injecting " +
              "shared material.",
          });
        }
      }
      for (const e of Array.isArray(c.env) ? c.env : []) {
        const key = e?.valueFrom?.secretKeyRef?.key;
        if (isCredentialKey(key)) {
          add({
            ruleId: "identity.secret-as-auth",
            category: "identity.secret-as-auth",
            severity: "high",
            name: `${workload}/${c.name || "?"}`,
            message: `container "${c.name || "?"}" takes ${e.name} from Secret key "${key}"`,
            remediation:
              "this is a shared credential handed to the workload. Replace it with an identity " +
              "the workload proves — IAM database auth, or mTLS with an SVID.",
          });
        }
      }
    }
  }

  return findings;
}

// Built across every manifest in the scan before workloads are evaluated, because a Deployment
// and the ServiceAccount it names are routinely in different files.
export function indexServiceAccounts(docs, into = new Map()) {
  for (const doc of docs) {
    if (doc?.kind === "ServiceAccount" && doc.metadata?.name) {
      into.set(doc.metadata.name, doc.metadata.annotations || {});
    }
  }
  return into;
}
