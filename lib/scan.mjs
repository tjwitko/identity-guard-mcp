import { readFileSync, readdirSync, existsSync } from "fs";
import path from "path";
import { parseAllDocuments } from "yaml";

import { scanCode, scanDockerfile } from "../rules/code.mjs";
import { scanKubernetes, indexServiceAccounts } from "../rules/kubernetes.mjs";

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".terraform", ".venv", "venv", "__pycache__", "dist", "build", ".next",
]);

// Same shape as terraform-guard's .tfguard-fixture, and shipped at the same time as the rules
// rather than added later under pressure. Some credentials are irreducible — a SPIRE server's own
// upstream CA, a third-party API that issues nothing but static keys, a bootstrap path. A policy
// with no legitimate way to say "this one, for this reason" gets bypassed wholesale, which is how
// .gitleaksignore became a way to silence real findings.
export const EXCEPTION_FILE = ".identity-exception";

export function exceptionFor(dir) {
  const file = path.join(dir, EXCEPTION_FILE);
  if (!existsSync(file)) return null;
  try {
    const reason = readFileSync(file, "utf8").trim().split("\n")[0];
    return reason || "declared an exception (no reason given)";
  } catch {
    return null;
  }
}

const CODE_EXT = new Set([".py", ".js", ".mjs", ".cjs", ".ts", ".go", ".rb", ".java"]);
const YAML_EXT = new Set([".yaml", ".yml"]);

function walk(dir, acc = { code: [], yaml: [], docker: [], exempt: [] }) {
  const reason = exceptionFor(dir);
  if (reason) {
    acc.exempt.push({ dir, reason });
    return acc;
  }
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      walk(full, acc);
    } else if (e.name === "Dockerfile" || e.name.startsWith("Dockerfile.")) {
      acc.docker.push(full);
    } else if (YAML_EXT.has(path.extname(e.name))) {
      acc.yaml.push(full);
    } else if (CODE_EXT.has(path.extname(e.name))) {
      acc.code.push(full);
    }
  }
  return acc;
}

function read(file) {
  try {
    return readFileSync(file, "utf8");
  } catch {
    return null;
  }
}

export function scanProject(root) {
  const found = walk(root);
  const rel = (f) => path.relative(root, f) || path.basename(f);
  const findings = [];

  // Two passes over the manifests: ServiceAccounts are indexed across the whole tree first,
  // because a Deployment and the ServiceAccount it names are routinely in different files and a
  // per-file check would report every correctly-bound workload as unbound.
  const parsed = [];
  const serviceAccounts = new Map();
  for (const file of found.yaml) {
    const text = read(file);
    if (text === null) continue;
    let docs;
    try {
      docs = parseAllDocuments(text).map((d) => d.toJS({ maxAliasCount: 100 }));
    } catch {
      continue; // not parseable as YAML — not this tool's problem to report
    }
    parsed.push({ file, docs });
    indexServiceAccounts(docs, serviceAccounts);
  }
  for (const { file, docs } of parsed) {
    findings.push(...scanKubernetes(docs, serviceAccounts, rel(file)));
  }

  const allowances = [];
  for (const file of found.code) {
    const text = read(file);
    if (text !== null) findings.push(...scanCode(text, rel(file), allowances));
  }
  for (const file of found.docker) {
    const text = read(file);
    if (text !== null) findings.push(...scanDockerfile(text, rel(file), allowances));
  }

  const blocking = findings.filter((f) => !f.heuristic);
  const advisory = findings.filter((f) => f.heuristic);

  return {
    root,
    clean: blocking.length === 0,
    counts: {
      blocking: blocking.length,
      advisory: advisory.length,
      filesScanned: found.code.length + found.yaml.length + found.docker.length,
    },
    // Exemptions are reported, never silent. A directory that opted out is a fact the reader
    // needs; an exception nobody can see is indistinguishable from a check that did not run.
    exemptions: found.exempt.map((e) => ({ path: rel(e.dir), reason: e.reason })),
    // Line-level opt-outs, reported for the same reason directory exemptions are: an allowance
    // nobody can see is indistinguishable from a rule that never fired.
    allowances,
    findings: [...blocking, ...advisory],
  };
}

export const REMEDIATION_HEADER =
  "This project requires workload identity: services authenticate by proving who they are, not " +
  "by presenting something they hold. Passwords, static cloud keys and shared tokens are not " +
  "acceptable regardless of where they are stored — a password fetched from a secret manager is " +
  "still a password. Use an issued identity: a SPIFFE SVID via the Workload API, or a federated " +
  "cloud identity (IRSA, EKS Pod Identity, GKE or Azure Workload Identity).";
