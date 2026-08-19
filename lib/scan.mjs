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

// A blank or comment-only file is not an exception. This used to end with
// `reason || "declared an exception (no reason given)"`, which turned a zero-byte file into a
// valid exemption -- and emptying the file is exactly what a model reaches for when it has been
// told to remove one and has no delete tool. A real run did both halves: it first wrote a file
// whose every line was a `#` comment (read as a reason, exempting everything), then emptied it to
// comply with a review (still exempting everything, while the validator reported PASS). An
// exception has to say in writing what it is for, or it does not exist.
export function exceptionFor(dir) {
  const file = path.join(dir, EXCEPTION_FILE);
  if (!existsSync(file)) return null;
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    return null;
  }
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    return trimmed;
  }
  return null;
}

const CODE_EXT = new Set([".py", ".js", ".mjs", ".cjs", ".ts", ".go", ".rb", ".java"]);
const YAML_EXT = new Set([".yaml", ".yml"]);

// `root` is threaded through so the scan root can be told apart from everything below it. An
// exception at the root exempts the whole project, which is not what this mechanism is for: it
// exists to say "this one directory, for this reason". A real run wrote one at the root after a
// commit was blocked and every rule stopped running everywhere at once. Refused at the root and
// nowhere else, so the escape hatch stays available exactly where its blast radius matches its
// stated reason. Refusals are recorded rather than dropped -- someone who put a file there needs
// to learn it did nothing, not wonder why the findings came back.
function walk(dir, acc = { code: [], yaml: [], docker: [], exempt: [], refused: [] }, root = dir) {
  const reason = exceptionFor(dir);
  if (reason && dir === root) {
    acc.refused.push({ dir, reason });
  } else if (reason) {
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
      walk(full, acc, root);
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
    // Reported for the same reason exemptions are, and for one more: a refusal is the only way
    // the author of a root-level exception file finds out why it had no effect.
    // Not `rel()`: that helper falls back to basename for an empty relative path, which would
    // print the scan root's directory name and read like a subdirectory. This one is always root.
    refusedExemptions: found.refused.map((e) => ({ path: path.relative(root, e.dir) || ".", reason: e.reason })),
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
