// Source-level anti-patterns: code that authenticates with material it holds.
//
// Deliberately narrow and literal, the same discipline as terraform-guard's source scan. These
// are call-site patterns for known connectors and known auth mechanisms, not an attempt to
// understand the program. A rule that guesses produces findings nobody trusts, and an untrusted
// security check gets switched off.

const STRIP_COMMENTS = [
  [/"""[\s\S]*?"""/g, ""],   // python docstrings
  [/'''[\s\S]*?'''/g, ""],
  [/\/\*[\s\S]*?\*\//g, ""], // block comments
  [/(^|\s)(#|\/\/).*$/gm, "$1"],
];

function strip(source) {
  let s = source;
  for (const [re, to] of STRIP_COMMENTS) s = s.replace(re, to);
  return s;
}

function lineOf(source, index) {
  return source.slice(0, index).split("\n").length;
}

// Line-precise opt-out, in the shape gitleaks already established with `gitleaks:allow`. A
// directory-wide exception is too blunt for the common cases: a rule file necessarily contains
// the patterns it detects, and a test necessarily contains the thing under test. Excusing the
// whole directory would also hide a genuine violation sitting next to them.
//
// The reason is required and is echoed in the report, so an opt-out is a statement someone made
// rather than a silence.
const ALLOW_MARKER = /identity-guard:allow(?:\s+(.*))?$/;

function allowedOnLine(source, line) {
  const text = source.split("\n")[line - 1] || "";
  const m = ALLOW_MARKER.exec(text);
  return m ? { reason: (m[1] || "").trim() || "no reason given" } : null;
}

// Note `password=` is a finding even when the value comes from an environment variable or a
// secret manager. That is not an oversight: the policy is that workloads authenticate with an
// issued identity, and a password read from Vault is still a password. Sourcing it well changes
// where it is stored, not what it is.
const RULES = [
  {
    id: "auth.static-cloud-key",
    category: "auth.static-cloud-key",
    severity: "critical",
    // boto3/botocore and the AWS JS SDK, given explicit key material.
    re: /\b(aws_access_key_id|aws_secret_access_key|accessKeyId|secretAccessKey)\s*[=:]/g,
    // Reading these keys OUT of an assume-role response is the compliant pattern — it is how
    // short-lived credentials get plumbed into a subprocess — and it looks identical to passing
    // static ones in. Found against terraform-guard's own STS credential-minting module, which
    // this rule flagged four times while being the most compliant file in that repo.
    excludeNearby: /\b(AssumeRole|assumeRole|STSClient|Credentials|sts:|SessionToken|sessionToken)\b/,
    message: "an AWS SDK is being given static key material",
    remediation:
      "remove the explicit keys and let the SDK resolve an assumed role — IRSA or EKS Pod " +
      "Identity in Kubernetes, an instance/task role otherwise. The SDK credential chain finds " +
      "these with no code.",
  },
  {
    id: "auth.password-connect",
    category: "auth.password",
    severity: "critical",
    // Database drivers taking a password argument, in Python or Node.
    re: /\b(password|passwd|pwd)\s*[=:]\s*(?!None\b|null\b|undefined\b)/g,
    requiresNearby: /\b(connect|createConnection|createPool|Client|Connection|Pool|engine|create_engine)\b/,
    message: "a database connection is authenticating with a password",
    remediation:
      "use IAM/OIDC database authentication (RDS IAM auth, Cloud SQL IAM, Azure AD auth) so the " +
      "workload presents its identity token instead of a shared secret. The password is still a " +
      "password when it comes from an env var or a secret manager.",
  },
  {
    id: "auth.connection-string-password",
    category: "auth.password",
    severity: "critical",
    // scheme://user:password@host — password authentication written into a connection string.
    //
    // Note this fires on placeholders too, and that is the point. secret-guard asks "is this a
    // leaked secret?" and correctly allowlists `user:password@`, because nothing was leaked. This
    // asks a different question — "is this password authentication?" — and the answer there is
    // yes regardless of whether the value is real, interpolated or a stand-in. The mechanism is
    // the finding, not the secrecy of the value.
    //
    // Found by running this scanner over six real generated projects: one had
    // `postgresql://user:password@db_host:5432/auditdb` as a default in application code, and it
    // fell through BOTH scanners.
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@"']*:[^/\s@"']{1,128}@/g,
    message: "a connection string authenticates with a password",
    remediation:
      "build the connection from an identity instead: an IAM auth token (RDS IAM, Cloud SQL IAM, " +
      "Azure AD) fetched at connect time, or mTLS with an SVID. A DSN with a password in it is " +
      "password authentication whether the value is real, interpolated or a placeholder.",
  },
  {
    id: "auth.basic",
    category: "auth.basic",
    severity: "high",
    re: /\b(HTTPBasicAuth|BasicAuth)\b|auth\s*=\s*\(|['"]Authorization['"]\s*:\s*['"]Basic\s/g, // identity-guard:allow the rule's own pattern
    message: "an outbound request is using HTTP Basic authentication",
    remediation:
      "authenticate with an mTLS client certificate from the Workload API (an X.509 SVID), or a " +
      "JWT-SVID / federated OIDC token, so the caller proves an identity rather than replaying a " +
      "shared secret.",
  },
];

export function scanCode(source, file, allowances = []) {
  const clean = strip(source);
  const findings = [];
  // One call site is one finding. `boto3.client(..., aws_access_key_id=, aws_secret_access_key=)`
  // matches twice on the same line and reporting it twice just makes the list harder to read.
  const seen = new Set();

  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(clean))) {
      // Some rules only make sense next to a connection call — `password=` inside an unrelated
      // dict is noise, and noise is what gets a scanner disabled.
      const window = clean.slice(Math.max(0, m.index - 240), m.index + 120);
      if (rule.requiresNearby && !rule.requiresNearby.test(window)) continue;
      if (rule.excludeNearby && rule.excludeNearby.test(window)) continue;
      const line = lineOf(clean, m.index);
      const key = `${rule.id}:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      // Checked against the original text: strip() has already removed the comment carrying it.
      const allowed = allowedOnLine(source, line);
      if (allowed) {
        allowances.push({ ruleId: rule.id, file, line, reason: allowed.reason });
        continue;
      }
      findings.push({
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        file,
        line,
        heuristic: false,
        message: rule.message,
        remediation: rule.remediation,
      });
    }
  }

  return findings;
}

// Dockerfiles: build-time credential material. ENV persists into the image and shows up in
// `docker history`, so a token passed this way is readable by anyone who can pull the image.
//
// Parsed per line rather than by one regex, because the two forms that matter both broke a
// single pattern: `ARG NPM_TOKEN` with no default (the usual way to pass a build secret, with the
// value supplied by --build-arg) has nothing after the name to match on, and `ENV A=1 B=2`
// declares several variables in one instruction.
const SECRET_ISH = /(PASSWORD|PASSWD|SECRET|TOKEN|ACCESS_KEY|APIKEY|API_KEY|CREDENTIAL)/i;

export function scanDockerfile(source, file, allowances = []) {
  const findings = [];
  const lines = source.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*(ENV|ARG)\s+(.*)$/i.exec(lines[i]);
    if (!m) continue;
    const instruction = m[1].toUpperCase();

    const names = [];
    for (const token of m[2].split(/\s+/)) {
      if (!token) continue;
      const name = token.split("=")[0];
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) names.push(name);
    }

    for (const name of names) {
      if (!SECRET_ISH.test(name)) continue;
      const allowed = allowedOnLine(source, i + 1);
      if (allowed) {
        allowances.push({ ruleId: "auth.dockerfile-credential", file, line: i + 1, reason: allowed.reason });
        continue;
      }
      findings.push({
        ruleId: "auth.dockerfile-credential",
        category: "auth.password",
        // ENV is baked into the image and readable by anyone who can pull it; ARG only reaches
        // the build cache. Both are wrong, one is worse.
        severity: instruction === "ENV" ? "critical" : "high",
        file,
        line: i + 1,
        heuristic: false,
        message: `${instruction} ${name} puts credential material in the image`,
        remediation:
          "an image layer is not a secret store — ENV survives into `docker history` and ARG into " +
          "the build cache. Obtain credentials at runtime from the workload's identity instead.",
      });
    }
  }
  return findings;
}
