// Two kinds of finding, and the distinction is the whole design.
//
// A DENY finding says "this code authenticates with something it holds" — a password, a static
// key, a basic-auth header. It is a fact about the text, so it blocks.
//
// A WIRING finding says "this workload has no identity to authenticate WITH". That is the
// positive half of the policy and it is strictly harder: a file containing no credential at all
// still fails it. Some wiring is also bound outside the manifest — EKS Pod Identity associates a
// role to a ServiceAccount in AWS, not in YAML — so the absence of evidence in the file is not
// always evidence of absence. Those are marked `heuristic` and reported without blocking, the
// same treatment secret-guard gives entropy-based hits.
export const CATEGORIES = [
  "auth.static-cloud-key",     // access key / secret key passed to an SDK
  "auth.password",             // a password reaches an authentication call
  "auth.basic",                // HTTP Basic / bearer-from-config
  "auth.long-lived-identity",  // infrastructure that creates a permanent credential
  "identity.default-sa",       // pod runs as the default ServiceAccount, or none
  "identity.unbound",          // non-default SA with no discoverable identity binding
  "identity.secret-as-auth",   // a Secret is being used as the authentication material
];

export function isKnownCategory(c) {
  return CATEGORIES.includes(c);
}

// What a workload identity actually looks like on a ServiceAccount, verified against current
// provider docs rather than memory (2026-08): AWS IRSA, GKE, and Azure Workload Identity each
// annotate the ServiceAccount; EKS Pod Identity deliberately does not, which is why its absence
// cannot be treated as proof of misconfiguration.
export const IDENTITY_ANNOTATIONS = [
  "eks.amazonaws.com/role-arn",          // AWS IRSA
  "iam.gke.io/gcp-service-account",      // GKE Workload Identity
  "azure.workload.identity/client-id",   // Azure AD Workload Identity
];

// Both shipping SPIFFE CSI drivers. `csi.spiffe.io` is spiffe/spiffe-csi (mounts the Workload API
// socket); `spiffe.csi.cert-manager.io` is cert-manager/csi-driver-spiffe (mounts an X.509 SVID
// keypair). Either is a valid way for a pod to obtain an SVID.
export const SPIFFE_CSI_DRIVERS = ["csi.spiffe.io", "spiffe.csi.cert-manager.io"];

// The Workload API socket, however it is reached. A hostPath mount of the SPIRE agent socket is
// the pre-CSI pattern and still common.
export const SPIFFE_SOCKET_HINTS = [
  "spire-agent",
  "/run/spire",
  "/tmp/spire-agent",
  "SPIFFE_ENDPOINT_SOCKET",
];
