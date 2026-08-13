import path from "path";

// Sole allowed scan boundary — defaults to this process's cwd (wherever the MCP client launched
// it from). Same containment pattern as dep-audit-mcp's SCAN_ROOT and local-delegate-mcp's
// CONTEXT_ROOT: a careless or attacker-influenced argument can't point the scanner at ~/.aws,
// ~/.ssh, or a sibling project.
//
// This server reports rule ids and line numbers, never file contents or credential values, so a
// traversal here leaks far less than secret-guard's would. The containment is kept identical
// anyway: the boundary should not depend on remembering which scanner is which.
export function resolveScanPath(relOrAbsPath, scanRoot) {
  const resolved = path.resolve(scanRoot, relOrAbsPath);
  if (resolved !== scanRoot && !resolved.startsWith(scanRoot + path.sep)) {
    throw new Error(`refuses to scan outside ${scanRoot}: ${relOrAbsPath}`);
  }
  return resolved;
}
