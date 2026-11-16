import { realpathSync } from "fs";
import path from "path";

// Sole allowed scan boundary — defaults to this process's cwd (wherever the MCP client launched
// it from). Same containment pattern as dep-audit-mcp's SCAN_ROOT and local-delegate-mcp's
// CONTEXT_ROOT: a careless or attacker-influenced argument can't point the scanner at ~/.aws,
// ~/.ssh, or a sibling project.
//
// This server reports rule ids and line numbers, never file contents or credential values, so a
// traversal here leaks far less than secret-guard's would. The containment is kept identical
// anyway: the boundary should not depend on remembering which scanner is which.
//
// Real paths, not resolved text. path.resolve() only normalises the string, so a symlink inside
// the root that points outside it passed, and a root reached through a symlink refused the real
// spelling of paths under it. Both the root and the target are resolved with realpathSync and the
// real target is what comes back, so the scanner reads the directory that was checked rather than
// a link that could be followed somewhere else. A target that does not exist is refused, except
// that a path below a link out of the root is refused as outside: the walk up to the nearest
// existing ancestor is there so a refusal never says what does or does not exist out there.
//
// The same function, line for line, is dep-audit-mcp's resolveScanPath, secret-guard-mcp's
// resolveScanPath and terraform-guard-mcp's resolveWorkingDir. Change them together.
export function resolveScanPath(relOrAbsPath, scanRoot) {
  const root = realpathOrNull(scanRoot);
  if (root === null) throw new Error(`containment root does not exist: ${scanRoot}`);
  const requested = path.resolve(root, relOrAbsPath);
  let existing = requested;
  let real = realpathOrNull(existing);
  while (real === null && path.dirname(existing) !== existing) {
    existing = path.dirname(existing);
    real = realpathOrNull(existing);
  }
  if (real === null || (real !== root && !real.startsWith(root + path.sep))) {
    throw new Error(`refuses to scan outside ${scanRoot}: ${relOrAbsPath}`);
  }
  if (existing !== requested) throw new Error(`does not exist: ${relOrAbsPath}`);
  return real;
}

function realpathOrNull(p) {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}
