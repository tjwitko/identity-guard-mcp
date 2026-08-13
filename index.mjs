#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import path from "path";

import { resolveScanPath } from "./lib/paths.mjs";
import { scanProject, REMEDIATION_HEADER, EXCEPTION_FILE } from "./lib/scan.mjs";

// Same guardrail as every sibling: a stdio server inherits its parent's whole environment by
// default and needs none of it.
function sanitizeEnv(allowlist) {
  for (const key in process.env) {
    if (!allowlist.includes(key)) delete process.env[key];
  }
}
sanitizeEnv(["PATH", "HOME", "SCAN_ROOT"]);

const SCAN_ROOT = path.resolve(process.env.SCAN_ROOT || process.cwd());

const server = new McpServer({ name: "identity-guard", version: "1.0.0" });

server.tool(
  "check_auth_posture",
  "Check that a project authenticates with workload identity rather than credentials it holds. " +
    "Reports two kinds of finding: code or config that authenticates with a password, static " +
    "cloud key, HTTP Basic header or Kubernetes Secret (blocking), and workloads that have no " +
    "identity bound to them at all (advisory, because EKS Pod Identity binds outside the " +
    "manifest). Run it after writing application code, Kubernetes manifests or a Dockerfile. " +
    "Advisory only: it reports, it cannot prevent a file being written or committed.",
  {
    directory: z
      .string()
      .describe(
        "Project directory to check, relative to this server's working directory or absolute " +
          "within it. Scanned recursively."
      ),
  },
  async ({ directory }) => {
    let resolved;
    try {
      resolved = resolveScanPath(directory, SCAN_ROOT);
    } catch (error) {
      return { content: [{ type: "text", text: `Refusing to scan: ${error.message}` }], isError: true };
    }

    const report = scanProject(resolved);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              ...report,
              policy: REMEDIATION_HEADER,
              ...(report.clean ? {} : { exceptionFile: EXCEPTION_FILE }),
            },
            null,
            2
          ),
        },
      ],
    };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("identity-guard MCP server running on stdio");
}
main().catch(console.error);
