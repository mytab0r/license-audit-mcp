# license-audit

MCP server that audits open-source licences for AI coding agents.

Tools:
- `license_lookup` — SPDX id, category (permissive / weak / strong / network copyleft), obligations, advisories, deprecation for one package version.
- `audit_dependencies` — batch audit of a dependency list with risk summary (strong/network copyleft, non-commercial, unknown licences, known advisories).
- `check_policy` — pass/fail against a compliance policy (deny/allow lists, block copyleft, block non-commercial) with exact violations.
- `generate_notices` — THIRDPARTYNOTICES.md-ready attribution file grouped by licence.

Data source: deps.dev (Google Open Source Insights), keyless. No API key needed by the server; the MCPize subscription is the only gate.
