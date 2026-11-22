/**
 * Pure tool functions — business logic only, no MCP dependency.
 * License data comes from the keyless deps.dev API (Google Open Source Insights).
 */

export type Category =
  | "public-domain"
  | "permissive"
  | "weak-copyleft"
  | "strong-copyleft"
  | "network-copyleft"
  | "unknown";

export interface LicenseInfo {
  category: Category;
  obligations: string[];
  commercial_ok: boolean;
}

const ATTR = "Must keep copyright notice and license text (attribution)";
const NO_WARRANTY = "Provided as-is, no warranty";

const TABLE: Record<string, LicenseInfo> = {
  "MIT": { category: "permissive", commercial_ok: true, obligations: [ATTR, NO_WARRANTY] },
  "ISC": { category: "permissive", commercial_ok: true, obligations: [ATTR, NO_WARRANTY] },
  "BSD-2-Clause": { category: "permissive", commercial_ok: true, obligations: [ATTR, NO_WARRANTY] },
  "BSD-3-Clause": { category: "permissive", commercial_ok: true, obligations: [ATTR, NO_WARRANTY, "Do not use names of authors/contributors to endorse your product"] },
  "Apache-2.0": { category: "permissive", commercial_ok: true, obligations: [ATTR, NO_WARRANTY, "State changes you made to the files", "Include NOTICE file if the project ships one", "Patent grant included"] },
  "0BSD": { category: "public-domain", commercial_ok: true, obligations: [] },
  "Unlicense": { category: "public-domain", commercial_ok: true, obligations: [] },
  "CC0-1.0": { category: "public-domain", commercial_ok: true, obligations: [] },
  "WTFPL": { category: "public-domain", commercial_ok: true, obligations: [] },
  "Zlib": { category: "permissive", commercial_ok: true, obligations: [ATTR, "Do not misrepresent the origin of the software"] },
  "BSL-1.0": { category: "permissive", commercial_ok: true, obligations: [ATTR, NO_WARRANTY] },
  "Python-2.0": { category: "permissive", commercial_ok: true, obligations: [ATTR, NO_WARRANTY] },
  "MPL-2.0": { category: "weak-copyleft", commercial_ok: true, obligations: [ATTR, NO_WARRANTY, "Publish source of modified MPL-covered files you distribute"] },
  "EPL-2.0": { category: "weak-copyleft", commercial_ok: true, obligations: [ATTR, "Publish source of modified EPL-covered modules"] },
  "LGPL-2.1-only": { category: "weak-copyleft", commercial_ok: true, obligations: [ATTR, "Allow relinking against a modified library (dynamic linking is the safe path)"] },
  "LGPL-2.1-or-later": { category: "weak-copyleft", commercial_ok: true, obligations: [ATTR, "Allow relinking against a modified library (dynamic linking is the safe path)"] },
  "LGPL-3.0-only": { category: "weak-copyleft", commercial_ok: true, obligations: [ATTR, "Allow relinking against a modified library (dynamic linking is the safe path)"] },
  "LGPL-3.0-or-later": { category: "weak-copyleft", commercial_ok: true, obligations: [ATTR, "Allow relinking against a modified library (dynamic linking is the safe path)"] },
  "GPL-2.0-only": { category: "strong-copyleft", commercial_ok: true, obligations: [ATTR, "Distributing binaries requires releasing full corresponding source under GPL"] },
  "GPL-2.0-or-later": { category: "strong-copyleft", commercial_ok: true, obligations: [ATTR, "Distributing binaries requires releasing full corresponding source under GPL"] },
  "GPL-3.0-only": { category: "strong-copyleft", commercial_ok: true, obligations: [ATTR, "Distributing binaries requires releasing full corresponding source under GPL", "Anti-tivoization: installation information required for user products"] },
  "GPL-3.0-or-later": { category: "strong-copyleft", commercial_ok: true, obligations: [ATTR, "Distributing binaries requires releasing full corresponding source under GPL", "Anti-tivoization: installation information required for user products"] },
  "AGPL-3.0-only": { category: "network-copyleft", commercial_ok: true, obligations: [ATTR, "Offering the software over a network requires publishing the full source, including your modifications"] },
  "AGPL-3.0-or-later": { category: "network-copyleft", commercial_ok: true, obligations: [ATTR, "Offering the software over a network requires publishing the full source, including your modifications"] },
  "SSPL-1.0": { category: "network-copyleft", commercial_ok: false, obligations: ["Offering as a service requires releasing the whole service stack source; effectively non-commercial for SaaS"] },
  "BUSL-1.1": { category: "unknown", commercial_ok: false, obligations: ["Source-available, NOT open source: production/commercial use is restricted until the change date in the license text"] },
  "Commons-Clause": { category: "unknown", commercial_ok: false, obligations: ["Forbids selling the software or services whose value derives from it"] },
};

export function classifyLicense(id: string): LicenseInfo {
  const raw = (id || "").trim();
  if (raw in TABLE) return TABLE[raw];
  const lower = raw.toLowerCase();
  if (!lower) return { category: "unknown", commercial_ok: false, obligations: ["No license declared: treat as all rights reserved"] };
  for (const key of Object.keys(TABLE)) {
    if (key.toLowerCase() === lower) return TABLE[key];
  }
  // SPDX "OR"/"AND" expressions: judge by the strictest term, which is what a
  // compliance review has to satisfy anyway.
  if (/[()]|\s(and|or|\/)\s/i.test(raw)) {
    const parts = raw.split(/[()]|\s(?:and|or|\/)\s/i).filter(Boolean);
    const infos = parts.map((p) => classifyLicense(p));
    const rank = ["unknown", "network-copyleft", "strong-copyleft", "weak-copyleft", "permissive", "public-domain"];
    const worst = infos.sort((a, b) => rank.indexOf(a.category) - rank.indexOf(b.category))[0];
    return { category: worst.category, commercial_ok: infos.every((i) => i.commercial_ok), obligations: [...new Set(infos.flatMap((i) => i.obligations))] };
  }
  if (/(^|[^a-z])lgpl|mpl|epl/i.test(raw)) return { category: "weak-copyleft", commercial_ok: true, obligations: [ATTR] };
  if (/agpl/i.test(raw)) return { category: "network-copyleft", commercial_ok: true, obligations: [ATTR, "Network use requires publishing full source"] };
  if (/gpl/i.test(raw)) return { category: "strong-copyleft", commercial_ok: true, obligations: [ATTR, "Distribution requires releasing corresponding source"] };
  if (/apache|mit|bsd|isc|unlicense|cc0/i.test(raw)) return { category: "permissive", commercial_ok: true, obligations: [ATTR] };
  return { category: "unknown", commercial_ok: false, obligations: ["Unrecognised license id: read the license text before commercial use"] };
}

// ---------------------------------------------------------------------------
// deps.dev client
// ---------------------------------------------------------------------------

const DEPS_API = "https://api.deps.dev/v3";
const TTL_MS = 60 * 60 * 1000;
const cache = new Map<string, { exp: number; value: DepInfo }>();

export interface DepInfo {
  ecosystem: string;
  name: string;
  version: string;
  licenses: string[];
  advisories: string[];
  deprecated: boolean;
  homepage?: string;
  error?: string;
}

export function normaliseSystem(s: string): string {
  const v = s.toLowerCase().trim();
  const map: Record<string, string> = { node: "NPM", javascript: "NPM", js: "NPM", python: "PYPI", py: "PYPI", golang: "GO", rust: "CARGO", java: "MAVEN", dotnet: "NUGET" };
  return map[v] || v.toUpperCase();
}

async function getJson(url: string): Promise<unknown> {
  let lastErr: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(9000), headers: { accept: "application/json" } });
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`deps.dev HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      lastErr = err;
      await new Promise((r) => setTimeout(r, 300 * (attempt + 1)));
    }
  }
  throw lastErr;
}

export async function resolveVersion(system: string, name: string): Promise<string | null> {
  const data = (await getJson(`${DEPS_API}/systems/${system}/packages/${encodeURIComponent(name)}`)) as
    | { versions?: Array<{ versionKey: { version: string }; isDefault?: boolean }> }
    | null;
  const versions = data?.versions || [];
  if (!versions.length) return null;
  return (versions.find((v) => v.isDefault) || versions[versions.length - 1]).versionKey.version;
}

export async function fetchDep(system: string, name: string, version?: string): Promise<DepInfo> {
  const sys = normaliseSystem(system);
  const key = `${sys}|${name}|${version || "latest"}`;
  const hit = cache.get(key);
  if (hit && hit.exp > Date.now()) return hit.value;

  let info: DepInfo = { ecosystem: sys, name, version: version || "", licenses: [], advisories: [], deprecated: false };
  try {
    let v = version;
    if (!v) v = await resolveVersion(sys, name) || "";
    if (!v) throw new Error("version not found");
    info.version = v;
    const data = (await getJson(`${DEPS_API}/systems/${sys}/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(v)}`)) as
      | { licenses?: string[]; advisoryKeys?: Array<{ id: string }>; isDeprecated?: boolean; links?: Array<{ label: string; url: string }> }
      | null;
    if (!data) throw new Error("package/version not found in deps.dev");
    info.licenses = data.licenses || [];
    info.advisories = (data.advisoryKeys || []).map((a) => a.id);
    info.deprecated = Boolean(data.isDeprecated);
    info.homepage = (data.links || []).find((l) => l.label === "HOMEPAGE")?.url;
  } catch (err) {
    info.error = err instanceof Error ? err.message : String(err);
  }
  cache.set(key, { exp: Date.now() + TTL_MS, value: info });
  return info;
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length || 1) }, async () => {
    while (cursor < items.length) {
      const i = cursor++;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

export interface DepSpec { name: string; version?: string }

export async function auditDependencies(ecosystem: string, deps: DepSpec[]) {
  const infos = await mapLimit(deps, 8, (d) => fetchDep(ecosystem, d.name, d.version));
  const rows = infos.map((info) => {
    const license = info.licenses[0] || "";
    const cls = classifyLicense(license);
    return {
      name: info.name,
      version: info.version,
      licenses: info.licenses,
      license: license || "UNKNOWN",
      category: cls.category,
      commercial_ok: cls.commercial_ok,
      obligations: cls.obligations,
      advisories: info.advisories,
      deprecated: info.deprecated,
      ...(info.error ? { error: info.error } : {}),
    };
  });
  const byCategory: Record<string, number> = {};
  for (const r of rows) byCategory[r.category] = (byCategory[r.category] || 0) + 1;
  return {
    ecosystem: normaliseSystem(ecosystem),
    total: rows.length,
    resolved: rows.filter((r) => !r.error).length,
    by_category: byCategory,
    risk: {
      strong_or_network_copyleft: rows.filter((r) => r.category === "strong-copyleft" || r.category === "network-copyleft").map((r) => r.name),
      non_commercial: rows.filter((r) => !r.commercial_ok && !r.error).map((r) => r.name),
      unknown_license: rows.filter((r) => r.category === "unknown" && !r.error).map((r) => r.name),
      with_advisories: rows.filter((r) => r.advisories.length > 0).map((r) => ({ name: r.name, version: r.version, advisories: r.advisories })),
    },
    dependencies: rows,
  };
}

export interface AuditPolicy {
  deny?: string[];
  allow?: string[];
  block_strong_copyleft?: boolean;
  block_non_commercial?: boolean;
}

export function evaluatePolicy(rows: Array<{ name: string; license: string; category: Category; commercial_ok: boolean }>, policy: AuditPolicy) {
  const deny = (policy.deny || []).map((d) => d.toLowerCase());
  const allow = (policy.allow || []).map((d) => d.toLowerCase());
  const violations: Array<{ name: string; license: string; reason: string }> = [];
  for (const r of rows) {
    const lic = r.license.toLowerCase();
    if (deny.includes(lic)) violations.push({ name: r.name, license: r.license, reason: "license is on the deny list" });
    else if (allow.length && !allow.includes(lic)) violations.push({ name: r.name, license: r.license, reason: "license is not on the allow list" });
    else if (policy.block_non_commercial && !r.commercial_ok) violations.push({ name: r.name, license: r.license, reason: "non-commercial license" });
    else if (policy.block_strong_copyleft && (r.category === "strong-copyleft" || r.category === "network-copyleft")) violations.push({ name: r.name, license: r.license, reason: `${r.category} license conflicts with a closed-source product` });
  }
  return { verdict: violations.length ? "fail" : "pass", checked: rows.length, violations };
}

export function buildNotices(rows: Array<{ name: string; version: string; license: string; license_number?: number }>, projectName = "this product") {
  const groups = new Map<string, string[]>();
  for (const r of rows) {
    const key = r.license || "UNKNOWN";
    const list = groups.get(key) || [];
    list.push(r.version ? `${r.name} ${r.version}` : r.name);
    groups.set(key, list);
  }
  const lines = [
    `# Third-party notices for ${projectName}`,
    "",
    "This product includes the following third-party software.",
    "",
  ];
  for (const [license, packages] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    lines.push(`## ${license}`, "", ...packages.sort().map((p) => `- ${p}`), "");
  }
  lines.push("Full license texts are distributed with each package; MIT/BSD/Apache-2.0 require them to be included with any distribution of this product.");
  return lines.join("\n");
}
