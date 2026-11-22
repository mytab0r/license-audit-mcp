import { describe, it, expect } from "vitest";
import { classifyLicense, evaluatePolicy, buildNotices, normaliseSystem } from "../src/tools.js";

describe("classifyLicense", () => {
  it("classifies permissive licenses as commercial-safe", () => {
    for (const id of ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]) {
      const info = classifyLicense(id);
      expect(info.category).toBe("permissive");
      expect(info.commercial_ok).toBe(true);
      expect(info.obligations.join(" ")).toMatch(/attribution/i);
    }
  });

  it("flags AGPL as network copyleft with the SaaS obligation spelled out", () => {
    const info = classifyLicense("AGPL-3.0-only");
    expect(info.category).toBe("network-copyleft");
    expect(info.obligations.join(" ")).toMatch(/over a network/i);
  });

  it("treats BUSL as non-commercial", () => {
    const info = classifyLicense("BUSL-1.1");
    expect(info.commercial_ok).toBe(false);
  });

  it("takes the strictest term of an SPDX OR expression", () => {
    const info = classifyLicense("MIT OR GPL-3.0-only");
    expect(info.category).toBe("strong-copyleft");
  });

  it("falls back to unknown for a licence it does not know", () => {
    expect(classifyLicense("Weird-1.0").category).toBe("unknown");
    expect(classifyLicense("").obligations.length).toBeGreaterThan(0);
  });
});

describe("evaluatePolicy", () => {
  const rows = [
    { name: "lodash", license: "MIT", category: "permissive" as const, commercial_ok: true },
    { name: "leftpad", license: "GPL-3.0-only", category: "strong-copyleft" as const, commercial_ok: true },
    { name: "sspl-thing", license: "SSPL-1.0", category: "network-copyleft" as const, commercial_ok: false },
  ];

  it("passes when nothing is denied", () => {
    const r = evaluatePolicy(rows, {});
    expect(r.verdict).toBe("pass");
    expect(r.violations).toHaveLength(0);
  });

  it("fails on deny list and names the package", () => {
    const r = evaluatePolicy(rows, { deny: ["GPL-3.0-only"] });
    expect(r.verdict).toBe("fail");
    expect(r.violations[0]).toMatchObject({ name: "leftpad", license: "GPL-3.0-only" });
  });

  it("fails on allow list for anything outside it", () => {
    const r = evaluatePolicy(rows, { allow: ["MIT", "Apache-2.0"] });
    expect(r.violations.map((v) => v.name).sort()).toEqual(["leftpad", "sspl-thing"]);
  });

  it("blocks strong copyleft and non-commercial on request", () => {
    const r = evaluatePolicy(rows, { block_strong_copyleft: true, block_non_commercial: true });
    expect(r.violations.map((v) => v.name).sort()).toEqual(["leftpad", "sspl-thing"]);
  });
});

describe("buildNotices", () => {
  it("groups packages by licence and keeps both name and version", () => {
    const md = buildNotices(
      [
        { name: "lodash", version: "4.17.21", license: "MIT" },
        { name: "axios", version: "1.6.0", license: "MIT" },
        { name: "requests", version: "2.31.0", license: "Apache-2.0" },
      ],
      "license-audit"
    );
    expect(md).toContain("# Third-party notices for license-audit");
    expect(md).toContain("## MIT");
    expect(md).toContain("- axios 1.6.0");
    expect(md).toContain("- lodash 4.17.21");
    expect(md).toContain("## Apache-2.0");
  });
});

describe("normaliseSystem", () => {
  it("maps aliases to deps.dev system ids", () => {
    expect(normaliseSystem("javascript")).toBe("NPM");
    expect(normaliseSystem("python")).toBe("PYPI");
    expect(normaliseSystem("npm")).toBe("NPM");
  });
});
