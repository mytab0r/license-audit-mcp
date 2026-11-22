import { describe, it, expect } from "vitest";
import { fetchDep, normaliseSystem } from "../src/tools.js";

const RUN = process.env.RUN_INTEGRATION === "1";

describe.runIf(RUN)("deps.dev live", () => {
  it("returns license + advisories for lodash 4.17.21", async () => {
    const d = await fetchDep("npm", "lodash", "4.17.21");
    expect(d.error).toBeUndefined();
    expect(d.licenses).toContain("MIT");
    expect(d.advisories.length).toBeGreaterThan(0);
  });

  it("maps pypi", async () => {
    const d = await fetchDep(normaliseSystem("python"), "requests", "2.31.0");
    expect(d.licenses).toContain("Apache-2.0");
  });
});
