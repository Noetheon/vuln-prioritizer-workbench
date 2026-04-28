import { describe, expect, it } from "vitest";

import { compactHash, formatCount, formatPercent, governanceLabel, topEntries } from "./format";

describe("format helpers", () => {
  it("formats Workbench counts and percentages", () => {
    expect(formatCount(25743)).toBe("25,743");
    expect(formatPercent(0.9432)).toBe("94.3%");
    expect(formatPercent(null)).toBe("N.A.");
  });

  it("normalizes compact UI labels", () => {
    expect(governanceLabel("review_due")).toBe("review due");
    expect(compactHash("abcdef0123456789")).toBe("abcdef0...56789");
  });

  it("sorts record entries by count and name", () => {
    expect(topEntries({ beta: 1, alpha: 3, gamma: 3 }, 2)).toEqual([
      ["alpha", 3],
      ["gamma", 3]
    ]);
  });
});
