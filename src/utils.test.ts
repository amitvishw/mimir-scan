import { describe, test, expect } from "bun:test";
import { generateFindingId } from "./utils";

describe("generateFindingId", () => {
  test("generates ID with all components", () => {
    const id = generateFindingId("scanner", "path/to/file.js", 42, "rule-id");
    expect(id).toBe("scanner:path/to/file.js:42:rule-id");
  });

  test("handles undefined line number", () => {
    const id = generateFindingId("scanner", "file.js", undefined, "rule");
    expect(id).toBe("scanner:file.js:0:rule");
  });

  test("sanitizes special characters", () => {
    const id = generateFindingId("scan ner", "file<>.js", 1, "rule|test");
    expect(id).not.toContain(" ");
    expect(id).not.toContain("<");
    expect(id).not.toContain(">");
    expect(id).not.toContain("|");
  });

  test("preserves allowed characters", () => {
    const id = generateFindingId("scanner", "src/path/file.ts", 10, "rule-id_v1");
    expect(id).toContain("src/path/file.ts");
    expect(id).toContain("rule-id_v1");
  });

  test("handles zero line number", () => {
    const id = generateFindingId("scanner", "file.js", 0, "rule");
    expect(id).toBe("scanner:file.js:0:rule");
  });
});
