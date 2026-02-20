import { describe, it, expect } from "vitest";
import { analyze } from "../src/index.js";

describe("analyze", () => {
  it("should return an analysis result", () => {
    const result = analyze("const x = 1;");
    expect(result).toHaveProperty("issues");
    expect(result).toHaveProperty("score");
  });
});
