import type { AnalysisResult, AnalyzerOptions } from "./types.js";

export function analyze(
  _code: string,
  _options?: AnalyzerOptions,
): AnalysisResult {
  // TODO: implement analysis logic
  return {
    issues: [],
    score: 100,
  };
}
