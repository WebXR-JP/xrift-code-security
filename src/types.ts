export interface SecurityIssue {
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  message: string;
  line: number;
  column: number;
}

export interface AnalysisResult {
  issues: SecurityIssue[];
  score: number;
}

export interface AnalyzerOptions {
  filePath?: string;
}
