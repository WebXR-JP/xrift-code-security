/**
 * セキュリティ解析の違反情報
 */
export interface Violation {
  rule: string
  severity: 'critical' | 'warning'
  message: string
  location?: {
    line: number
    column: number
    code: string
  }
}

/**
 * セキュリティシグナル（検出された脅威の情報）
 */
export interface SecuritySignals {
  hasEval: boolean
  hasDynamicCodeExecution: boolean
  hasNetworkAPI: boolean
  hasNetworkWithoutPermission: boolean
  hasDynamicURLConstruction: boolean
  hasObfuscatedCode: boolean
  hasGlobalVariableOverride: boolean
  hasStorageAccess: boolean
  hasNavigatorAccess: boolean
  hasDangerousDOMManipulation: boolean
  entropy: number
  suspiciousVariableNames: boolean
  importedPackages: string[]
  referencedDomains: string[]
  detectedViolations: Violation[]
}

/**
 * コードの権限設定
 */
export interface CodePermissions {
  network?: {
    allowedDomains: string[]
  }
}

/**
 * ファイルコンテキスト（検証ルールの調整に使用）
 */
export interface FileContext {
  filePath: string
  isUserCode: boolean
  isSharedLibrary: boolean
  isBundledDependency: boolean
}

/**
 * コード検証リクエスト
 */
export interface ValidateCodeRequest {
  code: string
  sourceMap?: string
  packageJson: {
    dependencies: Record<string, string>
  }
  manifestConfig?: {
    permissions?: CodePermissions
  }
  fileContext?: FileContext
}

/**
 * コード検証レスポンス
 */
export interface ValidateCodeResponse {
  valid: boolean
  securityScore: number
  violations: {
    critical: Violation[]
    warnings: Violation[]
  }
  analysis: {
    entropy: number
    suspiciousPatterns: string[]
    detectedAPIs: string[]
    externalDependencies: string[]
  }
}
