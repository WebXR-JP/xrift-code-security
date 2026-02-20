import { analyzeCodeSecurity } from './analyzer.js'
import { calculateSecurityScore } from './scoring.js'
import { adjustViolationSeverity, determineFileContext } from './utils/file-context.js'
import type {
  ValidateCodeRequest,
  ValidateCodeResponse,
  Violation
} from './types.js'

/**
 * エントロピー閾値（analyzer.ts, scoring.tsと同じ値）
 */
const ENTROPY_THRESHOLD = 7.0

/**
 * コードセキュリティ解析サービス
 */
export class CodeSecurityService {
  /**
   * コードを検証
   */
  validate(request: ValidateCodeRequest): ValidateCodeResponse {
    // ファイルコンテキストを判定（指定されていない場合は自動判定）
    const fileContext = request.fileContext || determineFileContext(request.code)

    // セキュリティ解析実行
    const signals = analyzeCodeSecurity(
      request.code,
      request.manifestConfig?.permissions
    )

    // ファイルコンテキストに基づいて違反の重大度を調整
    const adjustedViolations = signals.detectedViolations.map(violation => {
      const adjustedSeverity = adjustViolationSeverity(
        violation.rule,
        violation.severity,
        fileContext
      )

      return {
        ...violation,
        severity: adjustedSeverity
      }
    })

    // セキュリティスコア計算
    const securityScore = calculateSecurityScore(signals)

    // 違反を分類（調整後の重大度で）
    const critical: Violation[] = []
    const warnings: Violation[] = []

    for (const violation of adjustedViolations) {
      if (violation.severity === 'critical') {
        critical.push(violation)
      } else {
        warnings.push(violation)
      }
    }

    // 検出されたAPI一覧
    const detectedAPIs: string[] = []
    if (signals.hasEval) detectedAPIs.push('eval')
    if (signals.hasDynamicCodeExecution) detectedAPIs.push('setTimeout/setInterval(string)')
    if (signals.hasNetworkAPI) detectedAPIs.push('fetch/WebSocket/XMLHttpRequest')
    if (signals.hasStorageAccess) detectedAPIs.push('localStorage/sessionStorage/indexedDB/cookie')
    if (signals.hasNavigatorAccess) detectedAPIs.push('navigator')
    if (signals.hasDangerousDOMManipulation) detectedAPIs.push('innerHTML/outerHTML/createElement')
    if (signals.hasObfuscatedCode) detectedAPIs.push('obfuscation (atob/btoa/fromCharCode)')

    // 疑わしいパターン
    const suspiciousPatterns: string[] = []
    if (signals.hasDynamicURLConstruction) suspiciousPatterns.push('動的URL構築')
    if (signals.hasGlobalVariableOverride) suspiciousPatterns.push('グローバル変数改ざん')
    if (signals.entropy > ENTROPY_THRESHOLD) suspiciousPatterns.push(`高エントロピー文字列 (${signals.entropy.toFixed(2)})`)
    if (signals.suspiciousVariableNames) suspiciousPatterns.push('疑わしい変数名')

    // 外部依存パッケージ
    const externalDependencies = signals.importedPackages.filter(
      pkg => pkg.startsWith('http://') || pkg.startsWith('https://')
    )

    // Critical違反の有無のみで判定
    const valid = critical.length === 0

    return {
      valid,
      securityScore,
      violations: {
        critical,
        warnings
      },
      analysis: {
        entropy: signals.entropy,
        suspiciousPatterns,
        detectedAPIs,
        externalDependencies
      }
    }
  }
}

export { analyzeCodeSecurity } from './analyzer.js'
export { calculateSecurityScore, getSecurityVerdict } from './scoring.js'
export { determineFileContext, adjustViolationSeverity } from './utils/file-context.js'
export * from './types.js'
