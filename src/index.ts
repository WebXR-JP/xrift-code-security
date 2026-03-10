import { analyzeCodeSecurity } from './analyzer.js'
import { calculateSecurityScore } from './scoring.js'
import { adjustViolationSeverity, determineFileContext } from './utils/file-context.js'
import type {
  ValidateCodeRequest,
  ValidateCodeResponse,
  Violation,
  WorldPermissions
} from './types.js'

/**
 * エントロピー閾値（analyzer.ts, scoring.tsと同じ値）
 */
const ENTROPY_THRESHOLD = 7.0

/**
 * 絶対に許可不可なルール（allowedCodeRules で指定しても除外されない）
 * これらのルールはセキュリティの根幹に関わるため、ワールド開発者でも緩和できない
 */
export const NEVER_ALLOWABLE_RULES = [
  'no-eval',
  'no-sensitive-api-override',
  'no-rtc-connection',
  'no-prototype-pollution',
  'no-storage-access',
  'no-cookie-access',
  'no-indexeddb-access',
  'no-storage-event',
  'no-external-import',
] as const

/**
 * 許可可能なルール（allowedCodeRules で宣言可能）
 * ワールド開発者が正当な用途のために緩和を宣言でき、訪問者が同意して入室する
 */
export const ALLOWABLE_RULES = [
  'no-obfuscation',
  'no-new-function',
  'no-dangerous-dom',
  'no-javascript-blob',
  'no-global-override',
  'no-navigator-access',
  'no-network-without-permission',
  'no-string-timeout',
] as const

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

    // 共有ライブラリはホストが提供するためスキャン不要
    if (fileContext.isSharedLibrary) {
      return {
        valid: true,
        securityScore: 0,
        violations: { critical: [], warnings: [] },
        analysis: {
          entropy: 0,
          suspiciousPatterns: [],
          detectedAPIs: [],
          externalDependencies: [],
        },
      }
    }

    // worldPermissions の allowedDomains をマージ
    const mergedPermissions = this.mergePermissions(
      request.manifestConfig?.permissions,
      request.worldPermissions
    )

    // セキュリティ解析実行
    const signals = analyzeCodeSecurity(
      request.code,
      mergedPermissions
    )

    // ファイルコンテキストに基づいて違反の重大度を調整
    // adjustViolationSeverity が null を返した場合は誤検知として除外
    const adjustedViolations = signals.detectedViolations
      .map(violation => {
        const adjustedSeverity = adjustViolationSeverity(
          violation.rule,
          violation.severity,
          fileContext
        )

        if (adjustedSeverity === null) {
          return null
        }

        return {
          ...violation,
          severity: adjustedSeverity
        }
      })
      .filter((v): v is NonNullable<typeof v> => v !== null)

    // allowedCodeRules によるフィルタリング（NEVER_ALLOWABLE_RULES は除外不可）
    const { filteredViolations, permissionWarnings } = this.applyWorldPermissions(
      adjustedViolations,
      request.worldPermissions
    )

    // セキュリティスコア計算
    const securityScore = calculateSecurityScore(signals)

    // 違反を分類（調整後の重大度で）
    const critical: Violation[] = []
    const warnings: Violation[] = []

    for (const violation of filteredViolations) {
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
      },
      ...(permissionWarnings.length > 0 && { permissionWarnings }),
    }
  }

  /**
   * manifestConfig.permissions と worldPermissions.allowedDomains をマージ
   */
  private mergePermissions(
    manifestPermissions?: { network?: { allowedDomains: string[] } },
    worldPermissions?: WorldPermissions
  ) {
    const manifestDomains = manifestPermissions?.network?.allowedDomains || []
    const worldDomains = worldPermissions?.allowedDomains || []
    const mergedDomains = [...new Set([...manifestDomains, ...worldDomains])]

    if (mergedDomains.length === 0) {
      return manifestPermissions
    }

    return {
      ...manifestPermissions,
      network: {
        allowedDomains: mergedDomains
      }
    }
  }

  /**
   * worldPermissions.allowedCodeRules で許可されたルールの violations を除外
   * NEVER_ALLOWABLE_RULES に含まれるルールは除外不可
   */
  private applyWorldPermissions(
    violations: Violation[],
    worldPermissions?: WorldPermissions
  ): { filteredViolations: Violation[]; permissionWarnings: string[] } {
    const permissionWarnings: string[] = []
    const allowedCodeRules = worldPermissions?.allowedCodeRules || []

    if (allowedCodeRules.length === 0) {
      return { filteredViolations: violations, permissionWarnings }
    }

    // 無効なルール指定を警告
    const allKnownRules: readonly string[] = [...NEVER_ALLOWABLE_RULES, ...ALLOWABLE_RULES]
    for (const rule of allowedCodeRules) {
      if (NEVER_ALLOWABLE_RULES.includes(rule as any)) {
        permissionWarnings.push(
          `"${rule}" は絶対禁止ルールのため allowedCodeRules で許可できません`
        )
      } else if (!allKnownRules.includes(rule)) {
        permissionWarnings.push(
          `"${rule}" は不明なルールです`
        )
      }
    }

    // ALLOWABLE_RULES に含まれるルールのみ実際にフィルタリング
    const effectiveAllowedRules = allowedCodeRules.filter(
      rule => (ALLOWABLE_RULES as readonly string[]).includes(rule)
    )

    const filteredViolations = violations.filter(
      v => !effectiveAllowedRules.includes(v.rule)
    )

    return { filteredViolations, permissionWarnings }
  }
}

export { analyzeCodeSecurity } from './analyzer.js'
export { calculateSecurityScore, getSecurityVerdict } from './scoring.js'
export { determineFileContext, adjustViolationSeverity, PLATFORM_SHARED_PACKAGES } from './utils/file-context.js'
export * from './types.js'
