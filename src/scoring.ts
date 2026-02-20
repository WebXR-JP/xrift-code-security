import type { SecuritySignals } from './types.js'
import { ALLOWED_PACKAGES } from './utils/helpers.js'

/**
 * エントロピー閾値（analyzer.tsと同じ値）
 */
const ENTROPY_THRESHOLD = 7.0

/**
 * セキュリティスコアを計算（0-100、高いほど危険）
 */
export function calculateSecurityScore(signals: SecuritySignals): number {
  let score = 0

  // Critical violations（即100点 = 拒否）
  if (signals.hasEval) return 100
  if (signals.hasDynamicCodeExecution) return 100
  if (signals.hasNetworkWithoutPermission) return 100
  if (signals.hasGlobalVariableOverride) return 100
  if (signals.hasStorageAccess) return 100
  if (signals.hasNavigatorAccess) return 100
  if (signals.hasDangerousDOMManipulation) return 100
  if (signals.hasObfuscatedCode) return 100

  // 疑わしいパターンの組み合わせ
  if (signals.hasDynamicURLConstruction && signals.hasNetworkAPI) {
    score += 40
  }

  if (signals.entropy > ENTROPY_THRESHOLD) {
    score += 15
  }

  if (signals.suspiciousVariableNames) {
    score += 10
  }

  // 未許可パッケージ
  const unknownPackages = signals.importedPackages.filter(
    pkg => !ALLOWED_PACKAGES.some(allowed => pkg.startsWith(allowed))
  )
  score += unknownPackages.length * 20

  // 外部ドメイン参照（許可リスト外）
  score += signals.referencedDomains.length * 25

  return Math.min(score, 100)
}

/**
 * 判定基準:
 * - score >= 70: 拒否
 * - 50 <= score < 70: 要人的レビュー
 * - score < 50: 自動承認
 */
export function getSecurityVerdict(score: number): 'REJECT' | 'REVIEW' | 'APPROVE' {
  if (score >= 70) return 'REJECT'
  if (score >= 50) return 'REVIEW'
  return 'APPROVE'
}
