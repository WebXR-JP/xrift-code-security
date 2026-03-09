import type { FileContext } from '../types.js'
import { matchesKnownLibraryPattern } from './helpers.js'

/**
 * ファイルパスからコンテキストを判定
 *
 * 判定ロジック:
 * - __federation_expose_World: ユーザーコード (最も厳格)
 * - __federation_shared_: 共有ライブラリ (Module Federationが自動生成、緩和可能)
 * - __federation_fn_import: Module Federationインフラ (厳格)
 * - remoteEntry.js: Module Federationエントリーポイント (Module Federationが自動生成、緩和可能)
 * - その他: バンドルされた依存ライブラリ (緩和可能)
 */
export function determineFileContext(filePath: string): FileContext {
  const fileName = filePath.split('/').pop() || filePath

  // 1. ユーザーコード（__federation_expose_World-*.js）
  const isUserCode = fileName.includes('__federation_expose_World-') && fileName.endsWith('.js')

  // 2. 共有ライブラリ（__federation_shared_*/*.js）
  const isSharedLibrary =
    fileName.startsWith('__federation_shared_') ||
    filePath.includes('__federation_shared_')

  // 3. バンドルされた依存ライブラリ（既知パターンに一致する*.jsのみ）
  const isBundledDependency =
    !isUserCode &&
    !isSharedLibrary &&
    !fileName.includes('__federation_fn_import') &&
    fileName !== 'remoteEntry.js' &&
    matchesKnownLibraryPattern(fileName)

  return {
    filePath: fileName,
    isUserCode,
    isSharedLibrary,
    isBundledDependency
  }
}

/**
 * ファイルコンテキストに基づいて違反の重大度を調整
 * null を返した場合、その違反は完全に抑制される（誤検知として除外）
 */
export function adjustViolationSeverity(
  rule: string,
  originalSeverity: 'critical' | 'warning',
  context: FileContext
): 'critical' | 'warning' | null {
  // ユーザーコードは常に厳格
  if (context.isUserCode) {
    return originalSeverity
  }

  // __federation_fn_import は常に厳格
  const fileName = context.filePath
  if (fileName.includes('__federation_fn_import')) {
    return originalSeverity
  }

  // remoteEntry.js: Module Federationの仕様上必須の動作は完全抑制
  const isRemoteEntry = fileName === 'remoteEntry.js'
  if (isRemoteEntry) {
    const suppressedForRemoteEntry = [
      'no-global-override',
      'no-dangerous-dom',
    ]
    if (suppressedForRemoteEntry.includes(rule)) {
      return null
    }
  }

  // Vite preload-helper: document.head へのプリロード追加は標準動作のため完全抑制
  const isPreloadHelper = fileName.startsWith('preload-helper')
  if (isPreloadHelper) {
    if (rule === 'no-dangerous-dom') {
      return null
    }
  }

  // 共有ライブラリ、バンドル依存、remoteEntryは技術的違反を段階的に抑制
  // 開発者が修正できないバンドルコードの warning はノイズになるため
  if (context.isSharedLibrary || context.isBundledDependency || isRemoteEntry) {
    // 低リスク技術的違反: バンドルコードで頻出し、直接的な攻撃リスクが低いため完全抑制
    const lowRiskViolations = [
      'no-obfuscation',
      'no-navigator-access',
      'no-prototype-pollution',
      'no-global-override',
    ]

    if (lowRiskViolations.includes(rule)) {
      return null
    }

    // 高リスク技術的違反: 攻撃に直結しうるため、バンドル依存でも抑制しない
    const highRiskViolations = [
      'no-network-without-permission',
      'no-dangerous-dom',
    ]

    if (highRiskViolations.includes(rule)) {
      return originalSeverity
    }

    const criticalViolations = [
      'no-eval',
      'no-storage-access',
      'no-storage-event',
    ]

    if (criticalViolations.includes(rule)) {
      return 'critical'
    }
  }

  return originalSeverity
}

/**
 * ファイルコンテキストの説明を生成（デバッグ用）
 */
export function describeFileContext(context: FileContext): string {
  if (context.isUserCode) {
    return 'ユーザーコード（最も厳格に検証）'
  }
  if (context.isSharedLibrary) {
    return '共有ライブラリ（Module Federation自動生成、技術的違反を抑制）'
  }
  if (context.isBundledDependency) {
    return 'バンドルされた依存ライブラリ（低リスク技術的違反を抑制、高リスク違反は検出）'
  }
  const fileName = context.filePath
  if (fileName === 'remoteEntry.js') {
    return 'Module Federationエントリーポイント（Module Federation自動生成、低リスク技術的違反を抑制）'
  }
  if (fileName.includes('__federation_fn_import')) {
    return 'Module Federation動的インポート（厳格に検証）'
  }
  return '未知のファイル（既知ライブラリパターンに一致しないため、すべての違反を検出）'
}
