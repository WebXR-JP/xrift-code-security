import type { FileContext } from '../types.js'

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

  // 3. バンドルされた依存ライブラリ（その他の*.js）
  const isBundledDependency =
    !isUserCode &&
    !isSharedLibrary &&
    !fileName.includes('__federation_fn_import') &&
    fileName !== 'remoteEntry.js'

  return {
    filePath: fileName,
    isUserCode,
    isSharedLibrary,
    isBundledDependency
  }
}

/**
 * ファイルコンテキストに基づいて違反の重大度を調整
 */
export function adjustViolationSeverity(
  rule: string,
  originalSeverity: 'critical' | 'warning',
  context: FileContext
): 'critical' | 'warning' {
  // ユーザーコードは常に厳格
  if (context.isUserCode) {
    return originalSeverity
  }

  // __federation_fn_import は常に厳格
  const fileName = context.filePath
  if (fileName.includes('__federation_fn_import')) {
    return originalSeverity
  }

  // 共有ライブラリ、バンドル依存、remoteEntryは一部のルールを緩和
  const isRemoteEntry = fileName === 'remoteEntry.js'
  if (context.isSharedLibrary || context.isBundledDependency || isRemoteEntry) {
    const technicalViolations = [
      'no-obfuscation',
      'no-dangerous-dom',
      'no-navigator-access',
      'no-prototype-pollution',
      'no-global-override',
      'no-network-without-permission',
    ]

    if (technicalViolations.includes(rule)) {
      return 'warning'
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
    return '共有ライブラリ（Module Federation自動生成、一部ルールを緩和）'
  }
  if (context.isBundledDependency) {
    return 'バンドルされた依存ライブラリ（技術的違反を緩和）'
  }
  const fileName = context.filePath
  if (fileName === 'remoteEntry.js') {
    return 'Module Federationエントリーポイント（Module Federation自動生成、一部ルールを緩和）'
  }
  if (fileName.includes('__federation_fn_import')) {
    return 'Module Federation動的インポート（厳格に検証）'
  }
  return 'その他のファイル（標準的な検証）'
}
