import type { FileContext } from '../types.js'

/**
 * ホストが提供するプラットフォーム共有パッケージ
 * これらの __federation_shared_* ファイルのみスキャン対象から除外される
 */
export const PLATFORM_SHARED_PACKAGES = [
  'react',
  'react-dom',
  'three',
  '@react-three/fiber',
  '@react-three/drei',
  '@react-three/rapier',
  '@xrift/world-components',
]

/**
 * ファイルパスがプラットフォーム共有パッケージに該当するか判定
 */
function isKnownSharedPackage(filePath: string): boolean {
  const prefix = '__federation_shared_'
  const idx = filePath.indexOf(prefix)
  if (idx === -1) return false

  const afterPrefix = filePath.substring(idx + prefix.length)
  return PLATFORM_SHARED_PACKAGES.some(pkg =>
    afterPrefix === pkg ||
    afterPrefix.startsWith(pkg + '/') ||
    afterPrefix.startsWith(pkg + '-')
  )
}

/**
 * ファイルパスからコンテキストを判定
 *
 * 判定ロジック:
 * - __federation_expose_World: ユーザーコード (最も厳格)
 * - __federation_shared_ + 既知パッケージ: 共有ライブラリ (ホスト提供、スキャン除外)
 * - __federation_fn_import: Module Federationインフラ (厳格)
 * - remoteEntry.js: Module Federationエントリーポイント (Module Federationが自動生成、緩和可能)
 * - その他: バンドルされた依存ライブラリ (緩和可能)
 */
export function determineFileContext(filePath: string): FileContext {
  const fileName = filePath.split('/').pop() || filePath

  // 1. ユーザーコード（__federation_expose_World-*.js）
  const isUserCode = fileName.includes('__federation_expose_World-') && fileName.endsWith('.js')

  // 2. 共有ライブラリ（既知のプラットフォーム共有パッケージのみ）
  const isSharedLibrary = isKnownSharedPackage(filePath)

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
 * null を返した場合、その違反は完全に抑制される（誤検知として除外）
 */
export function adjustViolationSeverity(
  rule: string,
  originalSeverity: 'critical' | 'warning',
  context: FileContext
): 'critical' | 'warning' | null {
  // センシティブ API オーバーライドと非許可ドメインは、どのファイルコンテキストでも絶対に抑制しない
  const neverSuppressRules = [
    'no-sensitive-api-override',
    'no-unauthorized-domain',
    'no-rtc-connection',
  ]
  if (neverSuppressRules.includes(rule)) {
    return originalSeverity
  }

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

  // 共有ライブラリ、バンドル依存、remoteEntryは技術的違反を完全抑制
  // 開発者が修正できないバンドルコードの warning はノイズになるため
  if (context.isSharedLibrary || context.isBundledDependency || isRemoteEntry) {
    const technicalViolations = [
      'no-obfuscation',
      'no-dangerous-dom',
      'no-javascript-blob',
      'no-navigator-access',
      'no-prototype-pollution',
      'no-global-override',
      'no-network-without-permission',
      'no-new-function',
    ]

    if (technicalViolations.includes(rule)) {
      return null
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
    return 'バンドルされた依存ライブラリ（技術的違反を抑制）'
  }
  const fileName = context.filePath
  if (fileName === 'remoteEntry.js') {
    return 'Module Federationエントリーポイント（Module Federation自動生成、技術的違反を抑制）'
  }
  if (fileName.includes('__federation_fn_import')) {
    return 'Module Federation動的インポート（厳格に検証）'
  }
  return 'その他のファイル（標準的な検証）'
}
