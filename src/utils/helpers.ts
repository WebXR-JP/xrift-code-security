import type { Node } from 'acorn'

/**
 * シャノンエントロピーを計算（0-8の範囲）
 */
export function calculateEntropy(str: string): number {
  if (str.length === 0) return 0

  const frequency: Record<string, number> = {}
  for (const char of str) {
    frequency[char] = (frequency[char] || 0) + 1
  }

  let entropy = 0
  for (const char in frequency) {
    const p = frequency[char] / str.length
    entropy -= p * Math.log2(p)
  }

  return entropy
}

/**
 * 文字列配列の平均エントロピーを計算
 */
export function calculateAverageEntropy(strings: string[]): number {
  if (strings.length === 0) return 0

  const entropies = strings
    .filter(s => s.length > 20) // 20文字以上の文字列のみ対象
    .map(calculateEntropy)

  return entropies.length > 0
    ? entropies.reduce((a, b) => a + b, 0) / entropies.length
    : 0
}

/**
 * URL文字列からドメイン名を抽出
 */
export function extractDomains(urls: string[]): string[] {
  return urls
    .map(url => {
      try {
        return new URL(url).hostname
      } catch {
        return null
      }
    })
    .filter((domain): domain is string => domain !== null)
}

/**
 * CallExpressionの呼び出し先名を取得
 */
export function getCalleeName(callee: any): string | null {
  if (callee.type === 'Identifier') {
    return callee.name
  }
  if (callee.type === 'MemberExpression') {
    const property = callee.property
    if (property.type === 'Identifier') {
      return property.name
    }
  }
  return null
}

/**
 * ASTノードから位置情報を取得
 */
export function getLocation(node: Node): { line: number; column: number; code: string } | undefined {
  if (!node.loc) return undefined

  return {
    line: node.loc.start.line,
    column: node.loc.start.column,
    code: '(code snippet)'
  }
}

/**
 * 許可されたパッケージリスト
 */
export const ALLOWED_PACKAGES = [
  'react',
  'react-dom',
  'three',
  '@react-three/fiber',
  '@react-three/rapier',
  '@react-three/drei',
  '@xrift/world-sdk',
]

/**
 * 許可されたドメイン（CDN）
 */
export const ALLOWED_DOMAINS = [
  'cdn.jsdelivr.net',
  'unpkg.com',
  'esm.sh',
]

/**
 * バンドル依存として認識する既知ライブラリのファイル名パターン
 * ここに一致しないファイルは未知のファイルとして扱い、技術的違反の抑制対象外とする
 */
/**
 * Viteのバンドルハッシュサフィックス: -{hash}.js
 * 例: rapier-BEkZi1Ii.js, hls-BIqz-PrE.js
 */
const VITE_HASH_SUFFIX = '-[a-zA-Z0-9_-]{8}\\.js$'

/**
 * 既知の非ハッシュサフィックス（.min.js, .module.js 等）
 */
const KNOWN_SUFFIXES = '(?:\\.min|\\.module|_wasm|_bg|_decoder|_transcoder|_workers|_backend|_tasks|_bundle|_module|-es|-worker|-webgl)(?:-[a-zA-Z0-9_-]{8})?\\.js$'

export const KNOWN_LIBRARY_PATTERNS: RegExp[] = [
  // Three.js ecosystem
  new RegExp(`^three(?:${KNOWN_SUFFIXES}|${VITE_HASH_SUFFIX})`),
  new RegExp(`^draco(?:${KNOWN_SUFFIXES}|${VITE_HASH_SUFFIX})`),
  new RegExp(`^basis(?:${KNOWN_SUFFIXES}|${VITE_HASH_SUFFIX})`),
  // Physics engines
  new RegExp(`^rapier(?:${KNOWN_SUFFIXES}|${VITE_HASH_SUFFIX})`),
  new RegExp(`^cannon(?:${KNOWN_SUFFIXES}|${VITE_HASH_SUFFIX})`),
  new RegExp(`^ammo(?:${KNOWN_SUFFIXES}|${VITE_HASH_SUFFIX})`),
  // Media processing
  new RegExp(`^hls(?:${KNOWN_SUFFIXES}|${VITE_HASH_SUFFIX})`),
  new RegExp(`^mediapipe(?:${KNOWN_SUFFIXES}|${VITE_HASH_SUFFIX})`),
  new RegExp(`^vision_bundle(?:${KNOWN_SUFFIXES}|${VITE_HASH_SUFFIX})`),
  new RegExp(`^tfjs(?:${KNOWN_SUFFIXES}|${VITE_HASH_SUFFIX})`),
  // Google 3D Tiles (3d-tiles-renderer)
  new RegExp(`^GoogleTilesInner${VITE_HASH_SUFFIX}`),
  // Other 3D/WebXR libraries
  new RegExp(`^cesium(?:${KNOWN_SUFFIXES}|${VITE_HASH_SUFFIX})`),
  new RegExp(`^potpack(?:${KNOWN_SUFFIXES}|${VITE_HASH_SUFFIX})`),
  // Vite internal
  /^__vite-browser-external(?:-[a-zA-Z0-9_-]+)?\.js$/,
  // Vite helpers
  /^_commonjsHelpers-[a-zA-Z0-9_-]+\.js$/,
]

/**
 * ファイル名が既知ライブラリパターンに一致するかを判定
 */
export function matchesKnownLibraryPattern(fileName: string): boolean {
  return KNOWN_LIBRARY_PATTERNS.some(pattern => pattern.test(fileName))
}
