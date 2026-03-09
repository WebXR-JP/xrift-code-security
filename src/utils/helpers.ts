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
export const KNOWN_LIBRARY_PATTERNS: RegExp[] = [
  // Three.js ecosystem
  /^three[-.].*\.js$/,
  /^draco[-_].*\.js$/,
  /^basis[-_].*\.js$/,
  // Physics engines
  /^rapier[-_].*\.js$/,
  /^cannon[-_].*\.js$/,
  /^ammo[-_].*\.js$/,
  // Media processing
  /^hls[-.].*\.js$/,
  /^mediapipe[-_].*\.js$/,
  /^vision[-_]bundle[-_].*\.js$/,
  /^tfjs[-_].*\.js$/,
  // Google 3D Tiles (3d-tiles-renderer)
  /^GoogleTiles.*\.js$/,
  // Other 3D/WebXR libraries
  /^cesium[-_].*\.js$/,
  /^potpack[-_].*\.js$/,
  // Vite internal
  /^__vite[-_].*\.js$/,
]

/**
 * ファイル名が既知ライブラリパターンに一致するかを判定
 */
export function matchesKnownLibraryPattern(fileName: string): boolean {
  return KNOWN_LIBRARY_PATTERNS.some(pattern => pattern.test(fileName))
}
