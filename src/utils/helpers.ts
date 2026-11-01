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
 * ICE サーバー（STUN/TURN）の URL かどうか
 */
export function isIceServerUrl(url: string): boolean {
  return /^(stuns?|turns?):/i.test(url)
}

/**
 * ICE サーバーの URL（stun:host:port, turns:host?transport=tcp など）からホスト名を抽出
 * 特殊スキームではないため new URL() ではホスト名が取れない
 */
export function extractIceServerHost(url: string): string | null {
  const rest = url
    .replace(/^(stuns?|turns?):/i, '')
    .replace(/^\/\//, '')
    .split('?')[0]
  if (rest.startsWith('[')) {
    const end = rest.indexOf(']')
    return end > 1 ? rest.slice(0, end + 1).toLowerCase() : null
  }
  const host = rest.split(':')[0]
  return host ? host.toLowerCase() : null
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
 * 許可されたドメイン（CDN・標準仕様）
 */
export const ALLOWED_DOMAINS = [
  'cdn.jsdelivr.net',
  'unpkg.com',
  'esm.sh',
  'immersiveweb.dev',   // W3C Immersive Web: WebXR 機能記述子 URL として使用
]
