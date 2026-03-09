import * as acorn from 'acorn'
import * as walk from 'acorn-walk'
import type {
  SecuritySignals,
  CodePermissions
} from './types.js'
import {
  calculateEntropy,
  calculateAverageEntropy,
  extractDomains,
  getCalleeName,
  getLocation,
  ALLOWED_DOMAINS
} from './utils/helpers.js'

/**
 * エントロピー閾値
 * GLSLシェーダーや複雑な正規のコードを許容するため7.0に設定
 */
const ENTROPY_THRESHOLD = 7.0

/**
 * プロトタイプ汚染として検出すべき組み込みオブジェクト
 * MyClass.prototype.method = ... のようなクラス定義パターンは対象外
 */
const BUILTIN_PROTOTYPES = [
  'Object', 'Array', 'String', 'Number', 'Boolean',
  'Function', 'RegExp', 'Date', 'Promise',
  'Map', 'Set', 'WeakMap', 'WeakSet', 'Error',
]

/**
 * 疑わしい変数名チェックから除外する既知の安全な変数名
 * React DevTools、webpack、Vite 等のビルドツールが使用する標準的なグローバル変数
 */
const KNOWN_SAFE_VARIABLES = [
  '__REACT_DEVTOOLS_GLOBAL_HOOK__',
  '__webpack_require__',
  '__webpack_modules__',
  '__webpack_exports__',
  '__webpack_module_cache__',
  '__vite_ssr_import__',
  '__vite_ssr_dynamic_import__',
  '__vite_ssr_exportAll__',
  '__vite_ssr_export__',
]

/**
 * セキュリティ上重要な API（サプライチェーン攻撃で改ざんされると危険）
 * これらの window.xxx = ... はバンドル依存でも絶対に抑制しない
 */
const SENSITIVE_APIS = [
  'fetch', 'XMLHttpRequest', 'WebSocket',
  'setTimeout', 'setInterval',
  'eval', 'Function',
  'console', 'alert', 'prompt', 'confirm',
  'sendBeacon',
]

/**
 * Violationオブジェクトを作成するヘルパー関数
 */
function createViolation(
  rule: string,
  severity: 'critical' | 'warning',
  message: string,
  node?: acorn.Node
): any {
  const location = node ? getLocation(node) : undefined
  return {
    rule,
    severity,
    message,
    ...(location && { location }),
  }
}

/**
 * コードのセキュリティ解析を実行
 */
export function analyzeCodeSecurity(
  code: string,
  permissions?: CodePermissions
): SecuritySignals {
  const ast = acorn.parse(code, {
    ecmaVersion: 'latest',
    sourceType: 'module',
    locations: true,
  })

  const signals: SecuritySignals = {
    hasEval: false,
    hasDynamicCodeExecution: false,
    hasNetworkAPI: false,
    hasNetworkWithoutPermission: false,
    hasDynamicURLConstruction: false,
    hasObfuscatedCode: false,
    hasGlobalVariableOverride: false,
    hasStorageAccess: false,
    hasNavigatorAccess: false,
    hasDangerousDOMManipulation: false,
    entropy: 0,
    suspiciousVariableNames: false,
    importedPackages: [],
    referencedDomains: [],
    detectedViolations: [],
  }

  const urlStrings: string[] = []
  const stringLiterals: string[] = []
  const variableNames: string[] = []

  walk.ancestor(ast, {
    // 1. コード実行系
    CallExpression(node: any, ancestors: acorn.Node[]) {
      const calleeName = getCalleeName(node.callee)

      // eval検出
      if (calleeName === 'eval') {
        signals.hasEval = true
        signals.detectedViolations.push(createViolation(
          'no-eval',
          'critical',
          'eval()の使用は禁止されています',
          node
        ))
      }

      // setTimeout/setInterval の文字列引数
      if (['setTimeout', 'setInterval'].includes(calleeName || '')) {
        const firstArg = node.arguments[0]
        if (firstArg?.type === 'Literal' && typeof firstArg.value === 'string') {
          signals.hasDynamicCodeExecution = true
          signals.detectedViolations.push(createViolation(
            'no-string-timeout',
            'critical',
            `${calleeName}に文字列を渡すことは禁止されています`,
            node
          ))
        }
      }

      // ネットワークAPI検出
      if (['fetch', 'XMLHttpRequest'].includes(calleeName || '')) {
        // 引数からURL抽出
        const urlArg = node.arguments[0]
        if (urlArg?.type === 'Literal' && typeof urlArg.value === 'string') {
          const urlValue = urlArg.value as string
          // .wasm ファイルの読み込みはWASMライブラリの標準的な初期化処理のため除外
          if (!urlValue.endsWith('.wasm')) {
            signals.hasNetworkAPI = true
            urlStrings.push(urlValue)
          }
        } else {
          signals.hasNetworkAPI = true
          // 動的URL構築の疑い
          signals.hasDynamicURLConstruction = true
        }
      }

      // WebSocket検出
      if (calleeName === 'WebSocket') {
        signals.hasNetworkAPI = true
        const urlArg = node.arguments[0]
        if (urlArg?.type === 'Literal' && typeof urlArg.value === 'string') {
          urlStrings.push(urlArg.value)
        }
      }

      // navigator.sendBeacon検出
      if (node.callee.type === 'MemberExpression') {
        const obj = node.callee.object
        const prop = node.callee.property

        if (
          obj?.type === 'Identifier' &&
          obj.name === 'navigator' &&
          prop?.type === 'Identifier' &&
          prop.name === 'sendBeacon'
        ) {
          signals.hasNetworkAPI = true
          signals.hasNavigatorAccess = true
          signals.detectedViolations.push(createViolation(
            'no-navigator-access',
            'critical',
            'navigator.sendBeacon()の使用は禁止されています',
            node
          ))
        }
      }

      // 危険なDOM操作メソッド検出
      if (['insertAdjacentHTML'].includes(calleeName || '')) {
        signals.hasDangerousDOMManipulation = true
        signals.detectedViolations.push(createViolation(
          'no-dangerous-dom',
          'critical',
          `${calleeName}()の使用は禁止されています（XSS攻撃のリスク）`,
          node
        ))
      }

      // document.createElement('script') / document.createElement('iframe')
      if (calleeName === 'createElement' && node.callee.type === 'MemberExpression') {
        const obj = node.callee.object
        if (obj?.type === 'Identifier' && obj.name === 'document') {
          const tagArg = node.arguments[0]
          if (tagArg?.type === 'Literal' && typeof tagArg.value === 'string') {
            const tagName = tagArg.value.toLowerCase()
            if (['script', 'iframe'].includes(tagName)) {
              signals.hasDangerousDOMManipulation = true
              signals.detectedViolations.push(createViolation(
                'no-dangerous-dom',
                'critical',
                `document.createElement('${tagName}')の使用は禁止されています`,
                node
              ))
            }
          }
        }
      }

      // 難読化検出（Critical）
      if (['atob', 'btoa', 'unescape', 'decodeURIComponent'].includes(calleeName || '')) {
        signals.hasObfuscatedCode = true
        signals.detectedViolations.push(createViolation(
          'no-obfuscation',
          'critical',
          `難読化関数 ${calleeName}() の使用は禁止されています`,
          node
        ))
      }

      // String.fromCharCode検出
      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.object.type === 'Identifier' &&
        node.callee.object.name === 'String' &&
        node.callee.property.type === 'Identifier' &&
        node.callee.property.name === 'fromCharCode'
      ) {
        signals.hasObfuscatedCode = true
        signals.detectedViolations.push(createViolation(
          'no-obfuscation',
          'critical',
          'String.fromCharCode()の使用は禁止されています',
          node
        ))
      }

      // addEventListener('storage', ...) 検出
      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.property.type === 'Identifier' &&
        node.callee.property.name === 'addEventListener'
      ) {
        const firstArg = node.arguments[0]
        if (firstArg?.type === 'Literal' && typeof firstArg.value === 'string' && firstArg.value === 'storage') {
          signals.hasStorageAccess = true
          signals.detectedViolations.push(createViolation(
            'no-storage-event',
            'critical',
            "addEventListener('storage', ...)の使用は禁止されています（トークン傍受のリスク）",
            node
          ))
        }
      }
    },

    // 2. グローバル変数改ざん
    AssignmentExpression(node: any, _ancestors: acorn.Node[]) {
      const left = node.left

      // window.xxx = ... 検出
      if (
        left.type === 'MemberExpression' &&
        left.object.type === 'Identifier' &&
        ['window', 'globalThis', 'document', 'navigator'].includes(left.object.name)
      ) {
        const propertyName = left.property.type === 'Identifier'
          ? left.property.name
          : null

        signals.hasGlobalVariableOverride = true

        if (left.object.name === 'navigator') {
          signals.hasNavigatorAccess = true
        }

        if (propertyName && SENSITIVE_APIS.includes(propertyName)) {
          // センシティブ API オーバーライド → バンドル依存でも絶対に抑制されない
          signals.detectedViolations.push(createViolation(
            'no-sensitive-api-override',
            'critical',
            `セキュリティ上重要な API ${left.object.name}.${propertyName} の改ざんは禁止されています`,
            node
          ))
        } else {
          // カスタムグローバル設定 → 既存ルール（バンドル依存で抑制可能）
          signals.detectedViolations.push(createViolation(
            'no-global-override',
            'critical',
            `グローバルオブジェクト ${left.object.name} の改ざんは禁止されています`,
            node
          ))
        }
      }

      // Object.prototype.xxx = ... 検出（組み込みオブジェクトのみ）
      if (
        left.type === 'MemberExpression' &&
        left.object.type === 'MemberExpression' &&
        left.object.property.type === 'Identifier' &&
        left.object.property.name === 'prototype' &&
        left.object.object.type === 'Identifier' &&
        BUILTIN_PROTOTYPES.includes(left.object.object.name)
      ) {
        signals.hasGlobalVariableOverride = true
        signals.detectedViolations.push(createViolation(
          'no-prototype-pollution',
          'critical',
          `${left.object.object.name}.prototypeの汚染は禁止されています`,
          node
        ))
      }

      // onstorage への代入検出
      if (
        left.type === 'MemberExpression' &&
        left.property.type === 'Identifier' &&
        left.property.name === 'onstorage'
      ) {
        signals.hasStorageAccess = true
        signals.detectedViolations.push(createViolation(
          'no-storage-event',
          'critical',
          'onstorageへの代入は禁止されています（トークン傍受のリスク）',
          node
        ))
      }
    },

    // 3. ストレージアクセス & Navigator アクセス & DOM操作
    MemberExpression(node: any, ancestors: acorn.Node[]) {
      const objectName = node.object.type === 'Identifier'
        ? node.object.name
        : null
      const propertyName = node.property.type === 'Identifier'
        ? node.property.name
        : null

      // localStorage/sessionStorage検出
      if (['localStorage', 'sessionStorage'].includes(objectName || '')) {
        signals.hasStorageAccess = true
        signals.detectedViolations.push(createViolation(
          'no-storage-access',
          'critical',
          `${objectName}へのアクセスは禁止されています`,
          node
        ))
      }

      // document.cookie検出
      if (objectName === 'document' && propertyName === 'cookie') {
        signals.hasStorageAccess = true
        signals.detectedViolations.push(createViolation(
          'no-cookie-access',
          'critical',
          'Cookieへのアクセスは禁止されています',
          node
        ))
      }

      // indexedDB検出
      if (objectName === 'indexedDB') {
        signals.hasStorageAccess = true
        signals.detectedViolations.push(createViolation(
          'no-indexeddb-access',
          'critical',
          'IndexedDBへのアクセスは禁止されています',
          node
        ))
      }

      // navigator.* すべてを禁止
      if (objectName === 'navigator') {
        signals.hasNavigatorAccess = true
        signals.detectedViolations.push(createViolation(
          'no-navigator-access',
          'critical',
          `navigator.${propertyName || '*'}へのアクセスは禁止されています（フィンガープリンティング防止）`,
          node
        ))
      }

      // innerHTML / outerHTML への書き込み検出
      if (['innerHTML', 'outerHTML'].includes(propertyName || '')) {
        // 親がAssignmentExpressionで、leftがこのMemberExpressionの場合
        const parent = ancestors[ancestors.length - 2]
        if (parent?.type === 'AssignmentExpression' && (parent as any).left === node) {
          signals.hasDangerousDOMManipulation = true
          signals.detectedViolations.push(createViolation(
            'no-dangerous-dom',
            'critical',
            `${propertyName}への代入は禁止されています（XSS攻撃のリスク）`,
            node
          ))
        }
      }

      // document.head への要素追加検出
      if (objectName === 'document' && propertyName === 'head') {
        signals.hasDangerousDOMManipulation = true
        signals.detectedViolations.push(createViolation(
          'no-dangerous-dom',
          'critical',
          'document.headへのアクセスは禁止されています（スクリプト注入のリスク）',
          node
        ))
      }
    },

    // 4. インポート解析
    ImportDeclaration(node: any, _ancestors: acorn.Node[]) {
      const source = node.source.value
      signals.importedPackages.push(source)

      // 外部URL import検出
      if (source.startsWith('http://') || source.startsWith('https://')) {
        signals.detectedViolations.push(createViolation(
          'no-external-import',
          'critical',
          '外部URLからのimportは禁止されています',
          node
        ))
      }
    },

    // 5. 変数名収集
    Identifier(node: any, ancestors: acorn.Node[]) {
      variableNames.push(node.name)

      // navigator 変数への直接参照も検出
      if (node.name === 'navigator') {
        const parent = ancestors[ancestors.length - 2]
        if (parent?.type !== 'MemberExpression' || (parent as any).object !== node) {
          signals.hasNavigatorAccess = true
          signals.detectedViolations.push(createViolation(
            'no-navigator-access',
            'critical',
            'navigatorオブジェクトへのアクセスは禁止されています',
            node
          ))
        }
      }
    },

    // 6. 文字列リテラル収集（StringLiteral → Literal + string ガード）
    Literal(node: any, _ancestors: acorn.Node[]) {
      if (typeof node.value !== 'string') return

      stringLiterals.push(node.value)

      // 16進数エスケープ・Unicodeエスケープの検出
      const value = node.value
      if (/\\x[0-9a-fA-F]{2}/.test(value) || /\\u[0-9a-fA-F]{4}/.test(value)) {
        signals.hasObfuscatedCode = true
        signals.detectedViolations.push(createViolation(
          'no-obfuscation',
          'critical',
          '16進数/Unicodeエスケープによる難読化は禁止されています',
          node
        ))
      }
    },
  })

  // エントロピー計算
  signals.entropy = calculateAverageEntropy(stringLiterals)

  // 高エントロピー文字列の検出（Critical）
  if (signals.entropy > ENTROPY_THRESHOLD) {
    signals.hasObfuscatedCode = true
    signals.detectedViolations.push(createViolation(
      'no-obfuscation',
      'critical',
      `文字列のエントロピーが異常に高い（${signals.entropy.toFixed(2)}）- 難読化の疑い`
    ))
  }

  // 疑わしい変数名チェック（Critical）
  // 既知の安全な変数名（React DevTools, webpack, Vite等）は除外
  const suspiciousVars = variableNames.filter(
    name => /^[_$][a-zA-Z0-9_$]{4,}$/.test(name) &&
            calculateEntropy(name) > 3.5 &&
            !KNOWN_SAFE_VARIABLES.includes(name)
  )
  if (suspiciousVars.length > 0) {
    signals.hasObfuscatedCode = true
    signals.suspiciousVariableNames = true
    signals.detectedViolations.push(createViolation(
      'no-obfuscation',
      'critical',
      `疑わしい変数名が検出されました: ${suspiciousVars.slice(0, 3).join(', ')}...`
    ))
  }

  // URL解析
  signals.referencedDomains = extractDomains(urlStrings)

  // 権限チェック
  if (signals.hasNetworkAPI) {
    const allowedDomains = permissions?.network?.allowedDomains || []
    const unauthorizedDomains = signals.referencedDomains.filter(
      domain => !allowedDomains.includes(domain) && !ALLOWED_DOMAINS.includes(domain)
    )

    // リテラル URL で非許可ドメイン → バンドル依存でも絶対に抑制されない
    if (unauthorizedDomains.length > 0) {
      signals.hasNetworkWithoutPermission = true
      signals.detectedViolations.push(createViolation(
        'no-unauthorized-domain',
        'critical',
        `許可されていないドメインへのネットワーク通信: ${unauthorizedDomains.join(', ')}`
      ))
    }

    // 動的 URL → 既存ルール（バンドル依存で抑制可能）
    if (signals.hasDynamicURLConstruction) {
      signals.hasNetworkWithoutPermission = true
      signals.detectedViolations.push(createViolation(
        'no-network-without-permission',
        'critical',
        'ネットワーク通信にはxrift.config.tsでの権限宣言が必要です'
      ))
    }
  }

  return signals
}
