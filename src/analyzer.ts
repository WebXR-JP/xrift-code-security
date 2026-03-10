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
 * navigator のうちセキュリティ上危険なプロパティ
 * これらのみ no-navigator-access として検出する。
 * navigator.xr 等の正当利用は許可する。
 */
const DANGEROUS_NAVIGATOR_PROPERTIES = [
  'sendBeacon',       // データ外部送信
  'geolocation',      // 位置情報取得
  'credentials',      // 認証情報アクセス
  'mediaDevices',     // カメラ・マイクアクセス
  'clipboard',        // クリップボード操作
  'serviceWorker',    // ServiceWorker登録
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

      // setTimeout/setInterval の文字列引数 (A11: TemplateLiteral も検出)
      if (['setTimeout', 'setInterval'].includes(calleeName || '')) {
        const firstArg = node.arguments[0]
        if (
          (firstArg?.type === 'Literal' && typeof firstArg.value === 'string') ||
          firstArg?.type === 'TemplateLiteral'
        ) {
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

      // A1: 間接eval (0, eval)(...) 検出
      if (
        node.callee.type === 'SequenceExpression' &&
        node.callee.expressions.length >= 2
      ) {
        const lastExpr = node.callee.expressions[node.callee.expressions.length - 1]
        if (lastExpr.type === 'Identifier' && lastExpr.name === 'eval') {
          signals.hasEval = true
          signals.detectedViolations.push(createViolation(
            'no-eval',
            'critical',
            '間接eval (0, eval)() の使用は禁止されています',
            node
          ))
        }
      }

      // A2: .constructor.constructor(...) チェーン検出
      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.property.type === 'Identifier' &&
        node.callee.property.name === 'constructor' &&
        node.callee.object.type === 'MemberExpression' &&
        node.callee.object.property.type === 'Identifier' &&
        node.callee.object.property.name === 'constructor'
      ) {
        signals.hasEval = true
        signals.hasDynamicCodeExecution = true
        signals.detectedViolations.push(createViolation(
          'no-eval',
          'critical',
          '.constructor.constructor() による間接的なコード実行は禁止されています',
          node
        ))
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

      // A3: fetch.call()/fetch.apply()/fetch.bind() 検出
      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.property.type === 'Identifier' &&
        ['call', 'apply', 'bind'].includes(node.callee.property.name) &&
        node.callee.object.type === 'Identifier' &&
        SENSITIVE_APIS.includes(node.callee.object.name)
      ) {
        signals.detectedViolations.push(createViolation(
          'no-sensitive-api-override',
          'critical',
          `${node.callee.object.name}.${node.callee.property.name}() によるセンシティブ API の間接呼び出しは禁止されています`,
          node
        ))
      }

      // A4: Reflect.apply(fetch, ...) 検出
      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.object.type === 'Identifier' &&
        node.callee.object.name === 'Reflect' &&
        node.callee.property.type === 'Identifier' &&
        node.callee.property.name === 'apply'
      ) {
        const firstArg = node.arguments[0]
        if (firstArg?.type === 'Identifier' && SENSITIVE_APIS.includes(firstArg.name)) {
          signals.detectedViolations.push(createViolation(
            'no-sensitive-api-override',
            'critical',
            `Reflect.apply(${firstArg.name}, ...) によるセンシティブ API の間接呼び出しは禁止されています`,
            node
          ))
        }
      }

      // A5: Object.assign(window/globalThis, {fetch: ...}) 検出
      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.object.type === 'Identifier' &&
        node.callee.object.name === 'Object' &&
        node.callee.property.type === 'Identifier' &&
        node.callee.property.name === 'assign'
      ) {
        const targetArg = node.arguments[0]
        const sourceArg = node.arguments[1]
        if (
          targetArg?.type === 'Identifier' &&
          ['window', 'globalThis', 'self'].includes(targetArg.name) &&
          sourceArg?.type === 'ObjectExpression'
        ) {
          for (const prop of sourceArg.properties) {
            const propName = prop.key?.type === 'Identifier' ? prop.key.name
              : (prop.key?.type === 'Literal' && typeof prop.key.value === 'string') ? prop.key.value
              : null
            if (propName && SENSITIVE_APIS.includes(propName)) {
              signals.hasGlobalVariableOverride = true
              signals.detectedViolations.push(createViolation(
                'no-sensitive-api-override',
                'critical',
                `Object.assign(${targetArg.name}, {${propName}: ...}) によるセンシティブ API の改ざんは禁止されています`,
                node
              ))
            } else if (propName) {
              signals.hasGlobalVariableOverride = true
              signals.detectedViolations.push(createViolation(
                'no-global-override',
                'critical',
                `Object.assign(${targetArg.name}, ...) によるグローバルオブジェクトの改ざんは禁止されています`,
                node
              ))
            }
          }
        }
      }

      // A8: document.write / document.writeln 検出
      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.object.type === 'Identifier' &&
        node.callee.object.name === 'document' &&
        node.callee.property.type === 'Identifier' &&
        ['write', 'writeln'].includes(node.callee.property.name)
      ) {
        signals.hasDangerousDOMManipulation = true
        signals.detectedViolations.push(createViolation(
          'no-dangerous-dom',
          'critical',
          `document.${node.callee.property.name}()の使用は禁止されています（XSS攻撃のリスク）`,
          node
        ))
      }

      // A10: window.open(url) / location.replace(url) 検出
      if (node.callee.type === 'MemberExpression') {
        const obj = node.callee.object
        const prop = node.callee.property
        if (
          obj?.type === 'Identifier' &&
          prop?.type === 'Identifier' &&
          ((obj.name === 'window' && prop.name === 'open') ||
           (obj.name === 'location' && prop.name === 'replace'))
        ) {
          const urlArg = node.arguments[0]
          if (urlArg?.type === 'Literal' && typeof urlArg.value === 'string') {
            const url = urlArg.value
            if (url.startsWith('http://') || url.startsWith('https://')) {
              const domains = extractDomains([url])
              const allowedDomains = permissions?.network?.allowedDomains || []
              const unauthorized = domains.filter(
                d => !allowedDomains.includes(d) && !ALLOWED_DOMAINS.includes(d)
              )
              if (unauthorized.length > 0) {
                signals.hasNetworkAPI = true
                signals.hasNetworkWithoutPermission = true
                signals.detectedViolations.push(createViolation(
                  'no-unauthorized-domain',
                  'critical',
                  `${obj.name}.${prop.name}() による許可されていないドメインへのアクセス: ${unauthorized.join(', ')}`,
                  node
                ))
              }
            }
          }
        }
      }

      // 危険なDOM操作メソッド検出 (A9: createContextualFragment も追加)
      if (['insertAdjacentHTML', 'createContextualFragment'].includes(calleeName || '')) {
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

      // Object.defineProperty / Reflect.set / Reflect.defineProperty 検出 (A6, A7)
      if (node.callee.type === 'MemberExpression') {
        const obj = node.callee.object
        const prop = node.callee.property
        if (
          obj?.type === 'Identifier' &&
          prop?.type === 'Identifier' &&
          ((obj.name === 'Object' && prop.name === 'defineProperty') ||
           (obj.name === 'Reflect' && (prop.name === 'set' || prop.name === 'defineProperty')))
        ) {
          const targetArg = node.arguments[0]
          const nameArg = node.arguments[1]

          // window/globalThis/self 対象
          if (
            targetArg?.type === 'Identifier' &&
            ['window', 'globalThis', 'self'].includes(targetArg.name) &&
            nameArg?.type === 'Literal' &&
            typeof nameArg.value === 'string'
          ) {
            signals.hasGlobalVariableOverride = true
            if (SENSITIVE_APIS.includes(nameArg.value)) {
              signals.detectedViolations.push(createViolation(
                'no-sensitive-api-override',
                'critical',
                `${obj.name}.${prop.name} による ${targetArg.name}.${nameArg.value} の改ざんは禁止されています`,
                node
              ))
            } else {
              signals.detectedViolations.push(createViolation(
                'no-global-override',
                'critical',
                `${obj.name}.${prop.name} による ${targetArg.name} の改ざんは禁止されています`,
                node
              ))
            }
          }

          // A7: X.prototype 対象 (BUILTIN_PROTOTYPES)
          if (
            targetArg?.type === 'MemberExpression' &&
            targetArg.property.type === 'Identifier' &&
            targetArg.property.name === 'prototype' &&
            targetArg.object.type === 'Identifier' &&
            BUILTIN_PROTOTYPES.includes(targetArg.object.name)
          ) {
            signals.hasGlobalVariableOverride = true
            signals.detectedViolations.push(createViolation(
              'no-prototype-pollution',
              'critical',
              `${obj.name}.${prop.name} による ${targetArg.object.name}.prototype の汚染は禁止されています`,
              node
            ))
          }
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
        ['window', 'globalThis', 'self', 'document', 'navigator'].includes(left.object.name)
      ) {
        const propertyName = left.property.type === 'Identifier'
          ? left.property.name
          : (left.property.type === 'Literal' && typeof left.property.value === 'string')
            ? left.property.value
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

      // C2: window.__proto__.fetch = ... 検出
      if (
        left.type === 'MemberExpression' &&
        left.object.type === 'MemberExpression' &&
        left.object.property.type === 'Identifier' &&
        left.object.property.name === '__proto__' &&
        left.object.object.type === 'Identifier' &&
        ['window', 'globalThis', 'self'].includes(left.object.object.name)
      ) {
        const propertyName = left.property.type === 'Identifier'
          ? left.property.name
          : (left.property.type === 'Literal' && typeof left.property.value === 'string')
            ? left.property.value
            : null
        signals.hasGlobalVariableOverride = true
        if (propertyName && SENSITIVE_APIS.includes(propertyName)) {
          signals.detectedViolations.push(createViolation(
            'no-sensitive-api-override',
            'critical',
            `${left.object.object.name}.__proto__.${propertyName} によるセンシティブ API の改ざんは禁止されています`,
            node
          ))
        } else {
          signals.detectedViolations.push(createViolation(
            'no-global-override',
            'critical',
            `${left.object.object.name}.__proto__ によるグローバルオブジェクトの改ざんは禁止されています`,
            node
          ))
        }
      }

      // C3: Object.getPrototypeOf(window).fetch = ... 検出
      if (
        left.type === 'MemberExpression' &&
        left.object.type === 'CallExpression' &&
        left.object.callee.type === 'MemberExpression' &&
        left.object.callee.object.type === 'Identifier' &&
        left.object.callee.object.name === 'Object' &&
        left.object.callee.property.type === 'Identifier' &&
        left.object.callee.property.name === 'getPrototypeOf'
      ) {
        const targetArg = left.object.arguments[0]
        if (
          targetArg?.type === 'Identifier' &&
          ['window', 'globalThis', 'self'].includes(targetArg.name)
        ) {
          const propertyName = left.property.type === 'Identifier'
            ? left.property.name
            : (left.property.type === 'Literal' && typeof left.property.value === 'string')
              ? left.property.value
              : null
          signals.hasGlobalVariableOverride = true
          if (propertyName && SENSITIVE_APIS.includes(propertyName)) {
            signals.detectedViolations.push(createViolation(
              'no-sensitive-api-override',
              'critical',
              `Object.getPrototypeOf(${targetArg.name}).${propertyName} によるセンシティブ API の改ざんは禁止されています`,
              node
            ))
          } else {
            signals.detectedViolations.push(createViolation(
              'no-global-override',
              'critical',
              `Object.getPrototypeOf(${targetArg.name}) によるグローバルオブジェクトの改ざんは禁止されています`,
              node
            ))
          }
        }
      }

      // C4: ({}).__proto__.xxx = ... 検出 (window/globalThis/self 以外)
      if (
        left.type === 'MemberExpression' &&
        left.object.type === 'MemberExpression' &&
        left.object.property.type === 'Identifier' &&
        left.object.property.name === '__proto__' &&
        !(
          left.object.object.type === 'Identifier' &&
          ['window', 'globalThis', 'self'].includes(left.object.object.name)
        )
      ) {
        signals.hasGlobalVariableOverride = true
        signals.detectedViolations.push(createViolation(
          'no-prototype-pollution',
          'critical',
          '__proto__ を経由したプロトタイプ汚染は禁止されています',
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

      // .src / .href / .action への URL 代入検出 (C5: action 追加)
      if (
        left.type === 'MemberExpression' &&
        left.property.type === 'Identifier' &&
        ['src', 'href', 'action'].includes(left.property.name)
      ) {
        const rightValue = node.right
        if (rightValue?.type === 'Literal' && typeof rightValue.value === 'string') {
          const url = rightValue.value
          if (url.startsWith('http://') || url.startsWith('https://')) {
            const domains = extractDomains([url])
            const allowedDomains = permissions?.network?.allowedDomains || []
            const unauthorized = domains.filter(
              d => !allowedDomains.includes(d) && !ALLOWED_DOMAINS.includes(d)
            )
            if (unauthorized.length > 0) {
              signals.hasNetworkAPI = true
              signals.hasNetworkWithoutPermission = true
              signals.detectedViolations.push(createViolation(
                'no-unauthorized-domain',
                'critical',
                `.src/.href による許可されていないドメインへのデータ送信: ${unauthorized.join(', ')}`,
                node
              ))
            }
          }
        }
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

      // navigator の危険プロパティのみ検出
      if (objectName === 'navigator' && propertyName && DANGEROUS_NAVIGATOR_PROPERTIES.includes(propertyName)) {
        signals.hasNavigatorAccess = true
        signals.detectedViolations.push(createViolation(
          'no-navigator-access',
          'critical',
          `navigator.${propertyName}へのアクセスは禁止されています`,
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
    Identifier(node: any, _ancestors: acorn.Node[]) {
      variableNames.push(node.name)
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

    // 7. new Function() コンストラクタ検出 + B1-B4 ネットワーク/DOM コンストラクタ検出
    NewExpression(node: any, _ancestors: acorn.Node[]) {
      // B1: ネットワーク系コンストラクタ
      const networkConstructors = ['EventSource', 'WebSocket', 'Worker', 'SharedWorker']
      if (
        node.callee.type === 'Identifier' &&
        networkConstructors.includes(node.callee.name)
      ) {
        signals.hasNetworkAPI = true
        const urlArg = node.arguments[0]
        if (urlArg?.type === 'Literal' && typeof urlArg.value === 'string') {
          const url = urlArg.value
          const domains = extractDomains([url])
          const allowedDomains = permissions?.network?.allowedDomains || []
          const unauthorized = domains.filter(
            d => !allowedDomains.includes(d) && !ALLOWED_DOMAINS.includes(d)
          )
          if (unauthorized.length > 0) {
            signals.hasNetworkWithoutPermission = true
            signals.detectedViolations.push(createViolation(
              'no-unauthorized-domain',
              'critical',
              `new ${node.callee.name}() による許可されていないドメインへの通信: ${unauthorized.join(', ')}`,
              node
            ))
          }
        } else {
          signals.hasNetworkWithoutPermission = true
          signals.detectedViolations.push(createViolation(
            'no-network-without-permission',
            'critical',
            `new ${node.callee.name}() によるネットワーク通信にはxrift.jsonでの権限宣言が必要です`,
            node
          ))
        }
      }

      // B2: RTCPeerConnection（IP漏洩リスク → neverSuppress）
      if (
        node.callee.type === 'Identifier' &&
        node.callee.name === 'RTCPeerConnection'
      ) {
        signals.hasNetworkAPI = true
        signals.hasNetworkWithoutPermission = true
        signals.detectedViolations.push(createViolation(
          'no-rtc-connection',
          'critical',
          'new RTCPeerConnection() はIP漏洩のリスクがあるため禁止されています',
          node
        ))
      }

      // B2: BroadcastChannel（同一オリジン内データ転送）
      if (
        node.callee.type === 'Identifier' &&
        node.callee.name === 'BroadcastChannel'
      ) {
        signals.hasNetworkAPI = true
        signals.hasNetworkWithoutPermission = true
        signals.detectedViolations.push(createViolation(
          'no-network-without-permission',
          'critical',
          'new BroadcastChannel() による通信チャネルの使用にはxrift.jsonでの権限宣言が必要です',
          node
        ))
      }

      // B3: new DOMParser()
      if (node.callee.type === 'Identifier' && node.callee.name === 'DOMParser') {
        signals.hasDangerousDOMManipulation = true
        signals.detectedViolations.push(createViolation(
          'no-dangerous-dom',
          'critical',
          'new DOMParser()の使用は禁止されています（XSS攻撃のリスク）',
          node
        ))
      }

      // B4: new Blob([...], { type: 'text/javascript' }) 検出
      // Blob 内の文字列にセンシティブ API / 非許可ドメイン URL が含まれる場合のみ
      // neverSuppress ルールで検出。それ以外は technicalViolations（バンドル依存で抑制可能）
      if (node.callee.type === 'Identifier' && node.callee.name === 'Blob') {
        const optionsArg = node.arguments[1]
        let isJavaScriptBlob = false
        if (optionsArg?.type === 'ObjectExpression') {
          for (const prop of optionsArg.properties) {
            const key = prop.key?.type === 'Identifier' ? prop.key.name
              : (prop.key?.type === 'Literal' ? prop.key.value : null)
            if (
              key === 'type' &&
              prop.value?.type === 'Literal' &&
              typeof prop.value.value === 'string' &&
              prop.value.value.includes('javascript')
            ) {
              isJavaScriptBlob = true
            }
          }
        }

        if (isJavaScriptBlob) {
          // Blob の第1引数（配列）から文字列を抽出して中身を検査
          const contentArg = node.arguments[0]
          const contentStrings: string[] = []
          if (contentArg?.type === 'ArrayExpression') {
            for (const el of contentArg.elements) {
              if (el?.type === 'Literal' && typeof el.value === 'string') {
                contentStrings.push(el.value)
              }
            }
          }
          const bodyText = contentStrings.join(' ')

          const referencesSensitiveAPI = SENSITIVE_APIS.some(api => bodyText.includes(api))
          const urlMatches = bodyText.match(/https?:\/\/[^\s'"`)]+/g) || []

          if (referencesSensitiveAPI) {
            const matched = SENSITIVE_APIS.filter(api => bodyText.includes(api))
            signals.hasDangerousDOMManipulation = true
            signals.detectedViolations.push(createViolation(
              'no-sensitive-api-override',
              'critical',
              `JavaScript Blob 内でセンシティブ API (${matched.join(', ')}) が参照されています`,
              node
            ))
          }

          if (urlMatches.length > 0) {
            const domains = extractDomains(urlMatches)
            const allowedDomains = permissions?.network?.allowedDomains || []
            const unauthorized = domains.filter(
              d => !allowedDomains.includes(d) && !ALLOWED_DOMAINS.includes(d)
            )
            if (unauthorized.length > 0) {
              signals.hasNetworkAPI = true
              signals.hasNetworkWithoutPermission = true
              signals.detectedViolations.push(createViolation(
                'no-unauthorized-domain',
                'critical',
                `JavaScript Blob 内で許可されていないドメインが参照されています: ${unauthorized.join(', ')}`,
                node
              ))
            }
          }

          // センシティブ API も URL も含まない場合は通常の no-javascript-blob（抑制可能）
          if (!referencesSensitiveAPI && urlMatches.length === 0) {
            signals.hasDangerousDOMManipulation = true
            signals.detectedViolations.push(createViolation(
              'no-javascript-blob',
              'critical',
              'JavaScript Blob の作成は禁止されています（動的コード実行のリスク）',
              node
            ))
          }
        }
      }

      if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
        signals.hasEval = true
        signals.hasDynamicCodeExecution = true

        // 引数の文字列にセンシティブ API 名や URL が含まれているか検査
        const argStrings = node.arguments
          .filter((a: any) => a.type === 'Literal' && typeof a.value === 'string')
          .map((a: any) => a.value as string)
        const bodyText = argStrings.join(' ')

        const referencesSensitiveAPI = SENSITIVE_APIS.some(api => bodyText.includes(api))
        const urlMatches = bodyText.match(/https?:\/\/[^\s'"`)]+/g) || []

        if (referencesSensitiveAPI) {
          const matched = SENSITIVE_APIS.filter(api => bodyText.includes(api))
          signals.detectedViolations.push(createViolation(
            'no-sensitive-api-override',
            'critical',
            `new Function() 内でセンシティブ API (${matched.join(', ')}) が参照されています`,
            node
          ))
        }

        if (urlMatches.length > 0) {
          const domains = extractDomains(urlMatches)
          const allowedDomains = permissions?.network?.allowedDomains || []
          const unauthorized = domains.filter(
            d => !allowedDomains.includes(d) && !ALLOWED_DOMAINS.includes(d)
          )
          if (unauthorized.length > 0) {
            signals.hasNetworkAPI = true
            signals.hasNetworkWithoutPermission = true
            signals.detectedViolations.push(createViolation(
              'no-unauthorized-domain',
              'critical',
              `new Function() 内で許可されていないドメインが参照されています: ${unauthorized.join(', ')}`,
              node
            ))
          }
        }

        // センシティブ API も URL も含まない場合は通常の no-new-function
        if (!referencesSensitiveAPI && urlMatches.length === 0) {
          signals.detectedViolations.push(createViolation(
            'no-new-function',
            'critical',
            'new Function()の使用は禁止されています（eval相当の動的コード実行）',
            node
          ))
        }
      }
    },

    // D1: eval`code` (TaggedTemplateExpression) 検出
    TaggedTemplateExpression(node: any, _ancestors: acorn.Node[]) {
      if (node.tag.type === 'Identifier' && node.tag.name === 'eval') {
        signals.hasEval = true
        signals.detectedViolations.push(createViolation(
          'no-eval',
          'critical',
          'eval タグ付きテンプレートリテラルの使用は禁止されています',
          node
        ))
      }
    },

    // 8. dynamic import 検出
    ImportExpression(node: any, _ancestors: acorn.Node[]) {
      const source = node.source
      if (source?.type === 'Literal' && typeof source.value === 'string') {
        const url = source.value
        if (url.startsWith('http://') || url.startsWith('https://')) {
          signals.hasNetworkAPI = true
          const domains = extractDomains([url])
          const allowedDomains = permissions?.network?.allowedDomains || []
          const unauthorized = domains.filter(
            d => !allowedDomains.includes(d) && !ALLOWED_DOMAINS.includes(d)
          )
          if (unauthorized.length > 0) {
            signals.hasNetworkWithoutPermission = true
            signals.detectedViolations.push(createViolation(
              'no-unauthorized-domain',
              'critical',
              `動的importによる許可されていないドメインからのコード読み込み: ${unauthorized.join(', ')}`,
              node
            ))
          }
        }
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
        'ネットワーク通信にはxrift.jsonでの権限宣言が必要です'
      ))
    }
  }

  return signals
}
