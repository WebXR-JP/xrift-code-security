# @xrift/code-security

JavaScript コードの静的セキュリティ解析パッケージ。acorn ベースの AST 解析により、危険な API 使用や難読化パターンを検出します。

## インストール

```bash
npm install @xrift/code-security
```

## 使い方

### CodeSecurityService（推奨）

```typescript
import { CodeSecurityService } from '@xrift/code-security'

const service = new CodeSecurityService()

const result = service.validate({
  code: 'const x = 1;',
  packageJson: {
    dependencies: {}
  }
})

console.log(result.valid)          // true
console.log(result.securityScore)  // 0
console.log(result.violations)     // { critical: [], warnings: [] }
```

### analyzeCodeSecurity（低レベル API）

```typescript
import { analyzeCodeSecurity } from '@xrift/code-security'

const signals = analyzeCodeSecurity('eval("alert(1)")')

console.log(signals.hasEval)              // true
console.log(signals.detectedViolations)   // [{ rule: 'no-eval', ... }]
```

### ネットワーク権限の付与

```typescript
const result = service.validate({
  code: `fetch('https://api.example.com/data')`,
  packageJson: { dependencies: {} },
  manifestConfig: {
    permissions: {
      network: {
        allowedDomains: ['api.example.com']
      }
    }
  }
})
```

## 検出ルール

すべてのルールはデフォルト `critical` ですが、ファイルコンテキスト（バンドル依存、共有ライブラリ等）に応じて `warning` への緩和や完全抑制が行われます。

### コード実行

| ルール | 検出対象 |
|--------|----------|
| `no-eval` | `eval()` の呼び出し |
| `no-string-timeout` | `setTimeout("code", ms)` / `setInterval("code", ms)` のように文字列を渡すパターン |

### ストレージ・Cookie

| ルール | 検出対象 |
|--------|----------|
| `no-storage-access` | `localStorage.*` / `sessionStorage.*` へのアクセス |
| `no-cookie-access` | `document.cookie` へのアクセス |
| `no-indexeddb-access` | `indexedDB.*` へのアクセス |
| `no-storage-event` | `addEventListener('storage', ...)` / `onstorage = ...` |

### ブラウザ API

| ルール | 検出対象 |
|--------|----------|
| `no-navigator-access` | `navigator.*` プロパティへのアクセス（フィンガープリンティング防止） |
| `no-dangerous-dom` | `innerHTML` / `outerHTML` への代入、`document.createElement('script'` / `'iframe')` 、`insertAdjacentHTML()`、`document.head` へのアクセス |
| `no-global-override` | `window.*` / `globalThis.*` / `document.*` / `navigator.*` への代入によるグローバル改ざん |
| `no-prototype-pollution` | `Object.prototype` / `Array.prototype` 等の組み込みオブジェクトのプロトタイプ汚染（自クラスの `.prototype` 定義は対象外） |

### ネットワーク・インポート

| ルール | 検出対象 |
|--------|----------|
| `no-network-without-permission` | `fetch()` / `XMLHttpRequest` / `WebSocket` / `navigator.sendBeacon()` による未許可ドメインへの通信（`.wasm` ファイルの読み込みは対象外） |
| `no-external-import` | `import ... from 'https://...'` のような外部 URL からの import |

### 難読化

| ルール | 検出対象 |
|--------|----------|
| `no-obfuscation` | `atob()` / `btoa()` / `unescape()` / `decodeURIComponent()` / `String.fromCharCode()` の使用、16進数・Unicode エスケープ、高エントロピー文字列（閾値: 7.0）、疑わしい変数名パターン |

### ファイルコンテキストによる調整

ファイルの種類に応じて、違反の重大度が自動調整されます。

| ファイル種別 | 判定基準 | 調整内容 |
|-------------|----------|----------|
| ユーザーコード | `__federation_expose_World-*.js` | 調整なし（すべて厳格） |
| MF 動的インポート | `__federation_fn_import` を含む | 調整なし（すべて厳格） |
| 共有ライブラリ | `__federation_shared_*` | 技術的違反を完全抑制 |
| バンドル依存 | 上記以外の `.js` | 技術的違反を完全抑制 |
| `remoteEntry.js` | ファイル名が一致 | 技術的違反を完全抑制 |
| Vite preload-helper | `preload-helper*` で始まる | `no-dangerous-dom` を完全抑制 |

> **技術的違反**: `no-obfuscation`, `no-dangerous-dom`, `no-navigator-access`, `no-prototype-pollution`, `no-global-override`, `no-network-without-permission`
>
> **常に critical**: `no-eval`, `no-storage-access`, `no-storage-event`（ファイル種別にかかわらず緩和されない）

## API リファレンス

### クラス

- **`CodeSecurityService`** - セキュリティ解析サービス
  - `validate(request: ValidateCodeRequest): ValidateCodeResponse`

### 関数

- **`analyzeCodeSecurity(code, permissions?)`** - コードの AST 解析を実行
- **`calculateSecurityScore(signals)`** - セキュリティスコアを算出（0-100）
- **`getSecurityVerdict(score)`** - スコアから判定結果を返す（`APPROVE` / `REVIEW` / `REJECT`）
- **`determineFileContext(filePath)`** - ファイルパスからコンテキストを判定
- **`adjustViolationSeverity(rule, severity, context)`** - コンテキストに基づき重大度を調整

### 型

- `ValidateCodeRequest` / `ValidateCodeResponse`
- `SecuritySignals` / `Violation`
- `CodePermissions` / `FileContext`

## License

MIT
