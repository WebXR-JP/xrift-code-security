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

| ルール | 説明 | 重大度 |
|--------|------|--------|
| `no-eval` | `eval()` の使用 | critical |
| `no-string-timeout` | `setTimeout/setInterval` への文字列引数 | critical |
| `no-storage-access` | `localStorage/sessionStorage` アクセス | critical |
| `no-cookie-access` | `document.cookie` アクセス | critical |
| `no-indexeddb-access` | `indexedDB` アクセス | critical |
| `no-storage-event` | `addEventListener('storage')` / `onstorage` | critical |
| `no-navigator-access` | `navigator.*` アクセス | critical |
| `no-dangerous-dom` | `innerHTML` 代入 / `createElement('script')` | critical |
| `no-global-override` | `window/document/navigator` の改ざん | critical |
| `no-prototype-pollution` | `Object.prototype` 汚染 | critical |
| `no-obfuscation` | `atob/btoa/String.fromCharCode` 等 | critical |
| `no-external-import` | 外部 URL からの `import` | critical |
| `no-network-without-permission` | 未許可ドメインへの通信 | critical |

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
