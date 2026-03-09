/**
 * 回帰テストスクリプト
 * 実プロジェクトの dist ディレクトリを解析し、新ルールが正規ライブラリに誤検知しないことを確認する
 *
 * 使い方:
 *   npx tsx scripts/regression-test.ts <dist-dir> [<dist-dir> ...]
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, basename } from 'node:path'
import { analyzeCodeSecurity } from '../src/analyzer.js'
import { adjustViolationSeverity, determineFileContext } from '../src/utils/file-context.js'

const distDirs = process.argv.slice(2)

if (distDirs.length === 0) {
  console.error('使い方: npx tsx scripts/regression-test.ts <dist-dir> [<dist-dir> ...]')
  process.exit(1)
}

function collectJsFiles(dir: string): string[] {
  const files: string[] = []
  try {
    for (const entry of readdirSync(dir)) {
      const fullPath = join(dir, entry)
      const stat = statSync(fullPath)
      if (stat.isDirectory()) {
        files.push(...collectJsFiles(fullPath))
      } else if (entry.endsWith('.js')) {
        files.push(fullPath)
      }
    }
  } catch {
    // ディレクトリが存在しない場合は空配列を返す
  }
  return files
}

let allPassed = true

for (const distPath of distDirs) {
  const projectName = basename(join(distPath, '..'))
  const jsFiles = collectJsFiles(distPath)

  if (jsFiles.length === 0) {
    console.log(`\n⚠️  ${projectName}: dist ディレクトリが見つからないかJSファイルがありません (${distPath})`)
    continue
  }

  console.log(`\n📦 ${projectName}: ${jsFiles.length} 個のJSファイルを解析中...`)

  let filesFailed = 0

  for (const filePath of jsFiles) {
    const code = readFileSync(filePath, 'utf-8')
    const fileName = filePath.replace(distPath + '/', '')
    const context = determineFileContext(fileName)
    const signals = analyzeCodeSecurity(code)

    // adjustViolationSeverity を通して、最終的に残る violation をチェック
    const remainingViolations = signals.detectedViolations.filter(v => {
      const adjusted = adjustViolationSeverity(v.rule, v.severity, context)
      return adjusted !== null
    })

    if (remainingViolations.length > 0) {
      filesFailed++
      console.log(`  ❌ ${fileName}:`)
      for (const v of remainingViolations) {
        console.log(`     - [${v.rule}] ${v.message}`)
      }
    }
  }

  if (filesFailed === 0) {
    console.log(`  ✅ 全ファイル合格`)
  } else {
    console.log(`  ❌ ${filesFailed} 個のファイルで違反検出`)
    allPassed = false
  }
}

console.log('')
if (allPassed) {
  console.log('🎉 全プロジェクトの回帰テストに合格しました')
} else {
  console.log('💥 回帰テストに失敗したプロジェクトがあります')
  process.exit(1)
}
