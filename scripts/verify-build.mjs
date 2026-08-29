import assert from 'node:assert/strict'
import { readFile, stat } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'
import { allSeoPages } from './seo-pages.mjs'

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const distRoot = join(projectRoot, 'dist')

async function gzipBytes(path) {
  return gzipSync(await readFile(path)).byteLength
}

function requiredMatch(value, expression, label) {
  const match = value.match(expression)
  assert.ok(match?.[1], `Built homepage is missing ${label}`)
  return match[1]
}

const homepagePath = join(distRoot, 'index.html')
const homepage = await readFile(homepagePath, 'utf8')
const entryScript = requiredMatch(homepage, /<script\s+type="module"[^>]+src="([^"]+)"/i, 'entry script')
const appStylesheet = requiredMatch(homepage, /<link\s+rel="stylesheet"[^>]+href="([^"]*\/assets\/[^"]+\.css)"/i, 'application stylesheet')

const homepageGzip = await gzipBytes(homepagePath)
const scriptGzip = await gzipBytes(join(distRoot, entryScript.slice(1)))
const appCssGzip = await gzipBytes(join(distRoot, appStylesheet.slice(1)))
const seoCssGzip = await gzipBytes(join(distRoot, 'seo.css'))
const initialGzip = homepageGzip + scriptGzip + appCssGzip + seoCssGzip

assert.ok(homepageGzip <= 6 * 1024, `Homepage HTML exceeds 6 KiB gzip: ${homepageGzip}`)
assert.ok(scriptGzip <= 80 * 1024, `Initial JavaScript exceeds 80 KiB gzip: ${scriptGzip}`)
assert.ok(appCssGzip <= 7 * 1024, `Application CSS exceeds 7 KiB gzip: ${appCssGzip}`)
assert.ok(seoCssGzip <= 7 * 1024, `Shared SEO CSS exceeds 7 KiB gzip: ${seoCssGzip}`)
assert.ok(initialGzip <= 100 * 1024, `Initial homepage payload exceeds 100 KiB gzip: ${initialGzip}`)

assert.match(homepage, /<h1\b[^>]*>Inspect, Edit, and Compare Binary Files Online<\/h1>/)
assert.match(homepage, /<link rel="canonical" href="https:\/\/bitpeek-seven\.vercel\.app\/"/)

for (const page of allSeoPages) {
  const outputPath = join(distRoot, page.slug.slice(1) + '.html')
  const info = await stat(outputPath)
  const html = await readFile(outputPath, 'utf8')
  assert.ok(info.size <= 40 * 1024, `${page.slug} exceeds the 40 KiB HTML budget`)
  assert.doesNotMatch(html, /<script\s+[^>]*src=/i, `${page.slug} should not require client JavaScript`)
  assert.match(html, new RegExp(`<link rel="canonical" href="https://bitpeek-seven\\.vercel\\.app${page.slug}"`))
}

console.log(
  `Build budgets: HTML ${homepageGzip} B, initial JS ${scriptGzip} B, app CSS ${appCssGzip} B, shared CSS ${seoCssGzip} B, total ${initialGzip} B gzip.`,
)
console.log(`Verified ${allSeoPages.length} static landing-page outputs.`)
