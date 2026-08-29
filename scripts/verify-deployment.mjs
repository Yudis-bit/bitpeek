import assert from 'node:assert/strict'
import { allSeoPages, SITE_URL } from './seo-pages.mjs'

const target = new URL(process.argv[2] ?? SITE_URL)
target.pathname = '/'
target.search = ''
target.hash = ''

function countMatches(value, expression) {
  return [...value.matchAll(expression)].length
}

function requiredMatch(value, expression, label) {
  const match = value.match(expression)
  assert.ok(match?.[1], `Missing ${label}`)
  return match[1]
}

function plainText(value) {
  return value
    .replaceAll(/<script\b[\s\S]*?<\/script>/gi, ' ')
    .replaceAll(/<style\b[\s\S]*?<\/style>/gi, ' ')
    .replaceAll(/<[^>]+>/g, ' ')
    .replaceAll(/\s+/g, ' ')
    .trim()
}

function pageUrl(path) {
  return new URL(path, target).toString()
}

async function fetchDirect(path, expectedStatus) {
  const response = await fetch(pageUrl(path), { redirect: 'manual' })
  const location = response.headers.get('location')
  assert.equal(
    response.status,
    expectedStatus,
    `${path} returned ${response.status}, expected ${expectedStatus}${location ? ` (Location: ${location})` : ''}`,
  )
  return response
}

const indexablePages = [
  { slug: '/', canonical: SITE_URL + '/' },
  ...allSeoPages.map((page) => ({
    slug: page.slug,
    canonical: SITE_URL + page.slug,
  })),
]

for (const page of indexablePages) {
  const response = await fetchDirect(page.slug, 200)
  assert.match(
    response.headers.get('content-type') ?? '',
    /text\/html/i,
    `${page.slug} must return HTML`,
  )
  const html = await response.text()
  const title = requiredMatch(
    html,
    /<title>([\s\S]*?)<\/title>/i,
    `title for ${page.slug}`,
  )
  const description = requiredMatch(
    html,
    /<meta\s+name="description"\s+content="([^"]+)"/i,
    `description for ${page.slug}`,
  )
  const canonical = requiredMatch(
    html,
    /<link\s+rel="canonical"\s+href="([^"]+)"/i,
    `canonical for ${page.slug}`,
  )
  assert.equal(canonical, page.canonical, `${page.slug} has an unexpected canonical`)
  assert.ok(title.trim().length >= 30, `${page.slug} has a short title`)
  assert.ok(description.length >= 100, `${page.slug} has a short description`)
  assert.equal(countMatches(html, /<h1\b/gi), 1, `${page.slug} must have one H1`)
  assert.match(
    html,
    /name="robots"\s+content="index,follow/i,
    `${page.slug} must be indexable`,
  )
  assert.ok(plainText(html).length > 1_000, `${page.slug} has thin HTML`)

  const structuredData = [
    ...html.matchAll(
      /<script\s+type="application\/ld\+json">([\s\S]*?)<\/script>/gi,
    ),
  ]
  assert.ok(structuredData.length > 0, `${page.slug} is missing structured data`)
  for (const match of structuredData) JSON.parse(match[1])
}

const robots = await fetchDirect('/robots.txt', 200)
assert.match(await robots.text(), new RegExp(`Sitemap: ${SITE_URL}/sitemap\\.xml`))

const sitemap = await fetchDirect('/sitemap.xml', 200)
const sitemapText = await sitemap.text()
for (const page of indexablePages) {
  assert.ok(
    sitemapText.includes(`<loc>${page.canonical}</loc>`),
    `Sitemap is missing ${page.canonical}`,
  )
}

const manifest = await fetchDirect('/site.webmanifest', 200)
assert.equal((await manifest.json()).start_url, '/')

for (const asset of ['/favicon.svg', '/social/bitpeek-og.png']) {
  const response = await fetchDirect(asset, 200)
  assert.ok((await response.arrayBuffer()).byteLength > 0, `${asset} is empty`)
}

const notFound = await fetchDirect('/a-route-that-does-not-exist', 404)
const notFoundHtml = await notFound.text()
assert.match(notFoundHtml, /name="robots"\s+content="noindex,follow"/i)
assert.equal(countMatches(notFoundHtml, /<h1\b/gi), 1, '404 page must have one H1')

console.log(
  `Verified ${indexablePages.length} indexable pages, public SEO assets, and the custom 404 at ${target.origin}.`,
)
