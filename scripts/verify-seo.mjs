import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  allSeoPages,
  HOMEPAGE_LAST_MODIFIED,
  SITE_URL,
} from './seo-pages.mjs'

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const publicRoot = join(projectRoot, 'public')

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
    .replaceAll('&amp;', '&')
    .replaceAll('&mdash;', '—')
    .replaceAll('&nbsp;', ' ')
    .replaceAll(/\s+/g, ' ')
    .trim()
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function assertDate(value, label) {
  assert.match(value, /^\d{4}-\d{2}-\d{2}$/, `${label} must use YYYY-MM-DD`)
  assert.equal(
    new Date(value + 'T00:00:00Z').toISOString().slice(0, 10),
    value,
    `${label} must be a real calendar date`,
  )
}

const documents = [
  {
    slug: '/',
    file: join(projectRoot, 'index.html'),
    expectedCanonical: SITE_URL + '/',
    expectedLastModified: HOMEPAGE_LAST_MODIFIED,
  },
  ...allSeoPages.map((page) => ({
    slug: page.slug,
    file: join(publicRoot, page.slug.slice(1) + '.html'),
    expectedCanonical: SITE_URL + page.slug,
    expectedLastModified: page.lastModified,
  })),
]

const titles = new Set()
const descriptions = new Set()
const canonicals = new Set()
const headings = new Set()
const knownRoutes = new Set(documents.map((document) => document.slug))

for (const document of documents) {
  const html = await readFile(document.file, 'utf8')
  const title = plainText(requiredMatch(html, /<title>([\s\S]*?)<\/title>/i, `title for ${document.slug}`))
  const description = requiredMatch(
    html,
    /<meta\s+name="description"\s+content="([^"]+)"\s*\/?\s*>/i,
    `description for ${document.slug}`,
  )
  const canonical = requiredMatch(
    html,
    /<link\s+rel="canonical"\s+href="([^"]+)"\s*\/?\s*>/i,
    `canonical for ${document.slug}`,
  )
  const h1 = plainText(requiredMatch(html, /<h1\b[^>]*>([\s\S]*?)<\/h1>/i, `H1 for ${document.slug}`))

  assert.equal(countMatches(html, /<h1\b/gi), 1, `${document.slug} must have exactly one H1`)
  assert.equal(canonical, document.expectedCanonical, `${document.slug} has an unexpected canonical`)
  assert.match(html, /name="robots"\s+content="index,follow/i, `${document.slug} must be indexable`)
  if (document.slug === '/') {
    assert.match(
      html,
      /name="google-site-verification"\s+content="Jn0K5vK7EtJ9tpYr_JzwqkUNXm-OeVXELznWLvX7lns"/i,
      'Homepage must include the Google site verification token',
    )
  }
  assert.ok(title.length >= 30 && title.length <= 65, `${document.slug} title length is ${title.length}`)
  assert.ok(description.length >= 100 && description.length <= 170, `${document.slug} description length is ${description.length}`)
  assert.ok(plainText(html).length > 1_000, `${document.slug} initial HTML is too thin`)
  assert.ok(countMatches(html, /<a\s+[^>]*href=/gi) >= 8, `${document.slug} needs crawlable links`)
  assert.doesNotMatch(html, /\b(?:TODO|PLACEHOLDER_COPY|lorem ipsum)\b/i, `${document.slug} contains placeholder copy`)

  assert.ok(!titles.has(title), `Duplicate title: ${title}`)
  assert.ok(!descriptions.has(description), `Duplicate description: ${description}`)
  assert.ok(!canonicals.has(canonical), `Duplicate canonical: ${canonical}`)
  assert.ok(!headings.has(h1), `Duplicate H1: ${h1}`)
  titles.add(title)
  descriptions.add(description)
  canonicals.add(canonical)
  headings.add(h1)

  const structuredData = [...html.matchAll(/<script\s+type="application\/ld\+json">([\s\S]*?)<\/script>/gi)]
  assert.ok(structuredData.length >= 1, `${document.slug} is missing structured data`)
  for (const match of structuredData) JSON.parse(match[1])

  for (const hrefMatch of html.matchAll(/href="(\/(?:tools|file-formats)\/[^"?#]+)[^\"]*"/g)) {
    assert.ok(knownRoutes.has(hrefMatch[1]), `${document.slug} links to missing route ${hrefMatch[1]}`)
  }
}

const sitemap = await readFile(join(publicRoot, 'sitemap.xml'), 'utf8')
const sitemapUrls = new Set([...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]))
assert.equal(sitemapUrls.size, documents.length, 'Sitemap URL count does not match indexable pages')
for (const document of documents) {
  assertDate(document.expectedLastModified, `lastModified for ${document.slug}`)
  assert.ok(sitemapUrls.has(document.expectedCanonical), `Sitemap is missing ${document.expectedCanonical}`)
  assert.match(
    sitemap,
    new RegExp(
      `<loc>${escapeRegExp(document.expectedCanonical)}</loc>\\s*<lastmod>${document.expectedLastModified}</lastmod>`,
    ),
    `Sitemap has an unexpected lastmod for ${document.slug}`,
  )
}

const robots = await readFile(join(publicRoot, 'robots.txt'), 'utf8')
assert.match(robots, /^User-agent: \*/m)
assert.match(robots, /^Allow: \/$/m)
assert.match(robots, new RegExp(`^Sitemap: ${SITE_URL.replaceAll('.', '\\.')}/sitemap\\.xml$`, 'm'))

const notFound = await readFile(join(publicRoot, '404.html'), 'utf8')
assert.match(notFound, /name="robots"\s+content="noindex,follow"/i)
assert.equal(countMatches(notFound, /<h1\b/gi), 1)

const manifest = JSON.parse(await readFile(join(publicRoot, 'site.webmanifest'), 'utf8'))
assert.equal(manifest.start_url, '/')
assert.deepEqual(manifest.icons.map((icon) => icon.sizes), ['192x192', '512x512'])

const vercel = JSON.parse(await readFile(join(projectRoot, 'vercel.json'), 'utf8'))
assert.equal(vercel.cleanUrls, true)
assert.equal(vercel.trailingSlash, false)

console.log(`Verified ${documents.length} indexable pages, metadata, links, sitemap, robots, manifest, and 404.`)
