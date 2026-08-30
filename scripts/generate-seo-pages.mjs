import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  allSeoPages,
  HOMEPAGE_LAST_MODIFIED,
  SITE_URL,
} from './seo-pages.mjs'

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const publicRoot = join(projectRoot, 'public')

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function jsonLd(page) {
  const url = SITE_URL + page.slug
  return JSON.stringify(
    {
      '@context': 'https://schema.org',
      '@graph': [
        {
          '@type': 'WebPage',
          '@id': url + '#webpage',
          url,
          name: page.title,
          description: page.description,
          isPartOf: { '@id': SITE_URL + '/#website' },
          breadcrumb: { '@id': url + '#breadcrumb' },
          inLanguage: 'en',
        },
        {
          '@type': 'BreadcrumbList',
          '@id': url + '#breadcrumb',
          itemListElement: [
            {
              '@type': 'ListItem',
              position: 1,
              name: 'Bitpeek',
              item: SITE_URL + '/',
            },
            {
              '@type': 'ListItem',
              position: 2,
              name: page.label,
              item: url,
            },
          ],
        },
      ],
    },
    null,
    2,
  ).replaceAll('<', '\\u003c')
}

function siteHeader() {
  return `
    <a class="skip-link" href="#main-content">Skip to the main content</a>
    <header class="site-header">
      <div class="site-header-inner">
        <a class="site-brand" href="/" aria-label="Bitpeek home">bitpeek</a>
        <nav class="site-nav" aria-label="Primary navigation">
          <a href="/#workspace">workspace</a>
          <a href="/#tools">tools</a>
          <a href="/#file-formats">formats</a>
          <a href="https://github.com/Yudis-bit/bitpeek">source</a>
        </nav>
      </div>
    </header>`
}

function siteFooter() {
  return `
    <footer class="site-footer">
      <div class="site-header-inner footer-content">
        <p>bitpeek · browser hex and binary utility</p>
        <nav aria-label="Footer navigation">
          <a href="/">workspace</a>
          <a href="/tools/hex-editor">hex editor</a>
          <a href="/file-formats/png">format reference</a>
          <a href="https://github.com/Yudis-bit/bitpeek">source</a>
        </nav>
      </div>
    </footer>`
}

function renderSections(page) {
  return page.sections
    .map(
      (section) => `
        <section class="article-section" id="${escapeHtml(section.id)}" aria-labelledby="${escapeHtml(section.id)}-heading">
          <h2 id="${escapeHtml(section.id)}-heading">${escapeHtml(section.title)}</h2>
          ${section.html.trim()}
        </section>`,
    )
    .join('\n')
}

function renderFaqs(page) {
  return `
    <section class="article-section" id="faq" aria-labelledby="faq-heading">
      <h2 id="faq-heading">Frequently asked questions</h2>
      <div class="faq-list">
        ${page.faqs
          .map(
            (faq) => `
              <div>
                <h3>${escapeHtml(faq.question)}</h3>
                <p>${escapeHtml(faq.answer)}</p>
              </div>`,
          )
          .join('')}
      </div>
    </section>`
}

function renderRelated(page) {
  return `
    <section class="related-section" id="related" aria-labelledby="related-heading">
      <h2 id="related-heading">Related Bitpeek references</h2>
      <ul class="related-list">
        ${page.related
          .map(
            (item) => `
              <li>
                <a href="${escapeHtml(item.slug)}">${escapeHtml(item.label)}</a>
                <span>${escapeHtml(item.note)}</span>
              </li>`,
          )
          .join('')}
      </ul>
    </section>`
}

function renderAside(page) {
  const links = [
    ...page.sections.map((section) => ({
      href: '#' + section.id,
      label: section.title,
    })),
    { href: '#privacy', label: 'Local processing' },
    { href: '#faq', label: 'FAQ' },
    { href: '#related', label: 'Related references' },
  ]

  return `
    <aside class="article-aside" aria-label="On this page">
      <h2>On this page</h2>
      <nav>
        ${links
          .map(
            (link) =>
              `<a href="${escapeHtml(link.href)}">${escapeHtml(link.label)}</a>`,
          )
          .join('')}
      </nav>
    </aside>`
}

function renderPage(page) {
  const url = SITE_URL + page.slug
  const category = page.type === 'format' ? 'File formats' : 'Tools'
  const categoryHref = page.type === 'format' ? '/#file-formats' : '/#tools'
  const source = page.source
    ? `<p class="source-note">Technical reference: <a href="${escapeHtml(page.source.url)}" rel="noreferrer">${escapeHtml(page.source.label)}</a>.</p>`
    : ''

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="theme-color" content="#0c0e0f" />
    <meta name="color-scheme" content="dark" />
    <meta name="description" content="${escapeHtml(page.description)}" />
    <meta name="robots" content="index,follow,max-image-preview:large,max-snippet:-1,max-video-preview:-1" />
    <meta name="referrer" content="strict-origin-when-cross-origin" />
    <link rel="canonical" href="${url}" />

    <meta property="og:type" content="website" />
    <meta property="og:site_name" content="Bitpeek" />
    <meta property="og:locale" content="en_US" />
    <meta property="og:title" content="${escapeHtml(page.title)}" />
    <meta property="og:description" content="${escapeHtml(page.description)}" />
    <meta property="og:url" content="${url}" />
    <meta property="og:image" content="${SITE_URL}/social/bitpeek-og.png" />
    <meta property="og:image:alt" content="Bitpeek local-first hex editor and binary inspector" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />

    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${escapeHtml(page.title)}" />
    <meta name="twitter:description" content="${escapeHtml(page.description)}" />
    <meta name="twitter:image" content="${SITE_URL}/social/bitpeek-og.png" />
    <meta name="twitter:image:alt" content="Bitpeek local-first hex editor and binary inspector" />

    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="icon" type="image/png" sizes="192x192" href="/icon-192.png" />
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
    <link rel="manifest" href="/site.webmanifest" />
    <link rel="stylesheet" href="/seo.css" />
    <title>${escapeHtml(page.title)}</title>
    <script type="application/ld+json">
${jsonLd(page)}
    </script>
  </head>
  <body>
    ${siteHeader()}
    <main id="main-content">
      <header class="reference-header" aria-labelledby="page-heading">
        <div class="reference-column">
          <ol class="breadcrumb-list" aria-label="Breadcrumb">
            <li><a href="/">Bitpeek</a></li>
            <li aria-hidden="true">/</li>
            <li><a href="${categoryHref}">${escapeHtml(category)}</a></li>
            <li aria-hidden="true">/</li>
            <li aria-current="page">${escapeHtml(page.label)}</li>
          </ol>
          <h1 id="page-heading">${escapeHtml(page.h1)}</h1>
          <p class="page-lead">${escapeHtml(page.lead)}</p>
          <div class="reference-actions">
            <a class="button-link is-primary" href="${escapeHtml(page.ctaHref)}">${escapeHtml(page.ctaLabel)}</a>
            <a href="#privacy">Local processing notes</a>
          </div>
        </div>
      </header>

      <div class="page-main">
        <div class="reference-column article-layout">
          <article class="article-main">
            ${renderSections(page)}

            <section class="article-section" id="privacy" aria-labelledby="local-processing-heading">
              <h2 id="local-processing-heading">Local processing and privacy</h2>
              <p>The ${escapeHtml(page.label)} workflow opens the same Bitpeek browser workspace. Selected file bytes, file names, pasted input, searches, edits, hashes, and comparison data are processed in local browser memory and are not sent to a Bitpeek server.</p>
              <p>The static guide itself can be read without opening a file or creating an account.</p>
            </section>

            ${source}
            ${renderFaqs(page)}
            ${renderRelated(page)}
          </article>
          ${renderAside(page)}
        </div>
      </div>
    </main>
    ${siteFooter()}
  </body>
</html>
`
}

function renderSitemap() {
  const pages = [
    { slug: '/', lastModified: HOMEPAGE_LAST_MODIFIED },
    ...allSeoPages,
  ]
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${pages
  .map(
    (page) => `  <url>
    <loc>${SITE_URL}${page.slug}</loc>
    <lastmod>${page.lastModified}</lastmod>
  </url>`,
  )
  .join('\n')}
</urlset>
`
}

for (const page of allSeoPages) {
  const outputPath = join(publicRoot, page.slug.slice(1) + '.html')
  await mkdir(dirname(outputPath), { recursive: true })
  await writeFile(outputPath, renderPage(page), 'utf8')
}

await writeFile(join(publicRoot, 'sitemap.xml'), renderSitemap(), 'utf8')

console.log(`Generated ${allSeoPages.length} SEO pages and sitemap.xml.`)
