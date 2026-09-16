# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Jekyll static site (Valerio Casalino's blog), hosted on GitHub Pages. It is a single Jekyll-generated site (posts, pages, layouts, includes, assets) — there is no separate untemplated static page anymore (the old `links/index.html` link-in-bio page was removed in favor of `/about/`, which folds contact links into the templated site).

There is no build tooling in the repo (no `package.json`, no committed `Gemfile` — it's gitignored). Content is edited either directly as Markdown/YAML or through [Pages CMS](https://pagescms.org), a web-based editor configured by `.pages.yml`; commits made through that UI show up as "Update .pages.yml (via Pages CMS)" — don't be surprised by that commit message pattern in `git log`.

## Commands

Standard Jekyll workflow (Ruby/Bundler must be installed locally; there's no lockfile committed):

```sh
bundle install
bundle exec jekyll serve   # local dev server with live rebuild
bundle exec jekyll build   # production build into _site/
```

There is no test suite, linter, or CI configured in this repo.

## Content architecture

**Posts** live in `_posts/`, named `YYYY-MM-DD-title.md`. `_config.yml` applies `layout: post` and permalink `/p/:title/` to everything under `_posts` by default, so individual post front matter only strictly needs `categories`. In practice always set an explicit `title` too — Jekyll otherwise titleizes the filename slug for `page.title` (used in `<title>`, OG/JSON-LD, the homepage list, and the Atom feed), which reads badly for anything with an acronym or product name (e.g. `nuclei-can-now-speak-ad.md` would title itself "Nuclei Can Now Speak Ad" instead of "...AD"). Always set an explicit `description` too — it's the meta-description (and `og:description`/JSON-LD `description`), and it's also what `llms.txt` (below) puts next to the post's title, so a missing one falls back to a truncated `page.excerpt`, which is often just the post's opening words out of context (e.g. a writeup that opens with "As always, nmap") and misrepresents the post everywhere it's used:

```yaml
---
title: "Nuclei Can Now Speak AD"
description: "One sentence summarizing the post, used as the meta description when the opening paragraph doesn't work as one."
categories:
  - dev
  - research
---
```

**Layouts** (`_layouts/`):
- `blog.html` — the homepage (`index.md` uses `layout: blog`). Renders the bio and a plain text list (`ul.post-list`) of `site.posts` — date, title, `#category` tags — no images.
- `post.html` — individual post pages. Renders title/date/tags, then `{{content}}`, then loads Mermaid (see below) via an inline `<script type="module">`.
- `page.html` — generic content pages (currently just `about.md`, permalink `/about/`). Renders `page.title` as an `<h1>` then `{{content}}`, no date/tags/Mermaid. Reuses `post.html`'s `.post-header`/`.content` CSS classes.

**Includes** (`_includes/`) are shared partials: `head.html` (stylesheets), `header.html` (site title + nav), `footer.html`, `bio.html` (reads `_data/author.yml` for the avatar and contact links).

**The site is intentionally image-free.** No post cover/thumbnail images, no icon images for contact links (they're plain text, e.g. "github", "linkedin", joined with " · " in `bio.html`), no `jemoji` plugin (removed from `_config.yml` — write literal unicode emoji in post bodies instead of `:shortcode:` syntax, since jemoji renders shortcodes as `<img>`). The only image on the whole site is the author's GitHub avatar (`_data/author.yml`'s `dp` field, an `avatars.githubusercontent.com` URL), used in `bio.html`, always linked to `https://github.com/5amu`. Keep it that way when adding content — don't reintroduce screenshots/diagrams as raster images.

**Diagrams belong in Mermaid, not images.** Post pages load Mermaid from a CDN (`post.html`) and auto-render any `<div class="mermaid">...</div>` raw-HTML block in the markdown (kramdown passes raw HTML blocks through untouched, which sidesteps Rouge trying and failing to syntax-highlight a "mermaid" fenced code block as a language it doesn't know). See `_posts/2022-10-07-bgp-hijacking.md` for worked examples (sequence and graph diagrams). This only applies to `post.html` — the homepage doesn't load Mermaid.

**Author/contact info** lives in `_data/author.yml` (name, avatar URL, bio HTML, `contact: [{title, url}]`) and is consumed by `bio.html`, which renders the `contact` list as plain text links.

**Styling**: a single `assets/css/style.css` (CSS custom properties on `:root`, redefined under `@media (prefers-color-scheme: dark)` — no manual theme toggle) covers the whole site, plus `assets/css/syntax.css` for Rouge code highlighting (loaded only on `post.html`, also palette-driven via the same custom properties).

**SEO/GEO**: `head.html` renders `{% seo %}` (jekyll-seo-tag) then `{% feed_meta %}` (jekyll-feed's `<link rel="alternate" type="application/atom+xml">` discovery tag — must stay paired with `{% seo %}`, it's easy to add the plugin and forget this tag). `{% seo %}` emits title, meta description, canonical URL, Open Graph/Twitter Card tags, and JSON-LD from `_config.yml`'s `title`/`description`/`url`/`author`/`logo`/`social` keys plus each page's own `title`/`description` front matter:
- `author` (name/email/**url**) feeds the JSON-LD `author` on every page and the Atom feed's author.
- `logo` (the same GitHub avatar URL used in `bio.html` — metadata only, doesn't violate the image-free rule above since it renders no new visible image) feeds the JSON-LD `publisher.logo` Google expects on `BlogPosting` rich results.
- `social.name`/`social.links` (sameAs) feed the JSON-LD entity on the homepage and `/about/` only (jekyll-seo-tag's `homepage_or_about?` check) — update `links` if profile URLs change.
- Post type (`BlogPosting`) vs. page type (`WebSite`/`WebPage`) in JSON-LD is inferred automatically from `page.date`, not set explicitly.

`about.md` additionally embeds a raw `<script type="application/ld+json">` Person schema block (kramdown passes raw HTML blocks through untouched, same mechanism as the Mermaid divs) — update it if bio facts (role, employer, education, profile links) change.

**`robots.txt`** and **`llms.txt`** live at the repo root as Liquid-templated pages (empty `---\n---` front matter, like `search.json`, so Jekyll runs them through Liquid but doesn't markdown-render them since their extension isn't a markdown one). `robots.txt` allows all crawlers and points to both `sitemap.xml` (from jekyll-sitemap) and `llms.txt`; jekyll-sitemap would otherwise auto-generate a bare-bones `robots.txt` itself, but backs off once a source file exists. `llms.txt` follows the [llms.txt convention](https://llmstxt.org) — a plain-Markdown index of the site (About link + every post title/categories/summary) meant for LLMs/generative engines to fetch directly instead of parsing rendered HTML; it loops `site.posts` the same way `blog.html` and `search.json` do, so keep it in sync if that loop's shape changes. Each post's summary line prefers its `description` front matter, falling back to a truncated `excerpt` only if `description` is unset — so every post should carry a `description` (see the note above about post front matter), otherwise its `llms.txt` entry is just the post's opening words out of context, which misrepresents the content.
