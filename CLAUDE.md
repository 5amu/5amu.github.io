# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Jekyll static site (Valerio Casalino's blog), hosted on GitHub Pages. It has two independent parts:

- The Jekyll-generated blog (posts, layouts, includes, assets).
- `links/index.html` — a standalone, hand-written static HTML page (a link-in-bio page) with no Jekyll front matter. It is served as-is and is not templated.

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

**Posts** live in `_posts/`, named `YYYY-MM-DD-title.md`. `_config.yml` applies `layout: post` and permalink `/p/:title/` to everything under `_posts` by default, so individual post front matter usually only needs `categories`:

```yaml
---
categories:
  - dev
  - research
---
```

**Layouts** (`_layouts/`):
- `blog.html` — the homepage (`index.md` uses `layout: blog`). Renders the bio and a plain text list (`ul.post-list`) of `site.posts` — date, title, `#category` tags — no images.
- `post.html` — individual post pages. Renders title/date/tags, then `{{content}}`, then loads Mermaid (see below) via an inline `<script type="module">`.

**Includes** (`_includes/`) are shared partials: `head.html` (stylesheets), `header.html` (site title + nav), `footer.html`, `bio.html` (reads `_data/author.yml` for the avatar and contact links).

**The site is intentionally image-free.** No post cover/thumbnail images, no icon images for contact links (they're plain text, e.g. "github", "linkedin", joined with " · " in `bio.html`), no `jemoji` plugin (removed from `_config.yml` — write literal unicode emoji in post bodies instead of `:shortcode:` syntax, since jemoji renders shortcodes as `<img>`). The only image on the whole site is the author's GitHub avatar (`_data/author.yml`'s `dp` field, an `avatars.githubusercontent.com` URL), used in `bio.html` and in `links/index.html`, always linked to `https://github.com/5amu`. Keep it that way when adding content — don't reintroduce screenshots/diagrams as raster images.

**Diagrams belong in Mermaid, not images.** Post pages load Mermaid from a CDN (`post.html`) and auto-render any `<div class="mermaid">...</div>` raw-HTML block in the markdown (kramdown passes raw HTML blocks through untouched, which sidesteps Rouge trying and failing to syntax-highlight a "mermaid" fenced code block as a language it doesn't know). See `_posts/2022-10-07-bgp-hijacking.md` for worked examples (sequence and graph diagrams). This only applies to `post.html` — the homepage doesn't load Mermaid.

**Author/contact info** lives in `_data/author.yml` (name, avatar URL, bio HTML, `contact: [{title, url}]`) and is consumed by `bio.html`, which renders the `contact` list as plain text links.

**Styling**: a single `assets/css/style.css` (CSS custom properties on `:root`, redefined under `@media (prefers-color-scheme: dark)` — no manual theme toggle) covers the whole site, plus `assets/css/syntax.css` for Rouge code highlighting (loaded only on `post.html`, also palette-driven via the same custom properties). `links/index.html` is a separate static page (no Jekyll front matter, so no Liquid) that links the same `style.css` and adds a small inline `<style>` block for its own layout.
