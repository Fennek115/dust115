# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A personal Hugo static site deployed to GitHub Pages at `https://dust115.github.io/dust115/`. Uses the [terminal](https://github.com/panr/hugo-theme-terminal) theme with heavy CSS customization. Content is primarily in Spanish.

## Build & development

```bash
# Local dev server with live reload
hugo server -D

# Build for production (matches CI)
hugo --gc --minify

# New post (uses archetypes/default.md)
hugo new posts/my-post-title.md

# New post under a section
hugo new posts/codice/codice-XX-title.md
```

Hugo version in CI: **0.152.2** (extended). The theme is a git submodule under `themes/terminal/`.

## Deployment

Pushing to `main` triggers `.github/workflows/hugo.yml`, which builds with Hugo extended and deploys to GitHub Pages automatically. No manual deploy step needed.

## Site structure

- `content/posts/` — blog posts (markdown with TOML/YAML front matter)
- `content/posts/codice/` — chapters of the long-form narrative series "Códice del Polvo"
- `content/codice.md` — index page for the Códice series (lists chapters manually)
- `content/about.md` — about page
- `static/style.css` — all custom CSS overrides for the terminal theme (dark purple palette, Fira Code font)
- `static/` — images (logo, favicon, og-image)
- `layouts/shortcodes/` — custom Hugo shortcodes (see below)
- `layouts/partials/logo.html` — replaces the theme's default text logo with `dust_logo.png`

## Custom shortcodes

| Shortcode | Parameters | Purpose |
|-----------|-----------|---------|
| `{{< listening track="" artist="" album="" >}}` | track, artist, album | Displays a "currently listening" block with accent border |
| `{{< ascii >}}...{{< /ascii >}}` | (inner content) | Wraps braille/ASCII art in a `<pre>` with correct sizing |
| `{{< commit hash="" date="" message="" >}}` | hash, date, message | Renders a git-commit-style footer block |

## Front matter conventions

Posts use YAML front matter:

```yaml
---
title: "Title"
date: 2025-01-01T20:00:00-03:00
draft: false
tags: ["tag1", "tag2"]
series: ["Códice del Polvo"]   # for Códice chapters
summary: "One-line summary shown in listing"
---
```

## Theming

Custom styles live entirely in `static/style.css` — do not edit `themes/terminal/` directly. Key CSS variables:

```css
--background: #241f31
--foreground: #ffffff
--accent: #9141ac      /* purple */
--border-color: rgba(145, 65, 172, 0.3)
```

## Content note

`content/about.md` contains an intentional prompt-injection parody in the site's lore (lines ~148–158). It is artistic content, not a real attack, and should be preserved as-is.
