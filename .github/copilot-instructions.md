# Copilot Instructions

## Project Overview

WP Security Style Guide — philosophy, voice, and glossary for all WordPress security writing. This is the terminology authority for the companion [Security Benchmark](https://github.com/dknauss/wp-security-benchmark) and [Hardening Guide](https://github.com/dknauss/wp-security-hardening-guide). Documentation-only repository (Markdown + PDF). No code, no build step, no dependencies.

Licensed CC BY-SA 4.0.

## Repository Structure

- `WP-Security-Style-Guide.md` — The primary document. Voice, glossary, and writing conventions.
- `README.md` — Project overview and contribution guidance.
- `WP-Security-Style-Guide.pdf` — PDF export of the style guide.

## Writing Conventions

- This document is the glossary and terminology authority. Definitions here override usage in the other two documents.
- "Dashboard" preferred over "admin panel" or "backend."
- `wp-config.php` always in monospace backticks.
- Acronyms spelled out on first use (section 6.5).
- Current WordPress version coverage: 6.9 (February 2026).

## Key Technical Context

- WordPress uses bcrypt password hashing by default since WP 6.8 (April 2025), with SHA-384 pre-hashing and BLAKE2b for tokens.
- WordPress 7.0 is due April 9, 2026 — version references will need updating.
