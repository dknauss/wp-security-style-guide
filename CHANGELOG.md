# Changelog

All notable changes to the WordPress Security Style Guide.

## Unreleased

### Added
- Added a `Series review` issue form so quarterly and pre-release cross-document alignment checks can be tracked explicitly.
- Added a repo-local generated-artifact smoke validator and a dedicated `Validate Artifacts` workflow for PDF, EPUB, and DOCX outputs.

### Changed
- Renamed comparison-table headers from `Do` / `Don't` to `Recommended` / `Avoid` for clearer plain-text guidance across all output formats.
- Replaced checkmark and cross symbols in comparison-table headers with plain text so Markdown, PDF, EPUB, and DOCX outputs render consistently.
- Set a short PDF running header title so long document titles no longer wrap into the page body area.
- Hardened GitHub release automation fallback handling and pinned reusable workflow and action references to immutable commits for more reproducible CI/CD runs.
- Documented the maintainer edit, verification, artifact-generation, release, and cross-document review workflow for this repository and its companion document series.

## 1.1.0 — 2026-03-21

### Changed
- Standardized license metadata on the canonical Creative Commons legal text and normalized in-repo references to `CC-BY-SA-4.0`.
- Added explicit repository health files (`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, `.gitattributes`) and linked them from the README so the repo no longer relies on inherited defaults for contributor guidance.
- Added a shared `Project Health` section in the README and aligned contributor and AI-assisted editorial copy with the rest of the security-document series.
- Replaced the hard-coded local verification path in `docs/current-metrics.md` with `git rev-parse --show-toplevel` for path-independent maintenance checks.
- Refreshed version-reference examples for the WordPress 7.0 release cycle and kept PHP-version guidance aligned with the current document set baseline.
- Corrected the WP-CLI checksum command names in glossary guidance to use `wp core verify-checksums` and `wp plugin verify-checksums`.
- Added centered page numbering to `.github/pandoc/reference.docx` so DOCX-derived PDF output includes footer page numbers through the shared generation pipeline.
- Replaced the repo-local document-generation workflow with a caller to the shared reusable workflow in `ai-assisted-docs`, keeping the primary markdown source and generated artifact names unchanged.

### Added
- `CHANGELOG.md` — this file.
- `docs/current-metrics.md` — architectural fact counts with verification commands.

## 1.0 — 2026-03-08

### Added
- Initial public release: editorial reference for writing about WordPress security.
- 12 major sections covering security communication principles, audience and voice, inclusive communication, technical formatting, vulnerability writing, and a comprehensive glossary.
- 137 glossary terms with cross-references (53 "See also:" links).
- Operational appendix for internal vulnerability communication workflow.
- PDF, DOCX, and EPUB formats via Pandoc CI/CD pipeline.
- Editorial review by three frontier LLMs with human editorial approval.
