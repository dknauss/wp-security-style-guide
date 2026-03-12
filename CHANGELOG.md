# Changelog

All notable changes to the WordPress Security Style Guide.

## Unreleased

### Changed
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
