# Contributing

Thanks for helping improve the WordPress Security Style Guide.

## Scope

Contributions are welcome for:

- factual corrections
- outdated terminology or guidance
- glossary additions or clarifications
- broken links or repository automation issues

This repository is an editorial reference. It is not the place for detailed
operations procedures or prescriptive benchmark controls unless that context is
necessary to explain writing or terminology guidance clearly.

## Before You Start

Read these files first:

- `README.md`
- `WP-Security-Style-Guide.md`
- `docs/current-metrics.md`
- `SECURITY.md`

Related repositories in this document series may also need aligned updates:

- `wp-security-benchmark`
- `wp-security-hardening-guide`
- `wordpress-runbook-template`

## Reporting Issues

- Use the GitHub issue templates for inaccurate guidance, broken examples, or
  improvement requests.
- Do not use public issues for security-sensitive reports. Follow
  `SECURITY.md` instead.

When filing a documentation bug, include the affected section or glossary term,
the source used to verify the issue, and whether companion repos may also need
updates.

## Editing Rules

- Treat `WP-Security-Style-Guide.md` as the canonical source.
- Keep generated artifacts aligned with the canonical Markdown source, but do
  not hand-edit binary artifacts unless the change specifically targets the
  generation pipeline or template files.
- Verify WordPress-specific terminology against primary sources such as
  `developer.wordpress.org`, WordPress core documentation, or WordPress.org
  project pages.
- Keep terminology aligned within the document and across the other repos in
  this series.
- Update `CHANGELOG.md` for user-visible documentation or workflow changes.

## Metrics Verification

If your change affects headings, glossary terms, cross-references, or other
structural counts, update `docs/current-metrics.md` and run:

```bash
bash .github/scripts/verify-metrics.sh docs/current-metrics.md
```

The metrics file is the canonical source of truth for the structural counts
used in this repository.

## Generated Documents

This repository tracks generated `.docx`, `.epub`, and `.pdf` artifacts.
Regenerate them through the documented GitHub Actions workflow or an equivalent
local Pandoc toolchain when required by the change.

If you cannot regenerate artifacts locally, note that in the pull request
instead of committing guessed outputs.

## Pull Requests

Pull requests should:

- describe what changed and why
- mention any source verification performed
- note whether metrics, changelog entries, or generated artifacts changed
- call out any cross-document follow-up needed in the benchmark, hardening
  guide, or runbook repos

Keep changes focused. Separate editorial cleanup from unrelated repository or
workflow changes when practical.
