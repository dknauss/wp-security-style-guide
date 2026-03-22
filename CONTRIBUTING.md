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

After generated artifacts change, run:

```bash
python3 .github/scripts/validate-artifacts.py
npm run validate:pdf-visual
```

This smoke check confirms the tracked PDF, EPUB, and DOCX outputs exist, are
readable, and still contain expected canonical text and metadata markers. The
Playwright PDF visual smoke test compares a small set of critical page clips
against committed baselines.

## Maintainer Workflow

For canonical document changes:

1. Edit `WP-Security-Style-Guide.md`.
2. Run `bash .github/scripts/verify-metrics.sh docs/current-metrics.md` if the
   change affects structural counts, then update `docs/current-metrics.md` as
   needed.
3. Update `CHANGELOG.md` for any user-visible documentation or workflow change.
4. Merge to `main`.
5. Confirm the phased `Generate PDF, Word & EPUB Documents` workflow completes:
   it should build the outputs, run artifact and PDF visual validation, and only
   then publish regenerated files back to `main`.
6. Use the standalone `Validate Artifacts` and `Validate PDF Visuals` workflows
   for direct validator changes or manual rechecks without regenerating docs.
7. Create a version tag only when enough user-visible changes justify a release.
   After tagging, confirm the `Create Release` workflow publishes the generated
   artifacts for that tag.

For workflow-only changes:

1. Update `CHANGELOG.md` when the change affects maintainers or release
   behavior.
2. Manually dispatch the affected workflow after merge when a safe no-tag check
   is available.
3. Avoid testing the release workflow against a new tag unless you intend to
   publish a real release.

## Cross-Document Review Cadence

This repository is part of a four-document WordPress security series. Review it
against the companion repositories at least quarterly and before any release:

- `wp-security-benchmark`
- `wp-security-hardening-guide`
- `wordpress-runbook-template`

During each review, check:

- shared glossary terms and preferred terminology
- WordPress, PHP, and WP-CLI version references
- linked commands, external references, and support/reporting language
- whether a change here should also land in one or more companion repos

Record any follow-up as issues or pull requests in the affected repository so
cross-document drift is tracked explicitly. Use the `Series review` issue form
in this repository to capture each quarterly or pre-release review pass.

## Pull Requests

Pull requests should:

- describe what changed and why
- mention any source verification performed
- note whether metrics, changelog entries, or generated artifacts changed
- call out any cross-document follow-up needed in the benchmark, hardening
  guide, or runbook repos

Keep changes focused. Separate editorial cleanup from unrelated repository or
workflow changes when practical.
