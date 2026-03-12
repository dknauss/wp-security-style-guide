# Current Metrics (Canonical)

This file is the single source of truth for architectural counts in the WordPress Security Style Guide. Check this file before writing any count in prose, and update it when adding or removing terms, sections, or structural elements.

Last verified: 2026-03-12

## Architectural Facts

| Fact | Value | Verification command | Last changed |
|---|---:|---|---|
| Document lines | 693 | `wc -l WP-Security-Style-Guide.md` | v1.1 |
| Major sections (H2) | 12 | `grep -cE '^## ' WP-Security-Style-Guide.md` | v1.0 |
| Subsections (H3) | 26 | `grep -cE '^### ' WP-Security-Style-Guide.md` | v1.0 |
| Glossary terms | 139 | `grep -cE '^\*\*' WP-Security-Style-Guide.md` | v1.1 |
| "See also:" cross-references | 55 | `grep -c 'See also:' WP-Security-Style-Guide.md` | v1.1 |
| Table rows | 28 | `grep -cE '^\| ' WP-Security-Style-Guide.md` | v1.0 |
| Blockquote lines | 13 | `grep -cE '^>' WP-Security-Style-Guide.md` | v1.0 |
| Code fences | 0 | `grep -c '^\`\`\`' WP-Security-Style-Guide.md` | v1.0 |
| WP-CLI commands | 0 | `grep -cE '^\s*wp ' WP-Security-Style-Guide.md` | v1.0 |
| Output formats | 4 | Markdown, DOCX, EPUB, PDF | v1.0 |

## Key Content Areas

| Section | Focus | Terms/Rules |
|---|---|---|
| 1–2 | Philosophy | Security, vulnerability, trust in open source |
| 3 | Writing guidelines | 7 subsections on accuracy, framing, attribution |
| 4 | Audience and voice | 3 subsections on tone calibration |
| 5 | Inclusive communication | 3 subsections on terminology, accessibility |
| 6 | Technical formatting | 5 subsections on code, links, version references |
| 7 | Vulnerability writing | 7 subsections on disclosure, severity, communication |
| 8 | Glossary | 139 defined terms with cross-references |
| 9 | Operational appendix | Internal vulnerability communication workflow |

## Terminology Coverage

The glossary serves as the authoritative terminology reference for all four documents in the security series. When a term is used in the Benchmark, Hardening Guide, or Runbook, it must match the glossary definition here.

Key terminology rules enforced across the series:
- "allowlist" / "denylist" (not whitelist/blacklist)
- "Dashboard" (capitalized, referring to wp-admin)
- "WP-CLI" (hyphenated, all caps)
- "WordPress" (capital W, capital P)

## Verification Procedure

Run after any structural edit:

```bash
cd /Users/danknauss/Documents/GitHub/wp-security-style-guide

echo "=== Document size ==="
wc -l WP-Security-Style-Guide.md

echo "=== Structure ==="
echo "H2 sections: $(grep -cE '^## ' WP-Security-Style-Guide.md)"
echo "H3 subsections: $(grep -cE '^### ' WP-Security-Style-Guide.md)"

echo "=== Glossary ==="
echo "Terms: $(grep -cE '^\*\*' WP-Security-Style-Guide.md)"
echo "See also links: $(grep -c 'See also:' WP-Security-Style-Guide.md)"

echo "=== Content ==="
echo "Table rows: $(grep -cE '^\| ' WP-Security-Style-Guide.md)"
echo "Blockquotes: $(grep -cE '^>' WP-Security-Style-Guide.md)"
echo "Code fences: $(grep -c '^```' WP-Security-Style-Guide.md)"
```

## Update Procedure

1. After any edit to `WP-Security-Style-Guide.md`, run the verification script above.
2. Compare results to this table. Update any changed values.
3. If a glossary term was added or removed, update the count and verify cross-references.
4. Update `CHANGELOG.md` with the change.
