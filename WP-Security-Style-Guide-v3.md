��A Style Guide for Writing about

**WordPress and Security**

Principles, Practices, and Terminology

for Clear, Honest, and Empowering Security Communication

Dan Knauss

February 2026 • Version 3.0

## 1. Security, Vulnerability, and Trust in Open Source

We sell a security product, but the product is not security.

As part of the Open Web, WordPress is a commons, and so is WordPress security.

Security is never absolute, which is to say, security always comes with vulnerability.

We are always vulnerable in some way, however small. We are never completely invulnerable.

Open source leads by refusing to pretend software can ever be perfect — especially by hiding the source code.

Open source means working in the open — together.

That's never easy. We must constantly resist our inclination to hide defects and vulnerabilities — to create a mask of invulnerability based on obscurity and deception.

We are confident in the security of our systems when we believe our trust is well-founded in our tools, partners, experts, and other authorities we rely on for advice and insight.

Our confidence and trust require maintenance, learning, and growth in cooperative relationships. Together, we take care of our shared tools, knowledge, and relationships — with colleagues, partners, customers, and even competitors.

Because our security and vulnerability are shared collectively, so is responsibility. If responsibility is shared, so is the quality, security, and trust it generates in our customers and marketplace.

## 2. In/vulnerability: Dilemma and Opportunity

Writing about security, especially in open source, is a tricky rhetorical situation. There are several dilemmas presented to anyone with "bad news" facing an audience of superiors, peers, customers, and competitors, especially in contexts where "professionalism" is often misconstrued as a performance or mask of invulnerability, if not omniscience.

Admitting errors, defects, new risks, and security failures may cause individuals, organizations, and brands to lose trust. But denying, hiding, or lying about security failures always fails harder in the end. It's devastating to brands, products, reputations, and careers. We see this happen time and again.

Maximizing security — and trust — in open source requires exposing all our work (warts and all) to everyone for review (or exploitation) by anyone.

## 3. Writing about Security and Vulnerabilities in WordPress

### 3.1 Lead with Solutions, Not Fear

Be as accurate as possible about threats, but orient your writing toward solutions. Security writing should inform and empower, not alarm or paralyze. The goal is to help people understand real risks and take effective, proportionate action.

> **Guiding Principle**
> Don't use fear, uncertainty, and doubt (FUD) to sell solutions. Dispel fear with knowledge. Demonstrate how reasonable levels of risk can be managed. Foster confidence in the tools, information, and relationships that empower WordPress users to protect their web properties.


When describing threats, always provide an actionable path forward. What knowledge, tools, or relationships will most effectively reduce the risk? Lead with that. When writing about incidents or breaches, extract the lesson and present it constructively. There is almost always an upside in what can be learned and improved.

### 3.2 Be Realistic and Proportionate

Avoid both minimizing and overstating threats. Don't tell open-ended stories of vague, dark unknowns. Be specific about what the risk is, who it affects, and what can be done about it. If a vulnerability is critical, say so clearly. If a risk is low for most users, say that too.

Remember that the vast majority of WordPress compromises trace back to a few recurring causes: weak or reused passwords, outdated plugins with known vulnerabilities, and neglected server environments. This is not new information for security professionals, but it is new for many WordPress users. Repeat these messages clearly and without condescension.

### 3.3 Place Responsibility Where It's Constructive

When assigning responsibility, make sure it serves a purpose. Responsibility should point toward action, not blame. Be clear about what is within the user's control, what depends on their hosting provider, and what falls to the WordPress core team or plugin developers. Level with your audience, but don't push them away.

| **✓ Do** | **✗ Don't** |
| — | — |
| "This vulnerability affects sites running Plugin X versions prior to 3.2. Update immediately to version 3.2.1, which includes a patch." | "Your site could be hacked at any moment if you use Plugin X." |
| "Strong passwords and two-factor authentication significantly reduce the risk of unauthorized access." | "If you get hacked, it's your own fault for using weak passwords." |


### 3.4 Make Security Accessible and Engaging

Write for the WordPress user who is still learning. Security topics can be dry, intimidating, or both. Work to make them interesting, practical, and empowering. Use clear examples, relatable scenarios, and plain language. If a concept requires technical depth, build up to it. Always define terms on first use.

## 4. Audience, Voice, and Tone

### 4.1 Know Your Audiences

Security writing in the WordPress ecosystem addresses several overlapping audiences. Your content may reach any combination of them, so clarity and accessibility are essential:

-   WordPress site owners and administrators who manage one or more sites and need practical, actionable guidance.

-   Developers and engineers building custom themes, plugins, or integrations who need technically precise information.

-   Enterprise decision-makers (CTOs, CISOs, IT directors) evaluating WordPress for compliance, risk, and organizational security requirements.

-   Non-technical stakeholders (marketers, content editors, business owners) who interact with WordPress daily but have limited security knowledge.

-   WordPress community members and contributors, including those involved in core development, plugin review, and support forums.

### 4.2 Voice

Your voice should convey the brand's personality and values. It is:

-   **Confident** — grounded in knowledge and experience, never bluffing or overpromising.

-   **Candid** — honest about problems, limitations, and uncertainty.

-   **Expert** — technically accurate, well-sourced, and current.

-   **Accessible** — warm, clear, and human. Real people write this, and real people read it.

-   **Open** — reflecting the open-source values of transparency, collaboration, and shared responsibility.

### 4.3 Tone

Tone adapts to context while the voice remains consistent. The default tone for security writing is:

-   **Realistic about problems** — acknowledge risks squarely without catastrophizing.

-   **Optimistic about solutions** — emphasize what can be done and what's working.

-   **Down-to-earth** — avoid jargon-heavy abstractions. Prefer plain language. Explain technical terms when you use them.

> **Tone Shift by Context**
> Vulnerability disclosure: measured, precise, actionable. No editorializing.
> Educational content: encouraging, patient, building understanding step by step.
> Incident response guidance: calm, clear, directive. Prioritize the most important actions first.
> Thought leadership: reflective, well-sourced, open to nuance and debate.


## 5. Inclusive Communication

### 5.1 Bring Outsiders In

Security writing can easily become a closed conversation among experts. Actively work against this. Explain jargon and technical terms the first time you use them. Spell out acronyms on first use. Helping people learn the vocabulary means helping them enter the community and take responsibility for their own security.

### 5.2 Language Choices

Use inclusive, contemporary language. Some traditional security terminology carries exclusionary connotations or has clearer modern alternatives:

| **✓ Do** | **✗ Don't** |
| — | — |
| allowlist / denylist | whitelist / blacklist |
| primary / replica | master / slave |
| credential stuffing attack | brute-force hacking |
| threat actor | hacker (when meaning attacker) |


When referring to people who exploit systems maliciously, prefer specific terms like "threat actor," "attacker," or "cybercriminal" over the ambiguous "hacker," which has positive connotations in many technical communities.

### 5.3 WordPress-Specific Terminology

WordPress has its own vocabulary. Use terms consistently and prefer the forms familiar to the WordPress community:

-   **Dashboard** — the WordPress admin interface (avoid "backend" in user-facing writing).

-   **Plugin** — an extension that adds functionality to WordPress. Always one word, lowercase in running text.

-   **Theme** — a collection of templates and stylesheets that control a site's visual presentation.

-   **wp-admin** — the URL path to the WordPress admin area. Set in monospace (wp-admin) when referring to the path.

-   **wp-config.php** — the primary WordPress configuration file. Always in monospace.

-   **Multisite** — a WordPress feature enabling multiple sites on one installation. One word, capitalized.

-   **Auto-update** — WordPress's built-in mechanism for applying updates automatically. Hyphenated.

## 6. Technical Formatting Guidelines

### 6.1 Two-Font System

Use two font treatments to distinguish between human-readable and machine-readable terms:

-   **Normal font** (the document's body typeface) for names of products, organizations, document titles, and human-facing concepts: WordPress, Cloudflare, an SSL certificate.

-   **Monospace font** (like this) for code, commands, file paths, configuration values, and machine-facing identifiers: wp-config.php, DISALLOW_FILE_MODS, wp_kses().

### 6.2 When to Use Monospace

-   File names and paths: wp-config.php, /wp-content/uploads/

-   Configuration constants and PHP functions: FORCE_SSL_ADMIN, current_user_can()

-   Command-line tools and commands: wp-cli, ssh, fail2ban

-   Database fields, table names, and environment variables

-   HTTP headers, status codes, and URL parameters: X-Frame-Options, 403, ?author=1

-   CVE identifiers and version numbers in technical context: CVE-2024-1234, WordPress 6.5.2

### 6.3 When to Use Normal Font

-   Product names and their versions in running prose: WordPress 6.5, Cloudflare, Patchstack.

-   Names of organizations, teams, and conferences: OWASP, DEF CON, WordPress Security Team.

-   Concepts and roles: administrator, two-factor authentication, session cookie.

-   Error messages and security prompts when quoting them for a non-technical audience (use quotation marks).

### 6.4 Bold and Emphasis

Use bold sparingly for key terms being defined, important warnings, and UI elements the reader needs to find and click. Use italics for emphasis, titles of publications, and introducing new terms in running text.

### 6.5 Acronyms

Spell out acronyms on first use, followed by the abbreviation in parentheses: cross-site scripting (XSS), two-factor authentication (2FA). Use the acronym alone in subsequent references. If the acronym is more widely recognized than the full form (e.g., SQL, HTML, SSH), the spelled-out version can be omitted for technical audiences.

## 7. Writing about Vulnerabilities

### 7.1 Disclosure and Reporting

When writing about specific vulnerabilities, follow established responsible disclosure conventions:

1.  Use the official CVE identifier when available.

2.  Name the affected software and specific versions.

3.  Describe the vulnerability type using standard terminology (XSS, SQL injection, CSRF, etc.).

4.  State the severity using an established framework (CVSS score, Patchstack's severity rating, or the plugin repository's classification).

5.  Provide the remediation: update to version X, apply a configuration change, or remove the affected component.

6.  Credit the researcher or security team that reported the issue, consistent with responsible disclosure norms.

> **Template: Vulnerability Summary**
> [Plugin/Theme Name] versions [X] through [Y] contain a [vulnerability type] vulnerability ([CVE-YYYY-NNNNN]) rated [severity]. Authenticated users with [role] access or above can [exploit description]. Update to version [Z] or later to resolve this issue. [Credit to researcher/team for responsible disclosure.]


### 7.2 Severity Language

Match the urgency of your language to the actual severity of the vulnerability. Avoid words like "critical" or "dangerous" for low-severity issues. Conversely, don't understate genuinely critical vulnerabilities.

| **✓ Do** | **✗ Don't** |
| — | — |
| "Critical: unauthenticated remote code execution" | "Extremely dangerous flaw found in popular plugin!" |
| "Low severity: authenticated stored XSS requiring administrator role" | "Minor issue, probably nothing to worry about." |


### 7.3 Avoiding Sensationalism

Security news attracts clicks, and sensationalism is common in the WordPress security ecosystem. Resist it. Inflated threat descriptions erode trust, cause unnecessary alarm, and make it harder for users to distinguish genuinely urgent issues from routine maintenance.

Write with precision. If a vulnerability requires administrator-level authentication to exploit, say so. If it affects a plugin with 200 active installations, provide that context. Help the reader assess whether the issue is relevant to them.

## 8. Glossary of WordPress Security Terms

This glossary defines security-related terms as they are used in the WordPress ecosystem. Terms are listed alphabetically. Where a term has both a general and a WordPress-specific meaning, the WordPress usage is emphasized.

> **2FA / MFA** — Two-factor authentication / multi-factor authentication. A security mechanism requiring two or more verification methods (typically a password plus a time-based code from an authenticator app or hardware key) to access an account. In WordPress, 2FA is implemented through plugins or managed hosting features.
>
> **Admin (role)** — The highest default user role in a single-site WordPress installation. Administrators can install plugins, modify themes, manage users, and change site settings. On a Multisite network, the equivalent is Super Admin.
>
> **Auth cookie** — The session cookie WordPress sets when a user logs in. It contains an encrypted token that identifies the authenticated user and allows them to access the Dashboard without re-entering credentials until the cookie expires or the session is terminated.
>
> **Auto-update** — WordPress's built-in mechanism for automatically applying updates. Since version 3.7, minor (security) releases are applied automatically by default. Major version and plugin/theme auto-updates can be enabled separately.
>
> **Brute-force attack** — An attack method that attempts to guess login credentials by systematically trying many combinations. In WordPress, this typically targets the wp-login.php form. Mitigated by rate limiting, 2FA, and strong password policies.
>
> **Capability** — A specific permission assigned to a WordPress user role. Examples include edit_posts, manage_options, and install_plugins. Capabilities can be customized with plugins or code to implement the principle of least privilege.
>
> **Content Security Policy (CSP)** — An HTTP response header that controls which resources (scripts, styles, images) a browser is allowed to load on a page. Effective against XSS attacks. Configured at the server or application level.
>
> **Credential stuffing** — An automated attack that uses username/password pairs leaked from other breaches to attempt login on a target site. Effective against users who reuse passwords across services.
>
> **Cross-Site Request Forgery (CSRF)** — An attack that tricks an authenticated user into performing an unintended action. WordPress mitigates CSRF through nonces—cryptographic tokens tied to a specific user, action, and time window.
>
> **Cross-Site Scripting (XSS)** — A vulnerability that allows an attacker to inject malicious scripts into web pages viewed by other users. WordPress provides escaping functions (esc_html(), esc_attr(), wp_kses()) to prevent XSS.
>
> **CVE** — Common Vulnerabilities and Exposures. A standardized identifier (e.g., CVE-2024-1234) assigned to publicly disclosed security vulnerabilities. CVE numbers are issued by authorized numbering authorities.
>
> **CVSS** — Common Vulnerability Scoring System. A standardized framework for rating the severity of vulnerabilities on a 0--10 scale. Scores classify vulnerabilities as None (0), Low (0.1--3.9), Medium (4.0--6.9), High (7.0--8.9), or Critical (9.0--10.0).
>
> **Dashboard** — The WordPress administrative interface, accessed via /wp-admin/. Prefer "Dashboard" over "backend" or "admin panel" in user-facing writing.
>
> **Fail2Ban** — A server-level intrusion prevention tool that monitors log files and bans IP addresses showing malicious patterns (e.g., repeated failed login attempts). Integrates with WordPress through custom jail configurations.
>
> **FUD** — Fear, uncertainty, and doubt. A rhetorical strategy that exaggerates threats to motivate action (usually purchasing a product). Avoid FUD in security writing; it erodes trust and impairs informed decision-making.
>
> **Hardening** — The process of reducing a system's attack surface by disabling unnecessary features, restricting permissions, and applying security configurations. In WordPress, hardening includes setting constants in wp-config.php, restricting file permissions, and disabling XML-RPC.
>
> **Infostealer** — A category of malware designed to exfiltrate sensitive data from infected devices, including passwords, session cookies, browser data, and cryptocurrency wallets. Infostealers are a rapidly growing threat vector affecting all web platforms, including WordPress.
>
> **Multisite** — A WordPress feature that allows multiple sites to be run from a single WordPress installation, sharing the same database and file system. Security considerations differ from single-site installations, particularly around user roles and network-level settings.
>
> **Nonce** — In WordPress, a "number used once"—a cryptographic token used to verify that a request originates from a legitimate, authenticated user and is tied to a specific action. Nonces protect against CSRF attacks.
>
> **OWASP Top 10** — A regularly updated list of the ten most critical web application security risks, published by the Open Web Application Security Project. Used as a benchmark for evaluating and improving application security.
>
> **Patch / Patching** — A software update that fixes a specific bug or vulnerability. In WordPress, patches are delivered through minor version releases (e.g., 6.5.1) and plugin/theme updates. "Virtual patching" refers to WAF rules that block exploitation of a known vulnerability before a code-level fix is applied.
>
> **Phishing** — A social engineering attack that uses deceptive communications (usually email) to trick recipients into revealing credentials, installing malware, or taking other harmful actions. "Spear phishing" targets specific individuals; "whaling" targets executives.
>
> **Plugin** — A software extension that adds functionality to WordPress. Plugins run with the same privileges as WordPress core, making them a significant component of the site's security posture. Always one word, lowercase in running text.
>
> **Principle of Least Privilege (PoLP)** — A security principle requiring that users and processes be granted only the minimum permissions necessary to perform their functions. In WordPress, this means limiting admin accounts, restricting file modification capabilities, and using custom roles.
>
> **Responsible disclosure** — A practice in which a security researcher reports a vulnerability privately to the affected vendor, allowing time for a patch before public disclosure. The WordPress Security Team follows this practice and encourages it across the ecosystem.
>
> **REST API** — WordPress's built-in API for programmatic access to site data. Sensitive endpoints require authentication. The REST API can expose information (e.g., user enumeration via /wp-json/wp/v2/users) if not properly restricted.
>
> **Role** — A named collection of capabilities in WordPress. Default roles include Subscriber, Contributor, Author, Editor, and Administrator. Custom roles can be created to implement granular access control.
>
> **Session hijacking** — An attack in which a threat actor obtains a valid session cookie (e.g., through XSS, network interception, or infostealer malware) and uses it to impersonate the authenticated user. 2FA does not protect against hijacked sessions because the session is already authenticated.
>
> **SQL injection (SQLi)** — An attack that inserts malicious SQL code into queries executed by the database. WordPress mitigates SQLi through the $wpdb-\>prepare() method, which parameterizes queries.
>
> **Supply chain attack** — An attack that compromises software through its dependencies or distribution channels rather than targeting the software directly. In WordPress, this can occur through compromised plugins, themes, or build tools.
>
> **Theme** — A collection of template files and stylesheets that control a WordPress site's visual presentation. Themes can introduce security vulnerabilities through insecure coding practices, particularly in custom themes.
>
> **Threat actor** — An individual or group that attempts to exploit vulnerabilities in systems or people for malicious purposes. Preferred over "hacker" in security writing because "hacker" has positive connotations in technical communities.
>
> **Virtual patching** — A WAF rule that blocks exploitation of a known vulnerability at the network or application level, providing protection before a code-level patch is available. Services like Patchstack and Cloudflare offer virtual patching for WordPress.
>
> **Vulnerability** — A weakness in software, configuration, or process that could be exploited to compromise a system's security. In WordPress, vulnerabilities are categorized by type (XSS, SQLi, CSRF, etc.) and severity (CVSS score).
>
> **WAF** — Web Application Firewall. A security layer that filters and monitors HTTP traffic between a web application and the internet. In WordPress, WAFs may operate at the server level (ModSecurity), application level (Wordfence), or network edge (Cloudflare).
>
> **wp-config.php** — The primary WordPress configuration file, located in the site's root directory (or one level above). Contains database credentials, authentication keys, and security constants. Should be restricted to file permission 600 or 640.
>
> **XML-RPC** — A legacy remote procedure call protocol in WordPress (xmlrpc.php). Historically used for remote publishing and pingbacks, it is a common target for brute-force amplification attacks. Recommended to disable unless specifically required.
>
> **Zero-day** — A vulnerability that is publicly unknown and unpatched—the vendor has had "zero days" to address it. In formal writing, prefer "previously undisclosed vulnerability" or "publicly undisclosed vulnerability." Hyphenate when used as an adjective: a zero-day vulnerability.
>
> **Zero Trust** — A security model that requires continuous verification of all users and devices, regardless of network location. No user or system is trusted by default. In WordPress, Zero Trust principles inform practices like requiring 2FA, enforcing session limits, and restricting admin access by IP or device.

## 9. References and Further Reading

**Style and Writing Guides**

-   [Bishop Fox Cybersecurity Style Guide](https://bishopfox.com/resources/cybersecurity-style-guide) — the comprehensive reference for cybersecurity terminology and formatting conventions. This style guide is directly indebted to it.

-   [Google Developer Documentation Style Guide](https://developers.google.com/style/) — general technical writing guidance.

-   [Microsoft Writing Style Guide](https://learn.microsoft.com/en-us/style-guide/) — conventions for writing about software interfaces and procedures.

**Security Terminology References**

-   [NIST Glossary of Key Information Security Terms](https://csrc.nist.gov/glossary)

-   [OWASP Glossary](https://owasp.org/www-community/Glossary)

-   [SANS Security Glossary](https://www.sans.org/security-resources/glossary-of-terms/)

**WordPress Security Resources**

-   [WordPress Security White Paper](https://developer.wordpress.org/apis/security/)

-   [Hardening WordPress — Advanced Administration Handbook](https://developer.wordpress.org/advanced-administration/security/hardening/)

-   [Patchstack WordPress Vulnerability Database](https://patchstack.com/database/)

**License and Attribution**

This style guide is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0). Terminology and formatting conventions are adapted from and indebted to the Bishop Fox Cybersecurity Style Guide (2023), used with attribution.
��2Ffile:///Users/danknauss/Desktop/Security/WP-Security-Style-Guide-v3.md