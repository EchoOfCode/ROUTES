# Phase 1 scope

## Included

- Email/password accounts (Argon2id), server-side sessions in HttpOnly cookies, CSRF protection, per-user data isolation
- Projects, URL-first onboarding with explicit authorisation confirmation
- Sandboxed website discovery: manifest, robots.txt, sitemaps, ≤25 pages, forms, links with parameters, JavaScript endpoint references, OpenAPI documents, sign-in/registration pages, technology detection with evidence, selective JavaScript rendering
- Source connection: public GitHub, private GitHub (temporary fine-grained token), ZIP upload (≤100 MB)
- Repository matching evidence plus developer confirmation
- Source profiling, Next.js route structure, pg database interactions, configuration references
- Static analysis: SQL injection data flow (detailed), Semgrep rules for secrets, command execution, insecure configuration and related patterns
- Background processing with Redis/RQ, live progress polling, cancellation, timeouts, controlled retries
- Retention: 5 assessments per project; temporary source deleted after analysis
- Docker Compose deployment with sandbox manager, restricted Docker API proxy and controlled network gateway

## Supported for detailed analysis

| Component | Supported |
|---|---|
| Language | JavaScript, TypeScript |
| Framework | Next.js (App Router and Pages Router API routes) |
| Runtime | Node.js |
| Database | PostgreSQL |
| Database client | `pg` (Pool, Client, pooled clients, local wrappers) |

Other repositories receive a basic profile and the general Semgrep rules, and are clearly marked `unsupported` or `partial`. ROUTES does not claim coverage it does not have.

## Finding statuses

- **Potential**: a suspicious pattern with a traced data flow (static evidence only). Almost all Phase 1 findings.
- **Inconclusive**: a pattern was found but data flow from user input could not be established.
- **Confirmed**: reserved for later phases (independent reproduction). Phase 1 never produces it.

## Explicitly not included

SQLMap or any attack execution, attack replay, attack-log ingestion, dynamic exploit verification, application replicas, patch generation or remediation, fix verification, GitHub commits/pushes, runtime SDKs or monitoring, Wazuh/Suricata, LLM-generated text, multiple attack modules, cloud deployment, hosted databases, paid services, dependency CVE scanning (dependencies are inventoried only), email verification and password recovery.

## Known limitations

- Taint tracking is intra-procedural with one hop into imported helpers; flows through classes, callbacks passed across modules, ORMs and query builders are not traced. Such cases may be missed or reported as *inconclusive*.
- Pages Router handlers that do not branch on `req.method` are reported with method `ANY`.
- Monorepos: only the root and first-level `package.json` files are considered.
- JavaScript rendering is used only for pages that look like client-rendered shells (max 8 per assessment).
- The developer's authorisation confirmation is a manual statement, not cryptographic proof of ownership.
- See [SECURITY.md](SECURITY.md#known-limitations) for isolation limitations.
