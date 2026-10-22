
# TrustVault Threat Model

## 1. Assets to Protect

- User credentials and session cookies.
- Uploaded documents and their contents.
- Document ownership and sharing permissions.
- Sharing suggestions and owner decisions.
- Audit records.
- Session secrets and deployment configuration.

## 2. Trust Boundaries

- An unauthenticated visitor must not access private documents.
- An authenticated user must not access another user's documents without
  explicit permission.
- The browser is untrusted. Authorization must be checked on the server.
- AI-generated suggestions are untrusted recommendations, not permissions.
- Uploaded files are untrusted input.
- Environment secrets must remain outside source control.

## 3. Threats and Mitigations

| Threat | Mitigation | Remaining concern |
|---|---|---|
| Unauthorized document download | Check ownership or explicit permission on every download | All new download routes need the same check |
| Cross-user data exposure | Test access using separate accounts | Test additional roles and document states |
| Password compromise | Store password hashes rather than plaintext passwords | Enforce strong password policy and rate limits |
| CSRF attacks | Validate CSRF tokens on state-changing form submissions | Review every POST route |
| Session theft | Use a strong secret and secure cookie settings in production | HTTPS and production cookie settings are required |
| Malicious uploads | Apply size limits and validate file handling | Add file-type validation and malware scanning where appropriate |
| AI grants excessive access | Require explicit owner approval before creating permission | Review suggestion logic and audit its decisions |
| Audit tampering | Record relevant actions and actors | A database administrator can alter local database records |
| Secret leakage | Exclude `.env`, database files, and private uploads from Git | Review repository history before publishing |
| Denial of service | Limit upload sizes | Add rate limiting and resource limits |
| Path traversal | Use server-generated storage names and safe path handling | Review all filesystem operations |
| Privilege escalation | Assign roles server-side; do not trust a submitted role | Add tests for unauthorized role changes |

## 4. Authorization Rules

1. Documents are private by default.
2. The owner can access their own document.
3. A viewer can access a document only if an explicit permission exists.
4. A suggestion does not grant access.
5. Only the document owner can approve or reject sharing for that document.
6. Unauthorized download requests must not return the document content.
7. Every state-changing operation must verify authentication and CSRF protection
   where cookie-based browser sessions are used.

## 5. AI Safety

The suggestion engine must not:
- Create permissions by itself.
- Approve its own recommendations.
- Override the document owner's decision.
- Bypass normal authorization checks.

The owner must see and approve a suggestion before access is granted.
Both the suggestion and the owner's decision should be auditable.

## 6. Security Testing

Run:

```powershell
python -m pytest -v
```

Tests should verify that:
- Unauthenticated downloads are denied.
- A different user cannot download a private document.
- A suggestion does not grant access.
- Only the owner can approve a suggestion.
- Approved permissions grant access only to the intended recipient.

## 7. Known Limitations

- SQLite is suitable for a prototype, not every production workload.
- Local database audit records are not tamper-proof.
- Rule-based suggestions may be wrong.
- Upload validation, rate limiting, HTTPS, secure deployment configuration,
  monitoring, and recovery procedures need production review.

## 8. Residual Risk

A compromised owner account can authorize sharing of that owner's documents.
A compromised server or database administrator may access stored documents
and modify local audit records. Production deployment requires appropriate
host security, least-privilege access, backups, monitoring, and incident
response procedures.
