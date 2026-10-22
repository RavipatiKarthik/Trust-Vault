
# TrustVault AI-Assisted Development Log

## Reusable Project Context

TrustVault is a Python/FastAPI document-sharing prototype. Its core security
rule is that document access is decided by server-side authorization, not
by UI visibility or AI recommendations.

The document owner controls sharing. AI can suggest a recipient but cannot
grant access automatically. A suggestion and the owner's approval or
rejection should be auditable.

Use the existing project structure and preserve working functionality.
Prefer small changes followed by automated tests. Do not claim a security
property is implemented unless the code and tests demonstrate it.

## Entry 1 — 2026-10-22 — Authentication

- **Prompt or summary:** Help implement login and password verification for
  the FastAPI application.
- **Output:** Login route, password-hash verification, and session handling.
- **Incorrect or incomplete bit:** The browser login initially returned to
  the login page; a successful test request was needed to isolate the issue.
- **Correction:** Tested the login form with its actual hidden `csrf` field.
  The automated request returned a 303 redirect to `/dashboard`.
- **Verification:** Login request tested with FastAPI TestClient.
- **Commit:** Add the actual commit hash and GitHub commit URL after committing.

## Entry 2 — 2026-10-22 — Document Access Control

- **Prompt or summary:** Implement document access so another user cannot
  download a private document.
- **Output:** Server-side ownership and permission checks.
- **Incorrect or incomplete bit:** Hiding a document or link in the interface
  alone would not prevent direct URL access.
- **Correction:** Check authorization in the download route and test requests
  using separate users.
- **Verification:** Record the actual test result after running pytest.
- **Commit:** Add the actual commit hash and GitHub commit URL after committing.

## Entry 3 — 2026-10-22 — AI-Assisted Sharing

- **Prompt or summary:** Add sharing recommendations without allowing AI
  to expand document permissions.
- **Output:** A suggestion workflow with an explicit owner decision.
- **Incorrect or incomplete bit:** A recommendation must not be treated as
  an authorization grant.
- **Correction:** Keep suggestions separate from permissions. Create the
  permission only after owner approval and record the decision.
- **Verification:** Test that access is denied before approval and allowed
  only for the approved recipient afterwards.
- **Commit:** Add the actual commit hash and GitHub commit URL after committing.

## Entry 4 — 2026-10-22 — Audit Logging

- **Prompt or summary:** Record document-sharing and access-related decisions.
- **Output:** Audit events containing the actor, action, document, and details.
- **Incorrect or incomplete bit:** An ordinary database audit table is not
  tamper-proof and must not be described as immutable.
- **Correction:** Document this limitation and review whether each important
  state change records an audit event.
- **Verification:** Inspect audit entries after upload and sharing decisions.
- **Commit:** Add the actual commit hash and GitHub commit URL after committing.

## Entry 5 — 2026-10-22 — Automated Tests and Documentation

- **Prompt or summary:** Create tests and document the security model.
- **Output:** Pytest coverage, setup instructions, and a threat model.
- **Incorrect or incomplete bit:** Passing a few tests does not prove the
  application is secure in every situation.
- **Correction:** Document the test scope and remaining risks honestly.
- **Verification:** Run `python -m pytest -v` and record the actual result.
- **Commit:** Add the actual commit hash and GitHub commit URL after committing.

## General Lessons

- AI output can be incorrect or incomplete and must be reviewed.
- Server-side authorization is required for every protected resource.
- Human approval must control permission changes.
- Tests provide evidence for specific behaviors, not a guarantee of security.
- Commit links must refer to real commits in the submitted repository.
