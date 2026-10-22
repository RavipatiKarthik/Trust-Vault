
# TrustVault Route and Authorization Guide

The FastAPI application uses browser routes and cookie-based sessions.
Confirm each route's actual implementation in `app/main.py` before submission.

## Authentication

| Route | Method | Who can call it | Purpose |
|---|---|---|---|
| `/` | GET | Anyone | Open the application |
| `/register` | GET | Anyone | Display registration form |
| `/register` | POST | Anyone | Register a viewer account |
| `/login` | GET | Anyone | Display login form |
| `/login` | POST | Anyone | Authenticate a user |
| `/logout` | POST | Authenticated user | End the session |

State-changing browser forms must validate CSRF tokens.

## Documents

| Route | Method | Who can call it | Purpose |
|---|---|---|---|
| `/dashboard` | GET | Authenticated user | Display dashboard |
| `/documents` | GET | Authenticated user | Display available documents |
| `/upload` | POST | Authenticated user | Upload a document |
| `/documents/{document_id}/download` | GET | Owner or explicitly authorized viewer | Download a document |

The download route must perform a server-side permission check before
returning file contents. An unauthorized user must not receive the file.

## Sharing and AI Suggestions

| Route | Method | Who can call it | Purpose |
|---|---|---|---|
| Sharing form route | POST | Document owner | Submit a sharing request or suggestion |
| AI suggestion route | POST | Document owner | Generate a recommendation |
| Suggestion approval route | POST | Document owner of the related document | Approve a suggestion |
| Suggestion rejection route | POST | Document owner of the related document | Reject a suggestion |
| Audit route | GET | As defined by the application's audit policy | Inspect audit events |

**Important:** The exact route paths for sharing, suggestions, approval,
rejection, and audit must be copied from `app/main.py`. Do not submit
placeholder paths as if they were verified endpoints.

## Authorization Requirements

- Authentication is required for protected routes.
- Document ownership or explicit permission is required for downloads.
- Only the relevant owner may approve or reject a sharing suggestion.
- A suggestion must not create permission by itself.
- CSRF protection must apply to cookie-authenticated state-changing forms.
- Errors must not reveal protected document contents.

## Interactive API Documentation

When the server is running locally, open:

http://127.0.0.1:8000/docs

Review the actual registered endpoints and compare them against this guide
before submitting the project.
