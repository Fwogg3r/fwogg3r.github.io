# fwogg3r.github.io

Static GitHub Pages site (fwogg3r.com) plus Firebase project `fwogg3r-team` (Auth + Firestore). Never put secrets in this public repo. Permission design: `docs/permissions.md`.

## Permission schema rule (mandatory)

Any service added or changed through the website must be added to the permission schema in the same change:

1. `services.json` (schema source) and the Firestore `services/{id}` catalog (re-seed from the Permissions tab or edit there).
2. The hard-coded service-id and level allow-list in `firestore.rules` (`validGrants`, plus `isHigh`/`highUntouched`/`hasHigh` when the service is `highRisk`). Rules cannot read the catalog, so they must mirror `services.json`.
3. Its enforcement: a Cloudflare Access app/policy synced from Firestore by `Z:\shared\access-sync` (`cfAccessApp`), or the service's own check (`enforcedBy`: `own-login` / `agentdash`).
4. Links to the service on the team page must be gated by the grant (`members.js` / `permissions.js`), never hard-coded.
5. Update `docs/permissions.md`.

Other rules: the owner (`tbryant@fwogg3r.com`) is hard-coded in `firestore.rules` and `auth.js` and is never stored as a role; render user-supplied text with `textContent` only; keep the strict CSP on `members.html` (no inline scripts, no Stripe there); never enable custom OIDC/SAML Firebase providers (they can assert `email_verified`).
