# fwogg3r.github.io

Static GitHub Pages site (fwogg3r.com) plus Firebase project `fwogg3r-team` (Auth + Firestore). Never put secrets in this public repo. Permission design: `docs/permissions.md`.

## Permission schema rule (mandatory)

Any service added or changed through the website must be added to the permission schema in the same change:

1. `services.json` (schema source) and the Firestore `services/{id}` catalog (re-seed from the Permissions tab or edit there).
2. The hard-coded service-id and level allow-list in `firestore.rules` (`validGrants`, the `m.size()` cap, plus `isHigh`/`hasHigh` when the service is `highRisk`; `validService` lists the allowed `enforcedBy` values). Rules cannot read the catalog, so they must mirror `services.json`.
3. Its enforcement: a Cloudflare Access app/policy synced from Firestore by `Z:\shared\access-sync` (`cfAccessApp`), `access-oidc`, the owner-managed WARP + Gateway policy (`warp-gateway`), or the service's own check (`own-login` / `agentdash`). Services that are not `cloudflare-access` still need a line in `docs/permissions.md` saying what a grant does today. Keep public text free of IPs, internal hostnames and secret paths.
4. Links to the service on the team page must be gated by the grant (`members.js` / `permissions.js`), never hard-coded.
5. Update `docs/permissions.md`.

Other rules: the owner (`tbryant@fwogg3r.com`) is hard-coded in `firestore.rules` and `auth.js` and is never stored as a role; render user-supplied text with `textContent` only; keep the strict CSP on `members.html` (no inline scripts, no Stripe there); never enable custom OIDC/SAML Firebase providers (they can assert `email_verified`).
