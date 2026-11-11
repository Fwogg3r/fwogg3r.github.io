# Permissions

Who can see and use which service, managed from the **Permissions** tab on `members.html`. Excluded from the published site (`_config.yml`); no secrets here.

## Roles

| Role | Who | Can |
|---|---|---|
| `owner` | `tbryant@fwogg3r.com`, hard-coded in `firestore.rules` and `auth.js`; never stored | everything; the only one who grants/revokes `superadmin` and who changes **high-risk** grants |
| `superadmin` | `users/{email}.role == "superadmin"` | add any email, set per-service levels (except high-risk), edit the catalog |
| `member` | any other allowlisted email | sees links for services granted to them |

"Member" in the paid-membership sense (verified `@fwogg3r.com`: billing, `/remote/files/`, `nasUsers`) is separate from access grants. Billing is untouched.

High-risk grants (owner-only to grant, change or revoke): `ha`, `sheila-ssh`, `laptop-ssh`, `agentdash` levels `operate`/`admin`. Marked `highRisk` / `highRiskLevels` in the catalog; the rules mirror the list. A superadmin cannot write or delete **any** user doc that holds a high-risk grant (before or after the write), so `updatedBy` on such a doc is always the owner's uid; the sync checks `updatedBy == owner uid` before applying a high-risk grant. In the UI such users show as locked with an explanation.

## Data model

`users/{emailLowercase}`: `{email, role: "superadmin"|"member", services: {<id>: <level>}, note, updatedAt, updatedBy (uid), updatedByEmail}`. A level of none = key absent.

`services/{id}`: `{name, url|null, description, levels[], highRisk?, highRiskLevels?, cfAccessApp|null, enforcedBy: "cloudflare-access"|"own-login"|"agentdash", order, updatedAt, updatedBy, updatedByEmail}`. Schema source and seed: `services.json` (public info only).

Seed: owner opens Permissions, clicks **Seed catalog**. Initial services: files, ha, sheila-ssh, laptop-ssh, agentdash (view/operate/admin), pmjc, passwords, photos.

## Rules (`firestore.rules`)

- Everything requires `email_verified == true`. Owner = that verified hard-coded email.
- Superadmin = `get(users/<own email>).role == 'superadmin'`.
- Users read their own doc; owner and superadmins read/write all `users` docs.
- Only the owner may create/modify/delete a doc whose role is or becomes `superadmin`, or write the owner's address. `owner` can never be stored.
- Writes validate: doc ID == lowercase email, exact key set, `services` keys only from a hard-coded id list with values from each service's level list, `updatedAt == request.time`, `updatedBy == request.auth.uid`, `updatedByEmail` == own email. Superadmins cannot create, update or delete a doc that holds a high-risk grant (existing or resulting).
- `services` docs: readable by anyone with a `users` doc (needed to draw their links; public URLs only), writable by owner/superadmins with shape validation.
- `nasUsers` rule unchanged.
- The sync job on SHEILA reads `users` and `services` with a read-only Firebase service account (bypasses rules).

Rules cannot read the catalog, so a new service id/levels must also be added to `validGrants` (see CLAUDE.md). The client additionally limits levels to the catalog.

## Sign-in

Providers: email/password (any domain, email verification required) and Google (any Google account). Never enable custom OIDC/SAML providers, which can assert `email_verified`. Non-listed users can sign in but see nothing. Owner: enable MFA (TOTP) on the owner account.

## Enforcement

The team page only hides links; it is not the security boundary.

- **cloudflare-access** (`files`, `ha`, `sheila-ssh`, `laptop-ssh`): the sync job in `Z:\shared\access-sync` reads Firestore and rewrites each app's allow policy (`cfAccessApp`) to include the granted emails. It only applies grants for service ids it knows. A fixed "tbryant only" policy stays on every app, so the owner never depends on the sync. Removing a grant also revokes that user's active Access sessions.
- **agentdash**: checks the level (view/operate/admin) itself; its sessions are short.
- **own-login** (`pmjc`, `passwords`, `photos`): the service's own login stays the gate; the catalog entry controls only link visibility (no Access app, by design: connectors and mobile apps).

## Adding a service

Follow the checklist in `CLAUDE.md`: `services.json`, the Firestore catalog (re-seed or edit in the tab), the `firestore.rules` allow-list (and high-risk helpers), the enforcement, and this doc.

## Owner to-do in the Firebase console (not done by the repo)

1. Authentication, Sign-in method: keep Email/Password, enable **Google**. Authentication, Settings, Authorized domains must include fwogg3r.com.
2. Enable MFA (TOTP) and enroll the owner account.
3. Publish `firestore.rules` (Firestore, Rules).
4. Sign in as the owner, open Team, Permissions, **Seed catalog**.

## Rules test plan (Firebase console, Firestore, Rules, Rules Playground)

Publish `firestore.rules` first. Playground auth: toggle "Authenticated", provider google.com, set uid and token `email` and `email_verified: true` as below. Pre-create docs in the console as needed: `users/sa@x.com` (superadmin), `users/m@x.com` (member, services `{files: "on"}`), `users/h@x.com` (member, services `{ha: "on"}`).
Write payload fields: `email`, `role`, `services`, `note`, `updatedAt` (use server timestamp / request.time), `updatedBy` (= auth uid), `updatedByEmail` (= token email).

| # | Case | Auth (uid / email) | Request | Expect |
|---|---|---|---|---|
| 1 | Owner writes a superadmin | OWNERUID / tbryant@fwogg3r.com | set `users/sa@x.com` role superadmin | Allow |
| 2 | Owner grants high-risk | owner | set `users/m@x.com` services `{ha: "on"}` | Allow |
| 3 | Superadmin writes member | SAUID / sa@x.com | set `users/new@x.com` role member, services `{files: "on", agentdash: "view"}` | Allow |
| 4 | Superadmin tries superadmin | sa | set `users/new@x.com` role superadmin | Deny |
| 5 | Superadmin tries high-risk | sa | set `users/new@x.com` services `{ha: "on"}`; also `{agentdash: "operate"}` | Deny both |
| 6 | Superadmin edits a doc that holds one | sa | update `users/h@x.com` (any change, even the note) | Deny; delete also Deny |
| 7 | Superadmin deletes plain member | sa | delete `users/m@x.com` (no high-risk grant) | Allow |
| 8 | Wrong updatedBy | sa | as 3 but `updatedBy` = another uid, or `updatedByEmail` != token email | Deny |
| 9 | Member reads self | uid / m@x.com | get `users/m@x.com` | Allow |
| 10 | Member reads other, lists, writes | m | get `users/h@x.com`; list `users`; set own doc | Deny all |
| 11 | Member reads catalog | m | get `services/files` | Allow |
| 12 | Unverified email | any uid / tbryant@fwogg3r.com with `email_verified: false` | get/set anything | Deny |
| 13 | Unknown service / level | owner | services `{nope: "on"}`; `{agentdash: "root"}` | Deny both |
