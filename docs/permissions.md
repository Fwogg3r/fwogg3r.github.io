# Permissions

Who can see and use which service, managed from the **Permissions** tab on `members.html`. Excluded from the published site (`_config.yml`); no secrets here.

## Roles

| Role | Who | Can |
|---|---|---|
| `owner` | `tbryant@fwogg3r.com`, hard-coded in `firestore.rules` and `auth.js`; never stored | everything; the only one who grants/revokes `superadmin` and who changes **high-risk** grants |
| `superadmin` | `users/{email}.role == "superadmin"` | add any email, set per-service levels (except high-risk), edit the catalog |
| `member` | any other allowlisted email | sees links for services granted to them |

"Member" in the paid-membership sense (verified `@fwogg3r.com`: billing, `/remote/files/`, `nasUsers`) is separate from access grants. Billing is untouched.

High-risk grants (owner-only to grant, change or revoke): `ha`, `sheila-ssh`, `laptop-ssh`, `rdp`, `lmstudio`, `files-smb`, `agentdash` levels `operate`/`admin`. Marked `highRisk` / `highRiskLevels` in the catalog; the rules mirror the list. A superadmin cannot write or delete **any** user doc that holds a high-risk grant (before or after the write), so `updatedBy` on such a doc is always the owner's uid; the sync checks `updatedBy == owner uid` before applying a high-risk grant. In the UI such users show as locked with an explanation.

**Owner-only services** (`grantable: false` in the catalog; today `pmjc`): listed in the catalog and visible on the team page to the owner only, but nobody can be granted them. The rules leave the id out of `validGrants`, so ANY write carrying such a grant is denied, even from the owner (and a superadmin cannot see the link either); the Permissions UI shows "owner only" instead of a level select; `access-sync` ignores and alerts on any such grant found in Firestore and never emits it to `grants.json`. To make a service grantable later, remove the flag and add it to `validGrants` like any other.

## Data model

`users/{emailLowercase}`: `{email, role: "superadmin"|"member", services: {<id>: <level>}, note, updatedAt, updatedBy (uid), updatedByEmail}`. A level of none = key absent.

`services/{id}`: `{name, url|null, description, levels[], highRisk?, highRiskLevels?, grantable? (false = owner-only, not grantable), cfAccessApp|null, enforcedBy: "cloudflare-access"|"access-oidc"|"warp-gateway"|"own-login"|"agentdash"|"none", sso?: "access-jwt"|"oidc"|"google-oidc"|"none", plannedEnforcement?, order, updatedAt, updatedBy, updatedByEmail}`. Schema source and seed: `services.json` (public info only).

Seed: owner opens Permissions, clicks **Seed catalog**. Initial services (11): files, files-smb, ha, sheila-ssh, laptop-ssh, rdp, agentdash (view/operate/admin), pmjc (owner-only, not grantable), passwords, photos, lmstudio.

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

The team page only hides links; it is not the security boundary. What a grant does today, per service:

| Service | enforcedBy | What a grant does | Also needed | Risk |
|---|---|---|---|---|
| `files` | cloudflare-access | sync adds the email to the Access app | a TeraStation account (`nasUsers`) | normal |
| `files-smb` | warp-gateway | nothing automatic; the owner enrolls the device and edits the Gateway rule | TeraStation account | owner only |
| `ha` | cloudflare-access | sync adds the email to the Access app | Home Assistant account (owner creates it) | owner only |
| `sheila-ssh`, `laptop-ssh` | cloudflare-access | opens the tunnel only | an authorized SSH key | owner only |
| `rdp` | warp-gateway | nothing automatic (Gateway policy, owner) | Windows login | owner only |
| `agentdash` | agentdash | Access app via sync, level checked by agentdash itself (view/operate/admin) | none | operate/admin owner only |
| `pmjc` | own-login | not grantable: link shown to the owner only; a pmjc grant in Firestore is ignored and alerted by the sync | own Google login | owner only (not grantable) |
| `passwords` | own-login | link only; sync raises an owner alert | the owner invites you to a personal vault | normal |
| `photos` | own-login (planned: access-oidc) | link only; sync raises an owner alert | Immich account the owner creates (until the Access OIDC cutover) | normal |
| `lmstudio` | warp-gateway | nothing automatic (Gateway policy, owner) | Cloudflare One Client | owner only |

- **cloudflare-access** (`files`, `ha`, `sheila-ssh`, `laptop-ssh`): the sync job in `Z:\shared\access-sync` reads Firestore and rewrites each app's allow policy (`cfAccessApp`) to include the granted emails. It only applies grants for service ids it knows. A fixed "tbryant only" policy stays on every app, so the owner never depends on the sync. Removing a grant also revokes that user's active Access sessions.
- **access-oidc**: Cloudflare Access for SaaS (OIDC); the service redirects to Cloudflare to sign in. Not in use yet; `photos` carries `plannedEnforcement: "access-oidc"` until the Immich cutover, then switches `enforcedBy` and gets `cfAccessApp`.
- **warp-gateway**: WARP device enrollment plus a Gateway policy, managed by the owner by hand. The sync never sends these to Cloudflare; they appear in `grants.json` and each new grant raises an owner alert for the manual step.
- **own-login** (`passwords`, `photos`; `pmjc` is owner-only and not grantable): the service's own login stays the gate (no Access app, by design: connectors and mobile apps). The grant only shows the link; the owner creates the account. The team page says so.
- **agentdash**: checks the level itself; its sessions are short.
- **none**: informational row, no door.
- Not catalogued (no team-facing door): the local search service, the notes vault (NAS folder plus a private repo), and other internal-only endpoints.

## Adding a service

Follow the checklist in `CLAUDE.md`: `services.json`, the Firestore catalog (re-seed or edit in the tab), the `firestore.rules` allow-list (and high-risk helpers), the enforcement, and this doc.

## Owner to-do in the Firebase console (not done by the repo)

1. Authentication, Sign-in method: keep Email/Password, enable **Google**. Authentication, Settings, Authorized domains must include fwogg3r.com.
2. Upgrade to Identity Platform (Authentication, Settings or the upgrade prompt), then Authentication, Sign-in method, **Multi-factor authentication**: enable it with **TOTP** (SMS stays off). Then enroll the owner on the Team page (Security card). See "MFA" below.
3. Publish `firestore.rules` (Firestore, Rules).
4. Sign in as the owner, open Team, Permissions, **Seed catalog**.

## MFA (two-step verification, TOTP)

Client code: `mfa.js` (helpers), `login.html` (second step of sign-in), `members.js` + the Security card on `members.html` (enroll / remove). The QR code is drawn locally on a canvas by the vendored `vendor/qrcode-generator.js` (qrcode-generator 1.4.4, MIT); the secret is never sent to a third party. No new CSP origins: Firebase TOTP calls go to `identitytoolkit.googleapis.com`, already covered by `https://*.googleapis.com` in `members.html`; `login.html` has no CSP.

**Needs** the project upgraded to Identity Platform and TOTP MFA enabled (see "Owner to-do").

**Enroll (any signed-in user):** Team page, Services tab, "Security" card, "Set up authenticator app". Scan the QR code (or type the key), enter the current 6-digit code, "Turn on". The issuer shown in the app is `fwogg3r.com`, the account name is your email. If Firebase asks for a recent sign-in, the page offers to sign you out so you can sign in again, then retry. After enrolling, sign out and sign in once more: the session token only carries the second factor after a sign-in that used it.

**Sign in:** email/password or Google, then the page asks for the 6-digit code. Works the same for both.

**Enforcement:**
- Client: the Permissions tab shows a warning banner when the admin has no second factor. A **superadmin** without an active second factor (none enrolled, or this session started without it) has every management control disabled.
- Rules: `firestore.rules` requires `request.auth.token.firebase.sign_in_second_factor != null` (`hasSecondFactor()`) for all **superadmin writes** (users create/update/delete, catalog writes and deletes). Reads are unaffected. The **owner is exempt until they enroll**; once the owner has MFA, make it mandatory by adding `&& hasSecondFactor()` to the owner branches (`isOwner()` in the users rules and in `isAdminMfa()`). Do this only after confirming a sign-in with a code works; the Firebase console and the read-only sync service account bypass the rules, so a mistake is recoverable there.
- Tests: `docs/rules-test.mjs` has `mfa:` cases (token claim `firebase: {sign_in_second_factor: "totp"}`).

**Recovery:**
- Lost password: password reset via email (login page, "Forgot password?"). A password reset does not remove the second factor.
- Lost authenticator (owner or anyone): the owner removes the factor in the Firebase console, Authentication, Users, open the user, remove the second factor (or sign in with the existing code and use "Remove" on the Security card). Keep a second device or the manual key stored in a password manager so you are never down to one copy.
- Locked-out owner: the console and the Admin SDK do not depend on these rules; fix the factor there.

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
| 14 | New ids accepted | owner | set `users/new@x.com` services `{files-smb: "on", rdp: "on", lmstudio: "on"}` | Allow |
| 15 | New high-risk ids need the owner | sa | set `users/new@x.com` services `{rdp: "on"}`; again with `{lmstudio: "on"}`, `{files-smb: "on"}` | Deny all three |
| 16 | New id, bad level | owner | services `{rdp: "admin"}` | Deny |
| 17 | Catalog enforcedBy | owner | set `services/x` with `enforcedBy: "warp-gateway"`, then `"access-oidc"`, then `"none"` (valid shape) | Allow all |
| 18 | Catalog bad enforcedBy / sso | owner | `enforcedBy: "magic"`; or `sso: "x"` | Deny both |

## Running the rules tests (Firebase emulator, offline)

`docs/rules-test.mjs` runs the test plan above (cases 1-18) plus extra cases (nasUsers, owner identification, shape checks, catalog writes) against the emulator, using the `demo-fwogg3r` project id so nothing touches the real project or console. Last run: 123 passed, 0 failed (includes the pmjc owner-only cases and two `sanity:` cases that fail if the MFA claim override stops reaching `request.auth.token.firebase.sign_in_second_factor`) (firebase-tools 15.35.0, @firebase/rules-unit-testing 6.0.0, firebase 13.2.0, Temurin JRE 21).

1. Needs Java 21+ on PATH (a portable JRE is fine; set `JAVA_HOME`/`PATH` for the command only).
2. In a scratch folder outside this repo: `npm i --save-exact @firebase/rules-unit-testing@6.0.0 firebase@13.2.0`, put `"type": "module"` in its `package.json`, copy `docs/rules-test.mjs` there as `test.mjs`, and add a `firebase.json` with `{"firestore":{"rules":"<path to firestore.rules>"},"emulators":{"firestore":{"host":"127.0.0.1","port":8080},"ui":{"enabled":false}}}`.
3. `RULES_FILE=<path to firestore.rules> npx -y firebase-tools@15.35.0 emulators:exec --only firestore --project demo-fwogg3r "node test.mjs"` (exits non-zero on any failure).
