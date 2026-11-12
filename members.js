// Team page: service links gated by permissions, plus the Permissions tab (owner + superadmins).
// All user-supplied text is rendered with textContent / value, never innerHTML.
import { requireUser, mountUserMenu, isMember, checkNasAccess, auth } from "./auth.js";
import { signOut } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
  enrolledTotp, enrolledFactors, hasMfa, beginTotpEnrollment, finishTotpEnrollment, unenrollFactor,
  drawQr, isCode, cleanCode, mfaErrorText,
} from "./mfa.js";
import {
  loadProfile, loadServices, loadUsers, canAccess, levelFor, isAdmin, isOwner, isHighRisk, isGrantable,
  saveUser, deleteUser, saveService, deleteService, seedCatalog, normEmail, isValidEmail, NO_ACCESS,
} from "./permissions.js";

const $ = (id) => document.getElementById(id);
function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k in n) n[k] = v;
    else n.setAttribute(k, v);
  }
  for (const c of kids) n.append(c);
  return n;
}
function msg(text, kind = "error") { const m = $("msg"); m.textContent = text; m.className = "msg " + kind; }
function errText(e) {
  return e && e.code === "permission-denied" ? "Permission denied (rules refused this change)." : (e && e.message) || "Something went wrong.";
}
// What a grant does today, by enforcement type (shown to the person who holds it; no internal details).
const ENFORCEMENT = {
  "cloudflare-access": { tag: "Sign in with Cloudflare Access", note: "Sign in with Cloudflare Access (one-time code or Google). The service may also ask for its own account or key." },
  "access-oidc": { tag: "Sign in with Cloudflare Access", note: "Sign in with Cloudflare Access; the service signs you in automatically." },
  "warp-gateway": { tag: "WARP device + Gateway", note: "WARP device + Gateway (managed by the owner): the owner enrolls your device and adds you to the Gateway rule. Granting this here does not change it by itself." },
  "own-login": { tag: "Own account", note: "Uses its own login. The owner also creates your account; a grant here only shows the link." },
  "agentdash": { tag: "Cloudflare Access", note: "Sign in with Cloudflare Access; your level decides what you can do." },
  "none": { tag: "Informational", note: "Informational only; nothing to sign in to." },
};
const MANUAL_NOTE = {
  passwords: "The owner also creates your vault (invitation).",
  ha: "The owner also creates your Home Assistant account.",
};
const safeUrl = (u) => (typeof u === "string" && /^https:\/\//.test(u) ? u : null);

let me, profile, catalog = [];
// An admin (owner or superadmin) without an active second factor may not manage anything:
// firestore.rules requires it for every admin write (isOwnerMfa / isSuperadminMfa).
let mfaActive = false;
const mfaBlocked = () => isAdmin(profile) && !mfaActive;
const MFA_BLOCK_HINT = "Turn on two-step verification (Services tab, Security) and sign in again with your code to manage the allowlist.";

// "Active" = this session's token carries a second-factor sign-in (what the rules check).
async function refreshMfaState() {
  try {
    const r = await me.getIdTokenResult(true);
    mfaActive = !!(r.claims.firebase && r.claims.firebase.sign_in_second_factor);
  } catch (_) { mfaActive = false; }
}

// ---- Security card (any signed-in user) -------------------------------------------------
async function signInAgain() {
  if (!confirm("For your security, this needs a fresh sign-in. Sign out now and sign in again?")) return;
  try { await signOut(auth); } catch (_) { /* ignore */ }
  window.location.replace("/login.html?next=" + encodeURIComponent("/members.html"));
}
const withRecentLogin = async (fn) => {
  try { return await fn(); }
  catch (e) {
    if (e && e.code === "auth/requires-recent-login") { msg(mfaErrorText(e)); await signInAgain(); return undefined; }
    throw e;
  }
};

function renderSecurity() {
  const admin = isAdmin(profile);
  const totp = enrolledTotp(me);
  $("sec-card").classList.toggle("prominent", admin);
  const warn = $("sec-warn");
  if (admin && !totp.length) {
    warn.hidden = false;
    warn.textContent = profile.role === "owner"
      ? "Your account can change who has access to everything, and it has no second factor. Admin actions are disabled until you set up two-step verification."
      : "Superadmin actions are disabled until you set up two-step verification.";
  } else if (admin && totp.length && !mfaActive) {
    warn.hidden = false;
    warn.textContent = "Two-step verification is set up, but this session was started without it. Sign out and sign in again with your code.";
  } else warn.hidden = true;
  $("sec-status").textContent = totp.length ? "Two-step verification is ON." : "Two-step verification is OFF.";
  const list = $("sec-factors");
  list.replaceChildren();
  for (const f of enrolledFactors(me)) {
    const when = f.enrollmentTime ? " (added " + new Date(f.enrollmentTime).toISOString().slice(0, 10) + ")" : "";
    const rm = el("button", { type: "button", class: "btn small danger", text: "Remove" });
    rm.addEventListener("click", async () => {
      if (!confirm("Remove this authenticator? Your account will be less protected.")) return;
      try {
        const done = await withRecentLogin(async () => { await unenrollFactor(me, f); return true; });
        if (!done) return;
        msg("Authenticator removed.", "ok");
        await refreshMfaState();
        renderSecurity(); renderPermsGate();
      } catch (e) { msg(mfaErrorText(e)); }
    });
    list.append(el("li", {}, el("span", { text: (f.displayName || "Authenticator app") + when }), rm));
  }
  $("sec-start").hidden = !!totp.length || !$("sec-enroll").hidden;
}

let pending = null; // { secret, key, uri } while enrolling
function endEnroll() {
  pending = null;
  $("sec-enroll").hidden = true;
  $("sec-key").textContent = "";
  $("sec-code").value = "";
  $("sec-start").hidden = hasMfa(me);
}

function initSecurity() {
  $("sec-start").addEventListener("click", async () => {
    $("sec-start").disabled = true;
    try {
      const r = await withRecentLogin(() => beginTotpEnrollment(me));
      if (!r) return;
      pending = r;
      drawQr($("sec-qr"), r.uri);
      $("sec-key").textContent = r.key;
      $("sec-enroll").hidden = false;
      $("sec-start").hidden = true;
      $("sec-code").focus();
    } catch (e) { msg(mfaErrorText(e)); }
    finally { $("sec-start").disabled = false; }
  });
  $("sec-cancel").addEventListener("click", endEnroll);
  $("sec-confirm").addEventListener("click", async () => {
    if (!pending) return;
    if (!isCode($("sec-code").value)) return msg("Enter the 6-digit code from your authenticator app.");
    $("sec-confirm").disabled = true;
    try {
      const done = await withRecentLogin(async () => { await finishTotpEnrollment(me, pending.secret, cleanCode($("sec-code").value)); return true; });
      if (!done) return;
      endEnroll();
      await refreshMfaState();
      renderSecurity(); renderPermsGate();
      msg(mfaActive ? "Two-step verification is on." : "Two-step verification is on. Sign out and sign in again with your code so admin actions can use it.", "ok");
    } catch (e) { msg(mfaErrorText(e)); if (e && e.code === "auth/invalid-verification-code") $("sec-code").select(); }
    finally { $("sec-confirm").disabled = false; }
  });
}

// Permissions tab: banner + disabled controls for a superadmin without MFA.
function renderPermsGate() {
  if (!isAdmin(profile)) return;
  const b = $("mfa-banner");
  const blocked = mfaBlocked();
  b.hidden = !(blocked || !hasMfa(me));
  b.textContent = blocked ? "Management actions are disabled. " + MFA_BLOCK_HINT
    : "Warning: your admin account has no second factor. Set up two-step verification on the Services tab (Security).";
  for (const id of ["add-email", "seed", "add-service"]) $(id).disabled = blocked;
  $("add-form").querySelector("button").disabled = blocked;
  $("catalog").replaceChildren(...catalog.map(catalogRow));
  renderUsers();
}

// ---- Services pane ----------------------------------------------------------------------
function renderServices() {
  const list = $("svc-list");
  list.replaceChildren();
  let shown = 0;
  for (const svc of catalog) {
    if (!canAccess(profile, svc)) continue;
    shown++;
    const lvl = levelFor(profile, svc);
    const li = el("li");
    const url = safeUrl(svc.url);
    li.append(url ? el("a", { href: url, rel: "noopener", text: svc.name, class: "svc-name" }) : el("span", { class: "svc-name", text: svc.name }));
    const enf = ENFORCEMENT[svc.enforcedBy];
    if (!url) li.append(el("span", { class: "tag", text: svc.enforcedBy === "cloudflare-access" ? "[SSH access]" : "[no web link]" }));
    if (enf) li.append(el("span", { class: "tag", text: "[" + enf.tag + "]" }));
    if (svc.levels.length > 1) li.append(el("span", { class: "tag", text: "[" + lvl + "]" }));
    if (svc.description) li.append(el("div", { class: "hint", text: svc.description }));
    if (enf && (svc.enforcedBy === "own-login" || svc.enforcedBy === "warp-gateway" || svc.enforcedBy === "access-oidc")) {
      li.append(el("div", { class: "hint", text: "What a grant does: " + (MANUAL_NOTE[svc.id] || enf.note) + (MANUAL_NOTE[svc.id] && svc.enforcedBy === "own-login" ? " A grant here only shows the link." : "") }));
    }
    list.append(li);
  }
  $("svc-empty").hidden = shown > 0;
}

// ---- Permissions pane -------------------------------------------------------------------
function stamp(u) {
  const t = u.updatedAt && u.updatedAt.toDate ? u.updatedAt.toDate().toISOString().slice(0, 16).replace("T", " ") : "";
  return u.updatedByEmail ? `updated ${t} by ${u.updatedByEmail}` : "";
}

function userCard(u) {
  const owner = isOwner(profile);
  const isSuper = u.role === "superadmin";
  // Rules: only the owner may write a superadmin doc, or any doc that holds a high-risk grant.
  const holdsHigh = catalog.some((svc) => isHighRisk(svc, u.services && u.services[svc.id]));
  const locked = !owner && (isSuper || holdsHigh || mfaBlocked());
  const card = el("div", { class: "perm-user" + (u.email === profile.email ? " me" : "") });

  const roleSel = el("select", { title: owner ? "Role" : "Only the owner can change roles", disabled: !owner });
  for (const r of ["member", "superadmin"]) roleSel.append(el("option", { value: r, text: r, selected: u.role === r }));
  const head = el("div", { class: "perm-head" }, el("span", { class: "perm-email", text: u.email }), roleSel);
  card.append(head);

  const grid = el("div", { class: "perm-grid" });
  const selects = {};
  for (const svc of catalog) {
    if (!isGrantable(svc)) {
      // Owner-only service: no level select, nobody can be granted it (rules deny any pmjc grant).
      grid.append(el("div", {}, el("label", { text: svc.name }), el("span", { class: "hint", text: "owner only" })));
      continue;
    }
    const cur = (u.services && u.services[svc.id]) || NO_ACCESS;
    const sel = el("select", { id: `g-${u.id}-${svc.id}` });
    sel.append(el("option", { value: NO_ACCESS, text: "none", selected: cur === NO_ACCESS }));
    for (const l of svc.levels) {
      const risky = isHighRisk(svc, l);
      sel.append(el("option", { value: l, text: l + (risky ? " (owner only)" : ""), selected: cur === l, disabled: risky && !owner && cur !== l }));
    }
    if (locked || (!owner && isHighRisk(svc, cur))) { sel.disabled = true; sel.title = "Only the owner can change this user"; }
    selects[svc.id] = sel;
    grid.append(el("div", {}, el("label", { for: sel.id, text: svc.name }), sel));
  }
  card.append(grid);

  const note = el("input", { type: "text", maxLength: 500, placeholder: "note", value: u.note || "", disabled: locked });
  const save = el("button", { type: "button", class: "btn small", text: "Save", disabled: locked });
  const del = el("button", { type: "button", class: "btn small danger", text: "Remove", disabled: locked });
  card.append(el("div", { class: "perm-foot" }, note, save, del));
  if (locked) card.append(el("div", { class: "hint", text: mfaBlocked() ? MFA_BLOCK_HINT : isSuper
    ? "Superadmin: only the owner can change this user."
    : "This user holds a high-risk grant (Home Assistant, SSH, RDP, network drives, local LLMs, pmjc, or AgentController operate/admin). Only the owner can edit or remove them, so that the grant stays attributed to the owner." }));
  card.append(el("div", { class: "perm-stamp", text: stamp(u) }));

  save.addEventListener("click", async () => {
    const services = {};
    for (const [id, s] of Object.entries(selects)) services[id] = s.value;
    try {
      await saveUser(profile, { email: u.email, role: roleSel.value, services, note: note.value }, catalog);
      msg("Saved " + u.email + ".", "ok");
      await renderUsers();
    } catch (e) { msg(errText(e)); }
  });
  del.addEventListener("click", async () => {
    if (!confirm("Remove " + u.email + " from the allowlist?")) return;
    try { await deleteUser(u.email); msg("Removed " + u.email + ".", "ok"); await renderUsers(); }
    catch (e) { msg(errText(e)); }
  });
  return card;
}

async function renderUsers() {
  const box = $("users");
  try {
    const users = await loadUsers();
    box.replaceChildren(...users.map(userCard));
    if (!users.length) box.replaceChildren(el("p", { class: "hint", text: "No users yet." }));
  } catch (e) { msg(errText(e)); }
}

// ---- Catalog editor ---------------------------------------------------------------------
function catalogRow(svc) {
  const d = el("details", {});
  d.append(el("summary", { text: `${svc.name} (${svc.id}) - ${svc.enforcedBy}${svc.highRisk ? " (high-risk)" : ""}` }));
  const { id, updatedAt, updatedBy, updatedByEmail, ...editable } = svc;
  const ta = el("textarea", { class: "json", value: JSON.stringify(editable, null, 2), spellcheck: false });
  const save = el("button", { type: "button", class: "btn small", text: "Save service", disabled: mfaBlocked() });
  const del = el("button", { type: "button", class: "btn small danger", text: "Delete", disabled: mfaBlocked() });
  save.addEventListener("click", () => persistService(id, ta.value));
  del.addEventListener("click", async () => {
    if (!confirm("Delete service " + id + "? Rules still allow only the hard-coded service ids in grants.")) return;
    try { await deleteService(id); await refreshCatalog(); msg("Deleted.", "ok"); } catch (e) { msg(errText(e)); }
  });
  d.append(ta, el("div", { class: "perm-foot" }, save, del));
  return d;
}

async function persistService(id, text) {
  try {
    await saveService(profile, id, JSON.parse(text));
    await refreshCatalog();
    msg("Saved service " + id + ".", "ok");
  } catch (e) { msg(e instanceof SyntaxError ? "Invalid JSON." : errText(e)); }
}

async function refreshCatalog() {
  catalog = await loadServices();
  renderServices();
  const box = $("catalog");
  box.replaceChildren(...catalog.map(catalogRow));
  if (isAdmin(profile)) await renderUsers();
}

// ---- wiring -----------------------------------------------------------------------------
function selectTab(name) {
  const perms = name === "perms";
  $("pane-services").hidden = perms;
  $("pane-perms").hidden = !perms;
  $("tab-services").setAttribute("aria-selected", String(!perms));
  $("tab-perms").setAttribute("aria-selected", String(perms));
}

mountUserMenu();
requireUser(async (user) => {
  me = user;
  $("who").textContent = user.email;
  profile = await loadProfile(user);
  $("role").textContent = "(" + profile.role + ")";
  await refreshMfaState();
  initSecurity();
  renderSecurity();
  if (isMember(user)) {
    $("member-card").hidden = false;
    // The TeraStation card keeps the existing nasUsers flow.
    if ((await checkNasAccess(user)) === "ok") $("nas-card").hidden = false;
  }
  try { catalog = await loadServices(); } catch (e) { catalog = []; msg("Could not load the service catalog."); }
  renderServices();

  if (isAdmin(profile)) {
    $("page-tabs").hidden = false;
    renderPermsGate();
    $("tab-services").addEventListener("click", () => selectTab("services"));
    $("tab-perms").addEventListener("click", () => selectTab("perms"));
    $("seed-wrap").hidden = !isOwner(profile);
    $("seed").addEventListener("click", async () => {
      if (!confirm("Write the services.json catalog to Firestore?")) return;
      try { const n = await seedCatalog(profile); await refreshCatalog(); msg("Seeded " + n + " services.", "ok"); }
      catch (e) { msg(errText(e)); }
    });
    $("add-service").addEventListener("click", () => {
      const tpl = { name: "", url: null, description: "", levels: ["on"], cfAccessApp: null, enforcedBy: "own-login", order: 100 };
      const id = prompt("New service id (lowercase, digits, dashes). It must also be added to firestore.rules and services.json.");
      if (id) $("catalog").append(catalogRow({ id, ...tpl })), $("catalog").lastChild.open = true;
    });
    $("add-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = normEmail($("add-email").value);
      if (!isValidEmail(email)) return msg("Enter a valid email address.");
      try {
        if ((await loadUsers()).some((x) => x.email === email)) return msg(email + " is already on the list; edit them below.");
        await saveUser(profile, { email, role: "member", services: {}, note: "" }, catalog);
        $("add-email").value = "";
        msg("Added " + email + ". Now set their service levels.", "ok");
        await renderUsers();
      } catch (err) { msg(errText(err)); }
    });
    await renderUsers();
  }
});
