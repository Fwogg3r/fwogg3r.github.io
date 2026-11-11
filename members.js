// Team page: service links gated by permissions, plus the Permissions tab (owner + superadmins).
// All user-supplied text is rendered with textContent / value, never innerHTML.
import { requireUser, mountUserMenu, isMember, checkNasAccess } from "./auth.js";
import {
  loadProfile, loadServices, loadUsers, canAccess, levelFor, isAdmin, isOwner, isHighRisk,
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
const safeUrl = (u) => (typeof u === "string" && /^https:\/\//.test(u) ? u : null);

let me, profile, catalog = [];

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
    if (!url) li.append(el("span", { class: "tag", text: "[SSH access]" }));
    if (svc.levels.length > 1) li.append(el("span", { class: "tag", text: "[" + lvl + "]" }));
    if (svc.description) li.append(el("div", { class: "hint", text: svc.description }));
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
  const locked = isSuper && !owner; // only the owner may touch a superadmin doc
  const card = el("div", { class: "perm-user" + (u.email === profile.email ? " me" : "") });

  const roleSel = el("select", { title: owner ? "Role" : "Only the owner can change roles", disabled: !owner });
  for (const r of ["member", "superadmin"]) roleSel.append(el("option", { value: r, text: r, selected: u.role === r }));
  const head = el("div", { class: "perm-head" }, el("span", { class: "perm-email", text: u.email }), roleSel);
  card.append(head);

  const grid = el("div", { class: "perm-grid" });
  const selects = {};
  for (const svc of catalog) {
    const cur = (u.services && u.services[svc.id]) || NO_ACCESS;
    const sel = el("select", { id: `g-${u.id}-${svc.id}` });
    sel.append(el("option", { value: NO_ACCESS, text: "none", selected: cur === NO_ACCESS }));
    for (const l of svc.levels) {
      const risky = isHighRisk(svc, l);
      sel.append(el("option", { value: l, text: l + (risky ? " (owner only)" : ""), selected: cur === l, disabled: risky && !owner && cur !== l }));
    }
    // Changing or revoking an existing high-risk grant is owner-only too (firestore.rules).
    if (locked || (!owner && isHighRisk(svc, cur))) { sel.disabled = true; sel.title = "Only the owner can change this grant"; }
    selects[svc.id] = sel;
    grid.append(el("div", {}, el("label", { for: sel.id, text: svc.name }), sel));
  }
  card.append(grid);

  const note = el("input", { type: "text", maxLength: 500, placeholder: "note", value: u.note || "", disabled: locked });
  const save = el("button", { type: "button", class: "btn small", text: "Save", disabled: locked });
  const del = el("button", { type: "button", class: "btn small danger", text: "Remove", disabled: locked });
  card.append(el("div", { class: "perm-foot" }, note, save, del));
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
  d.append(el("summary", { text: `${svc.name} (${svc.id}) - ${svc.enforcedBy}` }));
  const { id, updatedAt, updatedBy, updatedByEmail, ...editable } = svc;
  const ta = el("textarea", { class: "json", value: JSON.stringify(editable, null, 2), spellcheck: false });
  const save = el("button", { type: "button", class: "btn small", text: "Save service" });
  const del = el("button", { type: "button", class: "btn small danger", text: "Delete" });
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
  if (isMember(user)) {
    $("member-card").hidden = false;
    // The TeraStation card keeps the existing nasUsers flow.
    if ((await checkNasAccess(user)) === "ok") $("nas-card").hidden = false;
  }
  try { catalog = await loadServices(); } catch (e) { catalog = []; msg("Could not load the service catalog."); }
  renderServices();

  if (isAdmin(profile)) {
    $("page-tabs").hidden = false;
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
