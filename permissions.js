// Permission model for the team page (see docs/permissions.md).
//   owner       = OWNER_EMAIL, hard-coded, never stored.
//   superadmin  = users/{email}.role == "superadmin" (only the owner can grant/revoke).
//   member      = everyone else; access comes from users/{email}.services[<serviceId>] = level.
// The client only hides/shows things; firestore.rules is the real gate for the data, and
// Cloudflare Access / the service itself is the gate for the services.
import {
  collection,
  doc,
  getDoc,
  getDocs,
  setDoc,
  deleteDoc,
  serverTimestamp,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import { db, OWNER_EMAIL } from "./auth.js";

export const NO_ACCESS = "none";
const ID_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;

export function normEmail(email) {
  return String(email || "").trim().toLowerCase();
}

export function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

// Loads the signed-in user's profile: { email, role: "owner"|"superadmin"|"member", services, hasDoc }.
export async function loadProfile(user) {
  const email = normEmail(user.email);
  const uid = user.uid;
  if (email === OWNER_EMAIL) return { uid, email, role: "owner", services: {}, hasDoc: false };
  try {
    const snap = await getDoc(doc(db, "users", email));
    if (snap.exists()) {
      const d = snap.data();
      return {
        uid,
        email,
        role: d.role === "superadmin" ? "superadmin" : "member",
        services: d.services && typeof d.services === "object" ? d.services : {},
        hasDoc: true,
      };
    }
  } catch (err) {
    console.warn("Could not load permissions:", err);
  }
  return { uid, email, role: "member", services: {}, hasDoc: false };
}

export const isAdmin = (p) => p.role === "owner" || p.role === "superadmin";
export const isOwner = (p) => p.role === "owner";

// Level the profile has on a service ("none" when no access). Admins get the service's highest level.
export function levelFor(profile, svc) {
  if (isAdmin(profile)) return svc.levels[svc.levels.length - 1];
  const lvl = profile.services[svc.id];
  return typeof lvl === "string" && svc.levels.includes(lvl) ? lvl : NO_ACCESS;
}

// High-risk grants can only be changed by the owner (firestore.rules enforces the same list).
export function isHighRisk(svc, level) {
  if (level === NO_ACCESS || !level) return false;
  return svc.highRisk === true || (Array.isArray(svc.highRiskLevels) && svc.highRiskLevels.includes(level));
}

export const canAccess = (profile, svc) => levelFor(profile, svc) !== NO_ACCESS;

export async function loadServices() {
  const snap = await getDocs(collection(db, "services"));
  return snap.docs
    .map((d) => ({ id: d.id, ...d.data() }))
    .filter((s) => Array.isArray(s.levels) && s.levels.length)
    .sort((a, b) => (a.order ?? 999) - (b.order ?? 999) || a.name.localeCompare(b.name));
}

// ---- admin operations (rules enforce who may do what) -----------------------------------

export async function loadUsers() {
  const snap = await getDocs(collection(db, "users"));
  return snap.docs.map((d) => ({ id: d.id, ...d.data() })).sort((a, b) => a.email.localeCompare(b.email));
}

// Keeps only grants that name a known service and one of its levels.
export function cleanGrants(grants, services) {
  const out = {};
  for (const svc of services) {
    const lvl = grants[svc.id];
    if (typeof lvl === "string" && lvl !== NO_ACCESS && svc.levels.includes(lvl)) out[svc.id] = lvl;
  }
  return out;
}

export async function saveUser(actor, { email, role, services, note }, catalog) {
  email = normEmail(email);
  if (!isValidEmail(email)) throw new Error("Enter a valid email address.");
  if (email === OWNER_EMAIL) throw new Error("The owner has no stored permissions.");
  if (role !== "member" && role !== "superadmin") throw new Error("Invalid role.");
  if (role === "superadmin" && !isOwner(actor)) throw new Error("Only the owner can grant superadmin.");
  await setDoc(doc(db, "users", email), {
    email,
    role,
    services: cleanGrants(services || {}, catalog),
    note: String(note || "").slice(0, 500),
    updatedAt: serverTimestamp(),
    updatedBy: actor.uid,
    updatedByEmail: actor.email,
  });
}

export async function deleteUser(email) {
  await deleteDoc(doc(db, "users", normEmail(email)));
}

const SERVICE_KEYS = ["name", "url", "description", "levels", "highRisk", "highRiskLevels", "cfAccessApp", "enforcedBy", "sso", "plannedEnforcement", "order"];
export const ENFORCED_BY = ["cloudflare-access", "access-oidc", "warp-gateway", "own-login", "agentdash", "none"];
const SSO_VALUES = ["access-jwt", "oidc", "google-oidc", "none"];

// Validates and normalizes a catalog entry (shape matches services.json / firestore.rules).
export function normalizeService(id, s) {
  if (!ID_RE.test(id)) throw new Error("Service id: lowercase letters, digits and dashes only.");
  const out = {
    name: String(s.name || "").trim(),
    url: s.url ? String(s.url).trim() : null,
    description: String(s.description || "").trim(),
    levels: Array.isArray(s.levels) ? s.levels.map((l) => String(l).trim()).filter(Boolean) : [],
    cfAccessApp: s.cfAccessApp ? String(s.cfAccessApp).trim() : null,
    enforcedBy: s.enforcedBy,
    highRisk: s.highRisk === true,
    highRiskLevels: Array.isArray(s.highRiskLevels) ? s.highRiskLevels.map(String) : [],
    order: Number.isFinite(Number(s.order)) ? Number(s.order) : 100,
  };
  if (!out.name) throw new Error("Service name is required.");
  if (out.url && !/^https:\/\//.test(out.url)) throw new Error("URL must start with https:// (or be empty).");
  if (!out.levels.length) throw new Error("At least one level is required.");
  if (out.levels.includes(NO_ACCESS)) throw new Error('"none" is implicit; do not list it as a level.');
  if (!ENFORCED_BY.includes(out.enforcedBy)) throw new Error("enforcedBy must be one of: " + ENFORCED_BY.join(", ") + ".");
  if (s.sso != null && s.sso !== "") {
    if (!SSO_VALUES.includes(s.sso)) throw new Error("sso must be one of: " + SSO_VALUES.join(", ") + ".");
    out.sso = s.sso;
  }
  if (s.plannedEnforcement != null && s.plannedEnforcement !== "") {
    if (!ENFORCED_BY.includes(s.plannedEnforcement)) throw new Error("plannedEnforcement must be one of: " + ENFORCED_BY.join(", ") + ".");
    out.plannedEnforcement = s.plannedEnforcement;
  }
  for (const k of Object.keys(s)) if (!SERVICE_KEYS.includes(k)) throw new Error("Unknown field: " + k);
  return out;
}

export async function saveService(actor, id, s) {
  const data = normalizeService(id, s);
  await setDoc(doc(db, "services", id), { ...data, updatedAt: serverTimestamp(), updatedBy: actor.uid, updatedByEmail: actor.email });
}

export async function deleteService(id) {
  await deleteDoc(doc(db, "services", id));
}

// One-time seeding from the repo's services.json (owner only in the UI; rules allow admins).
export async function seedCatalog(actor) {
  const res = await fetch("/services.json", { cache: "no-store" });
  if (!res.ok) throw new Error("Could not load services.json");
  const { services } = await res.json();
  for (const [id, s] of Object.entries(services)) await saveService(actor, id, s);
  return Object.keys(services).length;
}
