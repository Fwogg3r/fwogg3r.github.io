// Firestore rules tests (Firebase emulator). Run: see docs/permissions.md, "Running the rules tests".
import { readFileSync } from "node:fs";
import { initializeTestEnvironment, assertSucceeds, assertFails } from "@firebase/rules-unit-testing";
import { doc, getDoc, getDocs, collection, setDoc, deleteDoc, serverTimestamp, Timestamp } from "firebase/firestore";

const RULES = process.env.RULES_FILE || "firestore.rules";
const OWNER = { uid: "OWNERUID", email: "tbryant@fwogg3r.com" };
const SA = { uid: "SAUID", email: "sa@x.com" };
const M = { uid: "MUID", email: "m@x.com" };

const [host, port] = (process.env.FIRESTORE_EMULATOR_HOST || "127.0.0.1:8080").split(":");
const env = await initializeTestEnvironment({
  projectId: "demo-fwogg3r",
  firestore: { rules: readFileSync(RULES, "utf8"), host, port: Number(port) },
});

const ctx = (a, verified = true) =>
  env.authenticatedContext(a.uid, { email: a.email, email_verified: verified }).firestore();
const asOwner = () => ctx(OWNER);
const asSa = () => ctx(SA);
const asM = () => ctx(M);

// Same shape as permissions.js saveUser(): email, role, services, note, serverTimestamp, uid, email.
const userData = (actor, o = {}) => ({
  email: "new@x.com", role: "member", services: {}, note: "",
  updatedAt: serverTimestamp(), updatedBy: actor.uid, updatedByEmail: actor.email, ...o,
});
const setUser = (db, actor, email, o = {}) => setDoc(doc(db, "users", email), userData(actor, { email, ...o }));
// Same shape as permissions.js saveService() / normalizeService().
const svcData = (actor, o = {}) => ({
  name: "X", url: "https://x.example.com", description: "d", levels: ["on"], cfAccessApp: null,
  enforcedBy: "none", highRisk: false, highRiskLevels: [], order: 100,
  updatedAt: serverTimestamp(), updatedBy: actor.uid, updatedByEmail: actor.email, ...o,
});
const setSvc = (db, actor, id, o = {}) => setDoc(doc(db, "services", id), svcData(actor, o));

async function seed() {
  await env.clearFirestore();
  await env.withSecurityRulesDisabled(async (c) => {
    const db = c.firestore();
    const base = { updatedAt: Timestamp.now(), updatedBy: OWNER.uid, updatedByEmail: OWNER.email, note: "" };
    await setDoc(doc(db, "users/sa@x.com"), { ...base, email: "sa@x.com", role: "superadmin", services: {} });
    await setDoc(doc(db, "users/m@x.com"), { ...base, email: "m@x.com", role: "member", services: { files: "on" } });
    await setDoc(doc(db, "users/h@x.com"), { ...base, email: "h@x.com", role: "member", services: { ha: "on" } });
    await setDoc(doc(db, "users/sa2@x.com"), { ...base, email: "sa2@x.com", role: "superadmin", services: {} });
    await setDoc(doc(db, "services/files"), { name: "Files", levels: ["on"], enforcedBy: "cloudflare-access", order: 10, ...base });
    await setDoc(doc(db, "nasUsers/tbryant"), { name: "tbryant" });
    await setDoc(doc(db, "nasUsers/m"), { name: "m" });
  });
}

let pass = 0, fail = 0;
const failures = [];
async function t(name, expect, fn) {
  await seed();
  let ok;
  try { await (expect === "allow" ? assertSucceeds(fn()) : assertFails(fn())); ok = true; }
  catch (e) { ok = false; failures.push(name + " :: " + String(e.message).split("\n")[0]); }
  ok ? pass++ : fail++;
  console.log((ok ? "PASS " : "FAIL ") + name + " (expect " + expect + ")");
}

// ---- docs/permissions.md test plan 1-18 -------------------------------------
await t("1 owner writes a superadmin", "allow", () => setUser(asOwner(), OWNER, "sa@x.com", { role: "superadmin" }));
await t("2 owner grants high-risk (ha)", "allow", () => setUser(asOwner(), OWNER, "m@x.com", { services: { ha: "on" } }));
await t("3 superadmin writes member {files, agentdash:view}", "allow", () => setUser(asSa(), SA, "new@x.com", { services: { files: "on", agentdash: "view" } }));
await t("4 superadmin tries superadmin", "deny", () => setUser(asSa(), SA, "new@x.com", { role: "superadmin" }));
await t("5a superadmin tries ha", "deny", () => setUser(asSa(), SA, "new@x.com", { services: { ha: "on" } }));
await t("5b superadmin tries agentdash operate", "deny", () => setUser(asSa(), SA, "new@x.com", { services: { agentdash: "operate" } }));
await t("6a superadmin updates doc holding high-risk (note)", "deny", () => setUser(asSa(), SA, "h@x.com", { services: { ha: "on" }, note: "hi" }));
await t("6a2 superadmin strips high-risk from doc", "deny", () => setUser(asSa(), SA, "h@x.com", { services: {} }));
await t("6b superadmin deletes doc holding high-risk", "deny", () => deleteDoc(doc(asSa(), "users/h@x.com")));
await t("7 superadmin deletes plain member", "allow", () => deleteDoc(doc(asSa(), "users/m@x.com")));
await t("8a wrong updatedBy", "deny", () => setUser(asSa(), SA, "new@x.com", { updatedBy: "OTHERUID" }));
await t("8b wrong updatedByEmail", "deny", () => setUser(asSa(), SA, "new@x.com", { updatedByEmail: "other@x.com" }));
await t("9 member reads self", "allow", () => getDoc(doc(asM(), "users/m@x.com")));
await t("10a member reads other", "deny", () => getDoc(doc(asM(), "users/h@x.com")));
await t("10b member lists users", "deny", () => getDocs(collection(asM(), "users")));
await t("10c member writes own doc", "deny", () => setUser(asM(), M, "m@x.com", { services: { files: "on", photos: "on" } }));
await t("11 member reads catalog", "allow", () => getDoc(doc(asM(), "services/files")));
for (const [label, fn] of [
  ["get", (db) => getDoc(doc(db, "users/tbryant@fwogg3r.com"))],
  ["set", (db) => setUser(db, OWNER, "new@x.com")],
  ["list", (db) => getDocs(collection(db, "users"))],
  ["catalog get", (db) => getDoc(doc(db, "services/files"))],
]) await t("12 unverified owner " + label, "deny", () => fn(ctx(OWNER, false)));
await t("13a unknown service", "deny", () => setUser(asOwner(), OWNER, "new@x.com", { services: { nope: "on" } }));
await t("13b unknown level", "deny", () => setUser(asOwner(), OWNER, "new@x.com", { services: { agentdash: "root" } }));
await t("14 new ids accepted by owner", "allow", () => setUser(asOwner(), OWNER, "new@x.com", { services: { "files-smb": "on", rdp: "on", lmstudio: "on", pmjc: "on" } }));
for (const id of ["rdp", "lmstudio", "files-smb", "pmjc"])
  await t("15 superadmin high-risk " + id, "deny", () => setUser(asSa(), SA, "new@x.com", { services: { [id]: "on" } }));
await t("16 new id bad level (rdp admin)", "deny", () => setUser(asOwner(), OWNER, "new@x.com", { services: { rdp: "admin" } }));
for (const e of ["warp-gateway", "access-oidc", "none"])
  await t("17 catalog enforcedBy " + e, "allow", () => setSvc(asOwner(), OWNER, "x", { enforcedBy: e }));
await t("18a catalog bad enforcedBy", "deny", () => setSvc(asOwner(), OWNER, "x", { enforcedBy: "magic" }));
await t("18b catalog bad sso", "deny", () => setSvc(asOwner(), OWNER, "x", { sso: "x" }));

// ---- extra cases ------------------------------------------------------------
const NASM = { uid: "NASM", email: "m@fwogg3r.com" };
await t("nas: member reads own nasUsers/m", "allow", () => getDoc(doc(ctx(NASM), "nasUsers/m")));
await t("nas: non-fwogg3r email denied nasUsers/m", "deny", () => getDoc(doc(asM(), "nasUsers/m")));
await t("nas: member reads other nasUsers/tbryant", "deny", () => getDoc(doc(asM(), "nasUsers/tbryant")));
await t("nas: nobody lists", "deny", () => getDocs(collection(asOwner(), "nasUsers")));
await t("nas: owner cannot write", "deny", () => setDoc(doc(asOwner(), "nasUsers/tbryant"), { a: 1 }));
await t("nas: owner reads own", "allow", () => getDoc(doc(asOwner(), "nasUsers/tbryant")));
await t("nas: unverified member denied own", "deny", () => getDoc(doc(ctx(NASM, false), "nasUsers/m")));
await t("nas: unauthenticated denied", "deny", () => getDoc(doc(env.unauthenticatedContext().firestore(), "nasUsers/m")));

await t("owner: lists users", "allow", () => getDocs(collection(asOwner(), "users")));
await t("superadmin: lists users", "allow", () => getDocs(collection(asSa(), "users")));
await t("owner: deletes superadmin doc", "allow", () => deleteDoc(doc(asOwner(), "users/sa2@x.com")));
await t("owner: deletes high-risk doc", "allow", () => deleteDoc(doc(asOwner(), "users/h@x.com")));
const MIXED = { uid: "OWNERUID", email: "TBryant@Fwogg3r.com" };
// the client lowercases the profile email (permissions.js normEmail), so updatedByEmail is lowercase
await t("owner identified by email+verified: mixed-case token email", "allow", () => setUser(ctx(MIXED), OWNER, "new@x.com"));
const EVIL = { uid: "OWNERUID", email: "evil@x.com" };
await t("owner by uid is not enough (wrong email)", "deny", () => setUser(ctx(EVIL), EVIL, "new@x.com", { role: "superadmin" }));
await t("unverified owner cannot write", "deny", () => setUser(ctx(OWNER, false), OWNER, "new@x.com"));
await t("unverified owner cannot write catalog", "deny", () => setSvc(ctx(OWNER, false), OWNER, "x"));
await t("unverified superadmin denied", "deny", () => setUser(ctx(SA, false), SA, "new@x.com"));
await t("unauthenticated cannot read users", "deny", () => getDoc(doc(env.unauthenticatedContext().firestore(), "users/m@x.com")));
await t("owner: missing email_verified claim denied", "deny", () =>
  setUser(env.authenticatedContext("OWNERUID", { email: OWNER.email }).firestore(), OWNER, "new@x.com"));

await t("superadmin cannot write role owner", "deny", () => setUser(asSa(), SA, "new@x.com", { role: "owner" }));
await t("owner cannot write role owner", "deny", () => setUser(asOwner(), OWNER, "new@x.com", { role: "owner" }));
await t("superadmin cannot write owner's doc", "deny", () => setUser(asSa(), SA, "tbryant@fwogg3r.com"));
await t("owner may write owner's doc (member role)", "allow", () => setUser(asOwner(), OWNER, "tbryant@fwogg3r.com"));
await t("superadmin cannot update existing superadmin doc", "deny", () => setUser(asSa(), SA, "sa2@x.com", { role: "superadmin" }));
await t("superadmin cannot demote superadmin", "deny", () => setUser(asSa(), SA, "sa2@x.com", { role: "member" }));
await t("superadmin cannot delete superadmin", "deny", () => deleteDoc(doc(asSa(), "users/sa2@x.com")));
await t("superadmin updates plain member", "allow", () => setUser(asSa(), SA, "m@x.com", { services: { files: "on", photos: "on" }, note: "n" }));
await t("superadmin cannot delete owner's doc", "deny", () => deleteDoc(doc(asSa(), "users/tbryant@fwogg3r.com")));

await t("doc id lowercase: uppercase id denied", "deny", () => setUser(asOwner(), OWNER, "New@x.com"));
await t("doc id must equal email field", "deny", () => setDoc(doc(asOwner(), "users/new@x.com"), userData(OWNER, { email: "other@x.com" })));
await t("unknown field denied (users)", "deny", () => setDoc(doc(asOwner(), "users/new@x.com"), userData(OWNER, { email: "new@x.com", extra: 1 })));
await t("missing required field denied (users, no updatedBy)", "deny", () => {
  const d = userData(OWNER, { email: "new@x.com" }); delete d.updatedBy; return setDoc(doc(asOwner(), "users/new@x.com"), d);
});
await t("note too long denied", "deny", () => setUser(asOwner(), OWNER, "new@x.com", { note: "x".repeat(501) }));
await t("note absent allowed", "allow", () => {
  const d = userData(OWNER, { email: "new@x.com" }); delete d.note; return setDoc(doc(asOwner(), "users/new@x.com"), d);
});
await t("unknown field denied (services)", "deny", () => setSvc(asOwner(), OWNER, "x", { extra: 1 }));
await t("updatedAt client time denied (users)", "deny", () => setUser(asOwner(), OWNER, "new@x.com", { updatedAt: Timestamp.fromMillis(Date.now() - 86400000) }));
await t("updatedAt serverTimestamp allowed (users)", "allow", () => setUser(asOwner(), OWNER, "new@x.com"));
await t("updatedAt client time denied (services)", "deny", () => setSvc(asOwner(), OWNER, "x", { updatedAt: Timestamp.now() }));
await t("updatedAt missing denied (users)", "deny", () => {
  const d = userData(OWNER, { email: "new@x.com" }); delete d.updatedAt; return setDoc(doc(asOwner(), "users/new@x.com"), d);
});

await t("services: owner writes valid", "allow", () => setSvc(asOwner(), OWNER, "x"));
await t("services: superadmin writes valid", "allow", () => setSvc(asSa(), SA, "x", { enforcedBy: "cloudflare-access", cfAccessApp: "x", sso: "none", highRisk: true, highRiskLevels: ["on"], plannedEnforcement: "access-oidc" }));
await t("services: member denied write", "deny", () => setSvc(asM(), M, "x"));
await t("services: member denied update existing", "deny", () => setSvc(asM(), M, "files"));
await t("services: member denied delete", "deny", () => deleteDoc(doc(asM(), "services/files")));
await t("services: owner deletes", "allow", () => deleteDoc(doc(asOwner(), "services/files")));
await t("services: superadmin deletes", "allow", () => deleteDoc(doc(asSa(), "services/files")));
await t("services: bad plannedEnforcement denied", "deny", () => setSvc(asOwner(), OWNER, "x", { plannedEnforcement: "magic" }));
await t("services: non-https url denied", "deny", () => setSvc(asOwner(), OWNER, "x", { url: "http://x.example.com" }));
await t("services: null url allowed", "allow", () => setSvc(asOwner(), OWNER, "x", { url: null }));
await t("services: empty levels denied", "deny", () => setSvc(asOwner(), OWNER, "x", { levels: [] }));
await t("services: empty name denied", "deny", () => setSvc(asOwner(), OWNER, "x", { name: "" }));
await t("services: wrong updatedBy denied", "deny", () => setSvc(asOwner(), OWNER, "x", { updatedBy: "OTHER" }));
await t("services: wrong updatedByEmail denied", "deny", () => setSvc(asOwner(), OWNER, "x", { updatedByEmail: "other@x.com" }));
await t("services: all valid enforcedBy values", "allow", async () => {
  for (const e of ["cloudflare-access", "access-oidc", "warp-gateway", "own-login", "agentdash", "none"]) await setSvc(asOwner(), OWNER, "x", { enforcedBy: e });
});
await t("services: all valid sso values", "allow", async () => {
  for (const s of ["access-jwt", "oidc", "google-oidc", "none"]) await setSvc(asOwner(), OWNER, "x", { sso: s });
});
const NOBODY = { uid: "NOBODY", email: "nobody@x.com" };
await t("services: user without users doc cannot read catalog", "deny", () => getDoc(doc(ctx(NOBODY), "services/files")));
await t("services: member can list catalog", "allow", () => getDocs(collection(asM(), "services")));
await t("services: unverified member cannot read catalog", "deny", () => getDoc(doc(ctx(M, false), "services/files")));

console.log(`\n${pass} passed, ${fail} failed`);
failures.forEach((f) => console.log("  FAILED: " + f));
await env.cleanup();
process.exit(fail ? 1 : 0);
