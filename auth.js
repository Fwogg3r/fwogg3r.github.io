// Shared sign-in logic for fwogg3r.com team pages.
// Only verified @fwogg3r.com email accounts are treated as members.
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import {
  getAuth,
  onAuthStateChanged,
  signOut,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
  getFirestore,
  doc,
  getDoc,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import { firebaseConfig } from "./firebase-config.js";

export const ALLOWED_DOMAIN = "fwogg3r.com";

// Stripe links for the $25/month Team Membership.
// On localhost the site automatically uses Stripe's sandbox (test mode) links,
// so you can run the whole flow with test cards and no real charges.
// On fwogg3r.com it always uses the live links.
const STRIPE_LIVE = {
  subscribe: "https://buy.stripe.com/14AbJ08vigSq8K97WUawo01",
  portal: "https://billing.stripe.com/p/login/6oU3cuaDq6dMgcB0usawo00",
};
const STRIPE_SANDBOX = {
  subscribe: "https://buy.stripe.com/test_9B614pdsR6Yw3hA4tCfEk00",
  portal: "https://billing.stripe.com/p/login/test_9B614pdsR6Yw3hA4tCfEk00",
};

export const STRIPE_TEST_MODE = ["localhost", "127.0.0.1", "[::1]"].includes(window.location.hostname);
const STRIPE = STRIPE_TEST_MODE ? STRIPE_SANDBOX : STRIPE_LIVE;
export const STRIPE_SUBSCRIBE_URL = STRIPE.subscribe;
export const STRIPE_PORTAL_URL = STRIPE.portal;

export const configured = !String(firebaseConfig.apiKey).startsWith("REPLACE");

const app = configured ? initializeApp(firebaseConfig) : null;
export const auth = app ? getAuth(app) : null;
const db = app ? getFirestore(app) : null;

// ---- Remote file access (TeraStation) -------------------------------------
// The TeraStation's WebAccess is published through a Cloudflare Tunnel at this
// address (no router ports opened). See claude/remote-files-setup.md.
export const FILES_URL = "https://files.fwogg3r.com/";

// tbryant@fwogg3r.com -> "tbryant"
export function nasUsernameFor(email) {
  return String(email || "").trim().toLowerCase().split("@")[0];
}

// Checks whether this member has a matching TeraStation account.
// The list lives in Firestore: collection "nasUsers", one document per
// TeraStation username (document ID = username, e.g. "tbryant").
// Firestore rules only let a verified member read the document whose ID
// matches their own email, so nobody can list the other usernames.
// Returns "ok" | "missing" | "unavailable".
export async function checkNasAccess(user) {
  if (!db || !isMember(user)) return "missing";
  try {
    const snap = await getDoc(doc(db, "nasUsers", nasUsernameFor(user.email)));
    return snap.exists() && snap.data().enabled !== false ? "ok" : "missing";
  } catch (err) {
    // permission-denied means "no document for you"; anything else is an outage.
    if (err && err.code === "permission-denied") return "missing";
    console.warn("NAS user check failed:", err);
    return "unavailable";
  }
}

if (!configured) {
  console.warn("Team sign-in is not set up yet: fill in firebase-config.js.");
}

const EMAIL_RE = /^[^\s@]+@fwogg3r\.com$/i;

export function isAllowedEmail(email) {
  return typeof email === "string" && EMAIL_RE.test(email.trim());
}

export function isMember(user) {
  return !!user && user.emailVerified === true && isAllowedEmail(user.email);
}

// Calls cb(user, isMember) whenever sign-in state changes.
// Any account outside @fwogg3r.com is signed out immediately.
export function onMemberChange(cb) {
  if (!configured) {
    cb(null, false);
    return;
  }
  onAuthStateChanged(auth, async (user) => {
    if (user && !isAllowedEmail(user.email)) {
      await signOut(auth);
      user = null;
    }
    cb(user, isMember(user));
  });
}

export async function logOut() {
  if (auth) await signOut(auth);
  window.location.href = "/index.html";
}

// Protects a page: non-members are sent to the login page.
// Reveals the page (removes body.auth-pending) once a member is confirmed.
export function requireMember(onReady) {
  const here = window.location.pathname;
  onMemberChange((user, member) => {
    if (!member) {
      window.location.replace("/login.html?next=" + encodeURIComponent(here));
      return;
    }
    document.body.classList.remove("auth-pending");
    if (onReady) onReady(user);
  });
}

// Top-right account menu. Shows the dropdown only for signed-in members.
export function mountUserMenu() {
  const wrap = document.createElement("nav");
  wrap.id = "user-menu";
  wrap.setAttribute("aria-label", "Account");
  document.body.appendChild(wrap);

  onMemberChange((user, member) => {
    wrap.innerHTML = "";
    if (!member) {
      const a = document.createElement("a");
      a.href = "/login.html";
      a.className = "user-menu-login";
      a.textContent = "Team login";
      wrap.appendChild(a);
      return;
    }

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "user-menu-button";
    btn.setAttribute("aria-haspopup", "true");
    btn.setAttribute("aria-expanded", "false");
    btn.textContent = user.email + " ▾";

    const menu = document.createElement("div");
    menu.className = "user-menu-list";
    menu.hidden = true;

    const items = [
      ["Members", "/members.html"],
      ["Files", "/remote/files/"],
      ["Billing", "/billing.html"],
    ];
    for (const [label, href] of items) {
      const a = document.createElement("a");
      a.href = href;
      a.textContent = label;
      menu.appendChild(a);
    }
    const out = document.createElement("button");
    out.type = "button";
    out.textContent = "Sign out";
    out.addEventListener("click", logOut);
    menu.appendChild(out);

    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      menu.hidden = !menu.hidden;
      btn.setAttribute("aria-expanded", String(!menu.hidden));
    });
    document.addEventListener("click", () => {
      menu.hidden = true;
      btn.setAttribute("aria-expanded", "false");
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        menu.hidden = true;
        btn.setAttribute("aria-expanded", "false");
      }
    });

    wrap.appendChild(btn);
    wrap.appendChild(menu);
  });
}
