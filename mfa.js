// TOTP multi-factor authentication helpers (Firebase Auth with Identity Platform; see docs/permissions.md, "MFA").
// Shared by login.html (second step of sign-in) and members.js (Security card: enroll / unenroll).
// The TOTP secret never leaves the browser except to Firebase: the QR code is drawn locally
// with the vendored qrcode-generator (vendor/qrcode-generator.js), no third-party QR service.
import {
  multiFactor,
  getMultiFactorResolver,
  TotpMultiFactorGenerator,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import qrcode from "./vendor/qrcode-generator.js";

export const MFA_ISSUER = "fwogg3r.com";

// ---- sign-in (second step) ----------------------------------------------------------------
export const isMfaRequired = (err) => !!err && err.code === "auth/multi-factor-auth-required";

// Starts the second step after signIn* threw auth/multi-factor-auth-required.
// Returns { resolver, hint } (hint = the enrolled TOTP factor) or null when no TOTP factor exists.
export function startMfaSignIn(auth, err) {
  const resolver = getMultiFactorResolver(auth, err);
  const hint = resolver.hints.find((h) => h.factorId === TotpMultiFactorGenerator.FACTOR_ID);
  return hint ? { resolver, hint } : null;
}

// Verifies a 6-digit code; resolves to the UserCredential (throws auth/invalid-verification-code etc.).
export function finishMfaSignIn({ resolver, hint }, code) {
  const assertion = TotpMultiFactorGenerator.assertionForSignIn(hint.uid, String(code).trim());
  return resolver.resolveSignIn(assertion);
}

export const cleanCode = (v) => String(v || "").replace(/\s+/g, "");
export const isCode = (v) => /^\d{6}$/.test(cleanCode(v));

// ---- enrollment ---------------------------------------------------------------------------
export function enrolledFactors(user) {
  return user ? multiFactor(user).enrolledFactors : [];
}
export const enrolledTotp = (user) => enrolledFactors(user).filter((f) => f.factorId === TotpMultiFactorGenerator.FACTOR_ID);
export const hasMfa = (user) => enrolledFactors(user).length > 0;

// Step 1 of enrollment. May throw auth/requires-recent-login.
// Returns { secret, key (text for manual entry), uri (otpauth://...) }.
export async function beginTotpEnrollment(user) {
  const session = await multiFactor(user).getSession();
  const secret = await TotpMultiFactorGenerator.generateSecret(session);
  const uri = secret.generateQrCodeUrl(user.email, MFA_ISSUER);
  return { secret, key: secret.secretKey, uri };
}

// Step 2: verify a code from the authenticator and finalize. Throws auth/invalid-verification-code on a wrong code.
export async function finishTotpEnrollment(user, secret, code, displayName = "Authenticator app") {
  const assertion = TotpMultiFactorGenerator.assertionForEnrollment(secret, cleanCode(code));
  await multiFactor(user).enroll(assertion, displayName);
  await user.reload(); // refresh enrolledFactors
}

export async function unenrollFactor(user, factor) {
  await multiFactor(user).unenroll(factor);
  await user.reload();
}

// Draws text as a QR code on a canvas (no network, no CSP impact).
export function drawQr(canvas, text, px = 6, margin = 4) {
  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();
  const n = qr.getModuleCount();
  const size = (n + margin * 2) * px;
  canvas.width = size;
  canvas.height = size;
  const g = canvas.getContext("2d");
  g.fillStyle = "#fff";
  g.fillRect(0, 0, size, size);
  g.fillStyle = "#000";
  for (let r = 0; r < n; r++)
    for (let c = 0; c < n; c++)
      if (qr.isDark(r, c)) g.fillRect((c + margin) * px, (r + margin) * px, px, px);
}

export function mfaErrorText(err) {
  switch (err && err.code) {
    case "auth/invalid-verification-code": return "That code is wrong or has expired. Enter the current 6-digit code from your authenticator app.";
    case "auth/code-expired": return "That code has expired. Enter the current code.";
    case "auth/missing-verification-code": return "Enter the 6-digit code.";
    case "auth/invalid-multi-factor-session": return "Your sign-in session expired. Please sign in again.";
    case "auth/too-many-requests": return "Too many attempts. Wait a few minutes and try again.";
    case "auth/network-request-failed": return "Network error. Check your connection and try again.";
    case "auth/second-factor-already-in-use": return "That authenticator is already enrolled.";
    case "auth/unverified-email": return "Verify your email address before enabling two-step verification.";
    case "auth/operation-not-allowed": return "Two-step verification (TOTP) is not enabled for this project yet.";
    case "auth/requires-recent-login": return "Please sign in again to continue.";
    default: return "Something went wrong. Please try again.";
  }
}
