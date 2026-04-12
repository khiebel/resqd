#!/usr/bin/env node
/**
 * RESQD passphrase-fallback E2E roundtrip.
 *
 * Mirror of `streaming_roundtrip.mjs`, but configures the virtual
 * WebAuthn authenticator WITHOUT the PRF extension enabled
 * (`hasPrf: false`). This simulates iPhone Safari — passkey works,
 * PRF does not — and exercises the entire passphrase fallback path:
 *
 *   Signup:
 *     1. Create passkey via virtual authenticator (no PRF)
 *     2. Land on the "Pick a recovery passphrase" screen
 *     3. Fill passphrase + confirm
 *     4. Client generates a fresh 32-byte random master key
 *     5. Client wraps master key with Argon2id(passphrase, salt)
 *     6. PUT /auth/me/recovery-blob → server stores the envelope
 *     7. Redirect to /vault/
 *
 *   Upload:
 *     1. Upload a small file through the real upload page
 *     2. Master key is the one we seeded during signup
 *
 *   Logout:
 *     1. Wipe sessionStorage + cookies so the next phase starts
 *        without any client-side state beyond the virtual
 *        authenticator's persistent credential store (mimicking a
 *        user who closed the tab)
 *
 *   Login:
 *     1. Navigate to /login/, fill email, click Sign in
 *     2. Passkey assertion succeeds (no PRF output)
 *     3. loginWithPasskey returns a session; loadMasterKey() is
 *        null; login page calls fallbackToPassphrase()
 *     4. GET /auth/me/recovery-blob → the envelope we stored
 *     5. User enters passphrase
 *     6. Client derives KEK, decrypts envelope, stashes master key
 *     7. Redirect to /vault/
 *
 *   Fetch:
 *     1. Download the file uploaded in the earlier phase
 *     2. SHA-256 compares byte-equal with the original input
 *
 * A SHA match is the contract: it proves the same master key came
 * out of the passphrase unwrap as went into the wrap during signup.
 * If the two keys differed, the XChaCha20-Poly1305 AEAD would fail
 * to decrypt the per-asset key and the download phase would throw.
 *
 * See tests/e2e/README.md for the overall mechanism. The only
 * delta from streaming_roundtrip.mjs is `hasPrf: false` and the
 * passphrase phases.
 */

import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";

// ─────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function loadSecrets() {
  const secretsPath = path.join(__dirname, ".secrets.env");
  if (!fs.existsSync(secretsPath)) {
    console.error(
      `ERROR: ${secretsPath} missing. Create it with CF_ACCESS_CLIENT_ID + CF_ACCESS_CLIENT_SECRET.`,
    );
    process.exit(2);
  }
  const raw = fs.readFileSync(secretsPath, "utf8");
  for (const line of raw.split("\n")) {
    const s = line.trim();
    if (!s || s.startsWith("#")) continue;
    const eq = s.indexOf("=");
    if (eq < 0) continue;
    const k = s.slice(0, eq).trim();
    const v = s.slice(eq + 1).trim();
    process.env[k] = v;
  }
  if (!process.env.CF_ACCESS_CLIENT_ID || !process.env.CF_ACCESS_CLIENT_SECRET) {
    console.error(
      "ERROR: CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET missing from .secrets.env",
    );
    process.exit(2);
  }
}
loadSecrets();

const BASE_URL = "https://resqd.ai";
// Separate email from streaming_roundtrip so the two tests don't
// step on each other when run in parallel or back-to-back.
const TEST_EMAIL = "claude-e2e-passphrase@resqd.ai.test";
const TEST_PASSPHRASE = "Claude-E2E-Passphrase-2026!";
const TEST_FILE_PATH = path.join(
  __dirname,
  "test-output",
  "passphrase-roundtrip-input.bin",
);
// Keep the test file small — the passphrase test is about the key
// unwrap path, not the streaming path. 4 MB exercises the
// single-shot upload which is faster to run headless.
const TEST_FILE_SIZE = parseInt(
  process.env.RESQD_E2E_PASSPHRASE_FILE_SIZE ?? `${4 * 1024 * 1024}`,
  10,
);

const CF_HEADERS = {
  "CF-Access-Client-Id": process.env.CF_ACCESS_CLIENT_ID,
  "CF-Access-Client-Secret": process.env.CF_ACCESS_CLIENT_SECRET,
};

// ─────────────────────────────────────────────────────────────────
// Helpers (mirrored from streaming_roundtrip.mjs; small enough to
// duplicate rather than factor out)
// ─────────────────────────────────────────────────────────────────

function log(tag, ...args) {
  console.log(`[${new Date().toISOString().slice(11, 19)}] ${tag}`, ...args);
}

function generateTestFile() {
  fs.mkdirSync(path.dirname(TEST_FILE_PATH), { recursive: true });
  if (
    fs.existsSync(TEST_FILE_PATH) &&
    fs.statSync(TEST_FILE_PATH).size === TEST_FILE_SIZE
  ) {
    log("file", `reusing ${TEST_FILE_PATH} (${TEST_FILE_SIZE} bytes)`);
    return;
  }
  log(
    "file",
    `generating ${TEST_FILE_SIZE} bytes of pseudo-random content at ${TEST_FILE_PATH}`,
  );
  const buf = Buffer.alloc(1024 * 1024);
  const fd = fs.openSync(TEST_FILE_PATH, "w");
  let written = 0;
  let seed = 0xdeadbeef;
  while (written < TEST_FILE_SIZE) {
    for (let i = 0; i < buf.length; i += 4) {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      buf.writeUInt32LE(seed >>> 0, i);
    }
    const remaining = TEST_FILE_SIZE - written;
    const slice = Math.min(buf.length, remaining);
    fs.writeSync(fd, buf, 0, slice);
    written += slice;
  }
  fs.closeSync(fd);
}

function sha256(filePath) {
  const h = crypto.createHash("sha256");
  h.update(fs.readFileSync(filePath));
  return h.digest("hex");
}

function tryAws(cmd) {
  try {
    return execSync(cmd, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (e) {
    return null;
  }
}

function preflightCleanup() {
  log("cleanup", `dropping any stale user row for ${TEST_EMAIL}`);
  tryAws(
    `aws dynamodb delete-item --table-name resqd-users --key '{"email":{"S":"${TEST_EMAIL}"}}' --region us-east-1`,
  );
  log("cleanup", "stale user row cleanup done");
}

// ─────────────────────────────────────────────────────────────────
// Main run
// ─────────────────────────────────────────────────────────────────

async function main() {
  generateTestFile();
  const inputHash = sha256(TEST_FILE_PATH);
  log("file", `input sha256 = ${inputHash.slice(0, 16)}…`);

  preflightCleanup();

  log("browser", "launching headless chromium");
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1280, height: 900 },
  });
  await context.route("**/*", async (route) => {
    const url = route.request().url();
    const host = new URL(url).hostname;
    const headers = { ...route.request().headers() };
    if (host === "resqd.ai" || host.endsWith(".resqd-app.pages.dev")) {
      headers["cf-access-client-id"] = CF_HEADERS["CF-Access-Client-Id"];
      headers["cf-access-client-secret"] = CF_HEADERS["CF-Access-Client-Secret"];
    }
    await route.continue({ headers });
  });

  // Install a virtual authenticator WITHOUT PRF. This is the one
  // change that makes Chrome behave like iOS Safari for our
  // purposes: passkey registration and assertion still work, but
  // navigator.credentials.create() / .get() do not populate
  // `extensions.prf.results.first` on the returned credential.
  const page = await context.newPage();
  page.on("console", (msg) => {
    const t = msg.type();
    if (t === "error" || t === "warning") {
      log(`browser:${t}`, msg.text());
    }
  });
  page.on("pageerror", (err) => log("browser:pageerror", err.message));

  const client = await context.newCDPSession(page);
  await client.send("WebAuthn.enable");
  const { authenticatorId } = await client.send(
    "WebAuthn.addVirtualAuthenticator",
    {
      options: {
        protocol: "ctap2",
        ctap2Version: "ctap2_1",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        automaticPresenceSimulation: true,
        isUserVerified: true,
        hasLargeBlob: false,
        hasCredBlob: false,
        hasMinPinLength: false,
        // The one change from streaming_roundtrip.mjs. Everything
        // else is identical so behavioral drift between this test
        // and the baseline is entirely attributable to the PRF path.
        hasPrf: false,
      },
    },
  );
  log(
    "webauthn",
    `virtual authenticator ${authenticatorId} added (ctap2.1, PRF DISABLED — simulating iPhone Safari)`,
  );

  // ───── SIGNUP ─────
  log("signup", `navigating to ${BASE_URL}/signup/`);
  await page.goto(`${BASE_URL}/signup/`, { waitUntil: "networkidle" });

  log("signup", `filling email ${TEST_EMAIL}`);
  await page.locator('input[type="email"]').first().fill(TEST_EMAIL);
  const createBtn = page.locator('button[type="submit"]').first();
  await createBtn.waitFor({ state: "visible", timeout: 5000 });

  log("signup", "clicking Create passkey — virtual authenticator will sign the challenge");
  await createBtn.click();

  // Expect to land on the passphrase-setup screen, NOT on /vault/.
  // The signup page routes into the passphrase phase when
  // `loadMasterKey()` returns null after registerWithPasskey
  // finishes, which happens whenever PRF is absent.
  log("signup", "waiting for passphrase setup heading");
  await page
    .getByRole("heading", { name: /pick a recovery passphrase/i })
    .waitFor({ timeout: 15_000 });
  log("signup", "passphrase setup screen reached");

  // Fill passphrase + confirm. Use the "Show" toggle selector to
  // find the inputs reliably regardless of DOM ordering — both
  // fields are type=password so we match on their placeholder
  // labels.
  log("signup", "filling passphrase + confirm");
  await page
    .locator('input[placeholder^="At least"]')
    .first()
    .fill(TEST_PASSPHRASE);
  await page
    .locator('input[placeholder="Type it again"]')
    .first()
    .fill(TEST_PASSPHRASE);

  log("signup", "submitting passphrase — client will generate master key + PUT recovery-blob");
  await page.getByRole("button", { name: /create vault/i }).click();

  // The signup page redirects to /vault/ once the recovery-blob
  // PUT succeeds and the master key is stashed.
  await page.waitForURL(/\/vault\//, { timeout: 30_000 });
  log("signup", "redirected to /vault/, signup+passphrase setup complete");

  // Verify master key is now in sessionStorage and the server row
  // records has_recovery_blob=true.
  const signupState = await page.evaluate(async () => {
    const mk = sessionStorage.getItem("resqd_master_key");
    const me = await fetch("https://api.resqd.ai/auth/me", {
      credentials: "include",
    }).then((r) => (r.ok ? r.json() : null));
    return {
      master_key_present: Boolean(mk),
      master_key_length: mk?.length ?? 0,
      has_recovery_blob: me?.has_recovery_blob ?? null,
    };
  });
  if (!signupState.master_key_present) {
    throw new Error(
      "FAIL: master key not in sessionStorage after passphrase signup",
    );
  }
  if (!signupState.has_recovery_blob) {
    throw new Error(
      `FAIL: server does not report has_recovery_blob=true (got ${signupState.has_recovery_blob})`,
    );
  }
  log(
    "signup",
    `post-signup state OK — master_key ${signupState.master_key_length} chars, has_recovery_blob=${signupState.has_recovery_blob}`,
  );

  // Remember the pre-logout master key so we can sanity check that
  // the post-login unwrap produces the SAME key (not just a
  // working one).
  const preLogoutMasterKey = await page.evaluate(() =>
    sessionStorage.getItem("resqd_master_key"),
  );

  // Bump quota (keeping consistent with streaming_roundtrip.mjs —
  // default quota is 100 MB which still fits 4 MB, but bumping is
  // harmless and documents intent).
  tryAws(
    `aws dynamodb update-item --table-name resqd-users --key '{"email":{"S":"${TEST_EMAIL}"}}' ` +
      `--update-expression "SET storage_quota_bytes = :q" ` +
      `--expression-attribute-values '{":q":{"N":"${2 * 1024 * 1024 * 1024}"}}' ` +
      `--region us-east-1 --return-values UPDATED_NEW 2>&1`,
  );

  // ───── UPLOAD ─────
  log("upload", `navigating to ${BASE_URL}/upload/`);
  await page.goto(`${BASE_URL}/upload/`, { waitUntil: "networkidle" });

  const fileInput = page.locator("input#resqd-file-input");
  await fileInput.waitFor({ state: "attached", timeout: 5000 });
  log(
    "upload",
    `setting input file to ${TEST_FILE_PATH} (${TEST_FILE_SIZE} bytes)`,
  );
  await fileInput.setInputFiles(TEST_FILE_PATH);

  log("upload", "waiting for ✓ Vaulted OR error");
  const doneLoc = page.locator("text=✓ Vaulted").first();
  const errLoc = page.locator("text=/^Error:/i").first();
  await Promise.race([
    doneLoc.waitFor({ timeout: 5 * 60_000 }),
    errLoc.waitFor({ timeout: 5 * 60_000 }),
  ]);
  const errText = (await errLoc.isVisible().catch(() => false))
    ? await errLoc.textContent().catch(() => null)
    : null;
  if (errText) {
    throw new Error(`upload page reported error: ${errText}`);
  }
  const assetId = await page.evaluate(() => {
    const all = Array.from(document.querySelectorAll("dd"));
    for (const dd of all) {
      const txt = dd.textContent?.trim() ?? "";
      if (/^[0-9a-f-]{36}$/i.test(txt)) return txt;
    }
    return null;
  });
  if (!assetId) throw new Error("FAIL: could not read asset ID from upload page");
  log("upload", `commit successful — asset_id = ${assetId}`);

  // ───── LOGOUT (simulate closing the tab on iPhone) ─────
  log("logout", "clearing session cookies + sessionStorage");
  await page.evaluate(() => {
    sessionStorage.clear();
    localStorage.clear();
  });
  await context.clearCookies();

  // Sanity: /auth/me should now 401 because the session cookie is gone.
  const postLogoutMe = await page.evaluate(async () => {
    const r = await fetch("https://api.resqd.ai/auth/me", {
      credentials: "include",
    });
    return { status: r.status };
  });
  if (postLogoutMe.status !== 401) {
    throw new Error(
      `FAIL: expected 401 after logout, got ${postLogoutMe.status}`,
    );
  }
  log("logout", "cookies cleared, /auth/me returns 401 — session gone");

  // ───── LOGIN (passphrase unlock path) ─────
  log("login", `navigating to ${BASE_URL}/login/`);
  await page.goto(`${BASE_URL}/login/`, { waitUntil: "networkidle" });

  // The login page kicks off a conditional-UI passkey background
  // listener on mount. With Chrome's virtual authenticator and
  // `automaticPresenceSimulation: true`, that background listener
  // fires AUTOMATICALLY — Chrome auto-selects the only discoverable
  // credential and signs the assertion without any user interaction.
  // This is actually realistic: an iPhone user with a synced
  // iCloud Keychain passkey sees the same experience.
  //
  // What this means for the test: after navigation, we might land
  // either on the typed-email screen (if the conditional flow is
  // slow) or directly on the passphrase unlock screen (if it's
  // fast, which is the common case). Race the two locators and
  // branch accordingly.
  const emailField = page.locator('input[type="email"]').first();
  const passphraseHeading = page.getByRole("heading", {
    name: /unlock with passphrase/i,
  });
  log("login", "racing typed-email form vs auto-passphrase prompt");
  await Promise.race([
    emailField.waitFor({ timeout: 15_000 }).catch(() => null),
    passphraseHeading.waitFor({ timeout: 15_000 }).catch(() => null),
  ]);

  if (await passphraseHeading.isVisible().catch(() => false)) {
    log(
      "login",
      "conditional UI auto-completed passkey ceremony — already at passphrase prompt",
    );
  } else {
    log("login", `filling email ${TEST_EMAIL} (typed-email flow)`);
    await emailField.fill(TEST_EMAIL);
    const signInBtn = page.locator('button[type="submit"]').first();
    await signInBtn.waitFor({ state: "visible", timeout: 5000 });
    log(
      "login",
      "clicking Sign in — virtual authenticator will assert without PRF",
    );
    await signInBtn.click();

    log("login", "waiting for passphrase unlock heading");
    await passphraseHeading.waitFor({ timeout: 15_000 });
  }
  log("login", "passphrase unlock screen reached");

  log("login", "filling passphrase + submitting");
  await page
    .locator('input[placeholder="Your passphrase"]')
    .first()
    .fill(TEST_PASSPHRASE);
  await page.getByRole("button", { name: /unlock vault/i }).click();

  await page.waitForURL(/\/vault\//, { timeout: 30_000 });
  log("login", "redirected to /vault/, passphrase unlock complete");

  // Verify the master key came back and is byte-identical to the
  // one we wrapped during signup. If these differ, the whole flow
  // is broken (decrypting any asset would fail).
  const postLoginMasterKey = await page.evaluate(() =>
    sessionStorage.getItem("resqd_master_key"),
  );
  if (!postLoginMasterKey) {
    throw new Error("FAIL: master key not in sessionStorage after passphrase login");
  }
  if (postLoginMasterKey !== preLogoutMasterKey) {
    throw new Error(
      `FAIL: master key after passphrase unwrap does not match the original wrap. ` +
        `pre=${preLogoutMasterKey.slice(0, 8)}… post=${postLoginMasterKey.slice(0, 8)}…`,
    );
  }
  log("login", "post-login master key byte-equal to pre-logout — unwrap path verified");

  // ───── FETCH / DOWNLOAD ─────
  log("fetch", `navigating to ${BASE_URL}/fetch/?id=${assetId}`);
  await page.goto(`${BASE_URL}/fetch/?id=${encodeURIComponent(assetId)}`, {
    waitUntil: "networkidle",
  });

  log("fetch", "waiting for decrypt to finish (up to 5 minutes)");
  await page
    .locator("text=/Downloaded|Decrypted|Save|Download/i")
    .first()
    .waitFor({ timeout: 5 * 60_000 });

  const [dl] = await Promise.all([
    page.waitForEvent("download", { timeout: 60_000 }),
    page.getByRole("button", { name: /download/i }).first().click(),
  ]);

  const outPath = path.join(
    __dirname,
    "test-output",
    "passphrase-roundtrip-output.bin",
  );
  await dl.saveAs(outPath);
  log("fetch", `saved decrypted file to ${outPath}`);

  const outHash = sha256(outPath);
  const outSize = fs.statSync(outPath).size;
  log("verify", `output size=${outSize} sha256=${outHash.slice(0, 16)}…`);

  const pass = outSize === TEST_FILE_SIZE && outHash === inputHash;
  if (pass) {
    log("verify", "✓ PASSPHRASE ROUNDTRIP PASS — input and output are byte-equal");
  } else {
    log(
      "verify",
      `✗ PASSPHRASE ROUNDTRIP FAIL — size ${TEST_FILE_SIZE} vs ${outSize}, hash ${inputHash.slice(0, 16)} vs ${outHash.slice(0, 16)}`,
    );
  }

  // ───── TEARDOWN ─────
  log("teardown", "removing virtual authenticator");
  await client.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  await browser.close();

  preflightCleanup();

  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("UNHANDLED:", err);
  process.exit(3);
});
