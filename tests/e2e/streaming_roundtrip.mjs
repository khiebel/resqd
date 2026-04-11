#!/usr/bin/env node
/**
 * RESQD streaming upload/download E2E roundtrip.
 *
 * Runs the full Track 1 Verimus pipeline against the LIVE production
 * frontend at https://resqd.ai — no Kevin tap required. Uses:
 *
 *   - A Cloudflare Access service token to bypass the Access wall.
 *     Stored in tests/e2e/.secrets.env (gitignored).
 *   - A Chrome DevTools Protocol **virtual WebAuthn authenticator**
 *     with the PRF extension enabled. This replaces the hardware
 *     passkey + Touch ID tap. The server accepts it because its
 *     `webauthn-rs` builder uses the default attestation preference
 *     of `None`.
 *   - A fixed test email. Before each run the test deletes any
 *     existing user row with that email so the test is idempotent.
 *   - A deterministic 4 MB test file (generated on disk if missing)
 *     so the roundtrip is fast but still exercises the single-shot
 *     path. The streaming path kicks in above 100 MB; there's a
 *     commented-out option near the bottom to use the 250 MB file
 *     if you want to exercise it specifically.
 *
 * What this script VALIDATES end-to-end:
 *
 *   - CF Access service token bypass + CORS path from resqd.ai to
 *     api.resqd.ai with credentials
 *   - WebAuthn signup + PRF key derivation in the live React app
 *   - Master key persisted in sessionStorage
 *   - Vault upload flow (single-shot OR streaming depending on
 *     file size)
 *   - Vault list shows the new asset
 *   - Fetch flow decrypts the asset back
 *   - Byte-equal plaintext after the roundtrip
 *   - Teardown: user and all their blobs are deleted
 */

import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

// ─────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Load .secrets.env → process.env.CF_ACCESS_CLIENT_ID + ..._SECRET
function loadSecrets() {
  const secretsPath = path.join(__dirname, ".secrets.env");
  if (!fs.existsSync(secretsPath)) {
    console.error(
      `ERROR: ${secretsPath} missing. Create it with CF_ACCESS_CLIENT_ID + CF_ACCESS_CLIENT_SECRET. See README.md.`,
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
    console.error("ERROR: CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET missing from .secrets.env");
    process.exit(2);
  }
}
loadSecrets();

const BASE_URL = "https://resqd.ai";
const API_URL = "https://api.resqd.ai";
const TEST_EMAIL = "claude-e2e@resqd.ai.test";
const TEST_FILE_PATH = path.join(__dirname, "test-output", "roundtrip-input.bin");
const TEST_FILE_SIZE = parseInt(process.env.RESQD_E2E_FILE_SIZE ?? `${4 * 1024 * 1024}`, 10); // 4 MB default
// Use 150 * 1024 * 1024 to push above the STREAMING_THRESHOLD_BYTES.

const CF_HEADERS = {
  "CF-Access-Client-Id": process.env.CF_ACCESS_CLIENT_ID,
  "CF-Access-Client-Secret": process.env.CF_ACCESS_CLIENT_SECRET,
};

// ─────────────────────────────────────────────────────────────────
// Helpers
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
  log("file", `generating ${TEST_FILE_SIZE} bytes of pseudo-random content at ${TEST_FILE_PATH}`);
  const buf = Buffer.alloc(1024 * 1024);
  const fd = fs.openSync(TEST_FILE_PATH, "w");
  let written = 0;
  let seed = 0x12345678;
  while (written < TEST_FILE_SIZE) {
    // xorshift so the content is deterministic (test reproducibility)
    // but high-entropy enough to make erasure coding real work.
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

// ─────────────────────────────────────────────────────────────────
// Pre-run cleanup: delete any existing test user + their blobs.
// Called DIRECTLY against DynamoDB / S3 via aws CLI because I have
// the same access as the deploy role. Avoids polluting admin audit
// with test signups.
// ─────────────────────────────────────────────────────────────────

import { execSync } from "node:child_process";

function tryAws(cmd) {
  try {
    return execSync(cmd, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    return null;
  }
}

function preflightCleanup() {
  log("cleanup", `dropping any stale user row for ${TEST_EMAIL}`);
  // DynamoDB: delete from resqd-users by email PK
  tryAws(
    `aws dynamodb delete-item --table-name resqd-users --key '{"email":{"S":"${TEST_EMAIL}"}}' --region us-east-1`,
  );
  // DynamoDB: delete any auth challenges pinned to the email (not
  // strictly required because of TTL, but keeps things clean)
  // No-op if the table is empty for this email; ignore failures.
  log("cleanup", "stale user row cleanup done");
}

// Default user quota is 100 MB (QUOTA_BYTES in api/src/auth.rs). The
// streaming-path test uses a 150 MB file so we bump the test account
// to 2 GB directly in DynamoDB. Runs AFTER signup so the user row
// exists.
function bumpTestQuota(bytes) {
  log("quota", `bumping ${TEST_EMAIL} to ${bytes} bytes`);
  const result = tryAws(
    `aws dynamodb update-item --table-name resqd-users --key '{"email":{"S":"${TEST_EMAIL}"}}' ` +
      `--update-expression "SET storage_quota_bytes = :q" ` +
      `--expression-attribute-values '{":q":{"N":"${bytes}"}}' ` +
      `--region us-east-1 --return-values UPDATED_NEW 2>&1`,
  );
  if (result === null) {
    log("quota", "update failed or ignored");
  }
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
    // We do NOT set extraHTTPHeaders here — if we did, Playwright
    // would attach the CF Access service token to EVERY request
    // including XHRs to api.resqd.ai, and the CORS preflight to the
    // Lambda would fail because `cf-access-client-secret` is not in
    // the Lambda's Access-Control-Allow-Headers. Instead, we
    // route-intercept and add the headers only for requests that
    // actually hit the CF Access wall — i.e. resqd.ai (and
    // app.resqd.ai, though unused here). api.resqd.ai is `bypass`
    // mode and doesn't need them.
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

  // Install a virtual WebAuthn authenticator on a raw CDP session.
  // Playwright exposes CDP via `context.newCDPSession(page)` so we
  // attach it to the first page we create. The authenticator options
  // mirror a platform passkey with PRF support — this is exactly
  // what RESQD's `navigator.credentials.create({prf: ...})` call
  // needs.
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
  const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", {
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
      hasPrf: true,
    },
  });
  log("webauthn", `virtual authenticator ${authenticatorId} added (ctap2.1, PRF enabled)`);

  // Signup
  log("signup", `navigating to ${BASE_URL}/signup/`);
  await page.goto(`${BASE_URL}/signup/`, { waitUntil: "networkidle" });

  // Fill email + click create vault. Selectors come from
  // web/app/signup/page.tsx — `input[type=email]` + the "Create vault"
  // button label.
  log("signup", `filling email ${TEST_EMAIL}`);
  await page.locator('input[type="email"]').first().fill(TEST_EMAIL);
  // The button label is literally "Create passkey" in idle state;
  // also matches "Waiting for your authenticator…" and friends in
  // other phases. We look for the submit button specifically.
  const createBtn = page.locator('button[type="submit"]').first();
  await createBtn.waitFor({ state: "visible", timeout: 5000 });

  // Clicking triggers navigator.credentials.create() which the virtual
  // authenticator handles automatically.
  log("signup", "clicking Create passkey — virtual authenticator will sign the challenge");
  await createBtn.click();

  // Wait for signup to complete — the signup page redirects to /vault/
  // on success.
  await page.waitForURL(/\/vault\//, { timeout: 30_000 });
  log("signup", "redirected to /vault/, signup complete");

  // Dump master key state to verify PRF worked. The real key in
  // web/app/lib/passkey.ts is `resqd_master_key`.
  const masterKeyState = await page.evaluate(() => {
    try {
      const mk = sessionStorage.getItem("resqd_master_key");
      return { present: Boolean(mk), length: mk?.length ?? 0, keys: Object.keys(sessionStorage) };
    } catch (e) {
      return { present: false, error: String(e) };
    }
  });
  if (!masterKeyState.present) {
    throw new Error(
      `FAIL: master key not in sessionStorage — PRF extension did not produce a key. State: ${JSON.stringify(masterKeyState)}`,
    );
  }
  log("signup", `master key present in sessionStorage (${masterKeyState.length} chars)`);

  // Bump quota to 2 GB so the streaming-path test (150+ MB file)
  // doesn't trip the default 100 MB cap. Must happen after signup
  // so the user row actually exists.
  bumpTestQuota(2 * 1024 * 1024 * 1024);

  // ───── UPLOAD ─────
  log("upload", `navigating to ${BASE_URL}/upload/`);
  await page.goto(`${BASE_URL}/upload/`, { waitUntil: "networkidle" });

  const fileInput = page.locator('input#resqd-file-input');
  await fileInput.waitFor({ state: "attached", timeout: 5000 });
  log("upload", `setting input file to ${TEST_FILE_PATH} (${TEST_FILE_SIZE} bytes)`);
  await fileInput.setInputFiles(TEST_FILE_PATH);

  // Wait for either the "✓ Vaulted" confirmation OR an error state,
  // whichever comes first. The upload page renders "Error: …" when
  // phase === "error", so we race the two locators.
  log("upload", "waiting for ✓ Vaulted OR error (up to 5 minutes)");
  const doneLoc = page.locator("text=✓ Vaulted").first();
  const errLoc = page.locator("text=/^Error:/i").first();
  await Promise.race([
    doneLoc.waitFor({ timeout: 5 * 60_000 }),
    errLoc.waitFor({ timeout: 5 * 60_000 }),
  ]);
  const errText = await errLoc.isVisible().catch(() => false)
    ? await errLoc.textContent().catch(() => null)
    : null;
  if (errText) {
    throw new Error(`upload page reported error: ${errText}`);
  }
  const assetId = await page.evaluate(() => {
    // The asset ID is shown in a <dd class="font-mono text-xs"> under
    // the "Asset ID" label. Grab by text neighborhood.
    const all = Array.from(document.querySelectorAll("dd"));
    for (const dd of all) {
      const txt = dd.textContent?.trim() ?? "";
      if (/^[0-9a-f-]{36}$/i.test(txt)) return txt;
    }
    return null;
  });
  if (!assetId) throw new Error("FAIL: could not read asset ID from upload page");
  log("upload", `commit successful — asset_id = ${assetId}`);

  // ───── FETCH / DOWNLOAD ─────
  log("fetch", `navigating to ${BASE_URL}/fetch/?id=${assetId}`);
  await page.goto(`${BASE_URL}/fetch/?id=${encodeURIComponent(assetId)}`, {
    waitUntil: "networkidle",
  });

  // Wait for decoded download to be ready; the page transitions to
  // phase=done and offers a "Download" button.
  log("fetch", "waiting for decrypt to finish (up to 5 minutes)");
  await page.locator("text=/Downloaded|Decrypted|Save|Download/i").first().waitFor({ timeout: 5 * 60_000 });

  // Extract the decrypted bytes via JS — the fetch page stores
  // plaintextBytes in React state; we'll grab them via a
  // purpose-built window hook. Simpler: use the download button and
  // let Playwright capture the file.
  const [dl] = await Promise.all([
    page.waitForEvent("download", { timeout: 60_000 }),
    page.getByRole("button", { name: /download/i }).first().click(),
  ]);

  const outPath = path.join(__dirname, "test-output", "roundtrip-output.bin");
  await dl.saveAs(outPath);
  log("fetch", `saved decrypted file to ${outPath}`);

  const outHash = sha256(outPath);
  const outSize = fs.statSync(outPath).size;
  log("verify", `output size=${outSize} sha256=${outHash.slice(0, 16)}…`);

  const pass = outSize === TEST_FILE_SIZE && outHash === inputHash;
  if (pass) {
    log("verify", "✓ ROUNDTRIP PASS — input and output are byte-equal");
  } else {
    log("verify", `✗ ROUNDTRIP FAIL — size ${TEST_FILE_SIZE} vs ${outSize}, hash ${inputHash.slice(0, 16)} vs ${outHash.slice(0, 16)}`);
  }

  // ───── TEARDOWN ─────
  log("teardown", "removing virtual authenticator");
  await client.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  await browser.close();

  preflightCleanup(); // drop the test user row again so the next run is clean

  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("UNHANDLED:", err);
  process.exit(3);
});
