#!/usr/bin/env node
/**
 * RESQD proof-of-absorption negative test.
 *
 * Companion to `streaming_roundtrip.mjs`. Where the positive test
 * proves a clean upload round-trips byte-equal, this test proves
 * the server REJECTS a commit where one of the claimed shard
 * hashes does not match the BLAKE3 of the bytes actually in S3.
 *
 * Regression coverage for Chunk 2.3 of the Verimus plan (server-side
 * full-shard BLAKE3 re-hash) + Chunk 2.4 (structured 422 response
 * with absorption_failed code and failed_shard_indices array).
 *
 * # Threat model
 *
 * A malicious or buggy client could claim "shard 0's BLAKE3 is X"
 * in the commit request while the bytes actually landed in S3 are
 * a different object (tampered in transit, or client-side bug, or
 * active attack where the attacker intercepts and replaces shards
 * but forgets to update the claimed hash). The server must not
 * accept such a commit — if it did, the canary chain would be
 * anchored to a vault whose contents don't match what the
 * client-side Merkle-style receipt claims.
 *
 * Chunk 2.3 defends against this by streaming each shard's S3
 * object through BLAKE3 on the server and comparing to the
 * client-claimed hash. This test proves that defense works.
 *
 * # Mechanism
 *
 * We use the streaming path (file > 100 MB threshold) because the
 * absorption check only runs in `api/src/stream.rs::stream_commit`
 * — single-shot commits in `handlers.rs::commit` only HeadObject
 * each shard to confirm existence, no re-hash. The minimum-viable
 * file size to trigger streaming is 100 MB + 1 byte; we use 101 MB
 * to keep the upload fast while staying safely above the threshold.
 *
 * The corruption is injected at the COMMIT request, not during the
 * parts uploads. Playwright intercepts the POST to
 * `/vault/stream/{id}/commit`, rewrites the JSON body to replace
 * `expected_shard_hashes_hex[0]` with 64 zero hex chars, and
 * forwards the modified body. Effects:
 *
 *   - All 6 shards are actually uploaded correctly (the real
 *     shard bytes land in S3 with their real BLAKE3).
 *   - The client claims "shard 0's BLAKE3 is all zeros" on commit.
 *   - Server streams the real shard 0 through BLAKE3, gets the
 *     real hash, compares against the all-zeros claim, mismatches.
 *   - Server cleans up shard objects, deletes the sidecar, and
 *     returns 422 with {code: "absorption_failed",
 *     reason: "blake3_mismatch", failed_shard_indices: [0]}.
 *
 * # Assertions
 *
 * Three independent checks must all pass:
 *
 *   1. The HTTP response from /vault/stream/{id}/commit is 422.
 *   2. The response body has code === "absorption_failed",
 *      reason === "blake3_mismatch", and failed_shard_indices
 *      contains 0.
 *   3. The upload page transitions to its error state with the
 *      absorption-specific message (surfaced via the upload page's
 *      Chunk 2.4 error UX).
 *
 * If any of these fail, exit code is 1. Only all three passing
 * yields exit code 0.
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
const TEST_EMAIL = "claude-e2e-absorption@resqd.ai.test";
const TEST_FILE_PATH = path.join(
  __dirname,
  "test-output",
  "absorption-negative-input.bin",
);
// Just over the 100 MB streaming threshold (in `web/app/upload/page.tsx`).
// Keeping the file small minimizes wall-clock time while still
// exercising the path that runs Chunk 2.3 absorption verification.
// ~101 MB = 105,906,176 bytes.
const TEST_FILE_SIZE = parseInt(
  process.env.RESQD_E2E_ABSORPTION_FILE_SIZE ?? `${101 * 1024 * 1024}`,
  10,
);

const CF_HEADERS = {
  "CF-Access-Client-Id": process.env.CF_ACCESS_CLIENT_ID,
  "CF-Access-Client-Secret": process.env.CF_ACCESS_CLIENT_SECRET,
};

// 64 zero hex chars — a valid-looking BLAKE3 hash that couldn't
// possibly be the hash of any real non-empty shard, so we know the
// server's comparison will reject it.
const CORRUPTED_HASH = "0".repeat(64);

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
  log(
    "file",
    `generating ${TEST_FILE_SIZE} bytes of pseudo-random content at ${TEST_FILE_PATH}`,
  );
  const buf = Buffer.alloc(1024 * 1024);
  const fd = fs.openSync(TEST_FILE_PATH, "w");
  let written = 0;
  let seed = 0xcafebabe;
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

  preflightCleanup();

  log("browser", "launching headless chromium");
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1280, height: 900 },
  });

  // Captured by the /vault/stream/{id}/commit route intercept so
  // the test can assert the server response shape at the end.
  const commitIntercept = {
    intercepted: false,
    url: null,
    originalBody: null,
    modifiedBody: null,
    responseStatus: null,
    responseBody: null,
  };

  // CF Access service token injection + commit rewrite. Both are
  // routed through a single route handler because Playwright only
  // supports one context.route per pattern.
  await context.route("**/*", async (route) => {
    const request = route.request();
    const url = request.url();
    const host = new URL(url).hostname;
    const headers = { ...request.headers() };

    if (host === "resqd.ai" || host.endsWith(".resqd-app.pages.dev")) {
      headers["cf-access-client-id"] = CF_HEADERS["CF-Access-Client-Id"];
      headers["cf-access-client-secret"] =
        CF_HEADERS["CF-Access-Client-Secret"];
    }

    // The only commit we care about is the POST to
    // /vault/stream/{id}/commit on api.resqd.ai. Everything else
    // passes through untouched.
    const isCommit =
      request.method() === "POST" &&
      host === "api.resqd.ai" &&
      /\/vault\/stream\/[^/]+\/commit$/.test(new URL(url).pathname);

    if (!isCommit) {
      await route.continue({ headers });
      return;
    }

    try {
      const rawBody = request.postData();
      commitIntercept.url = url;
      commitIntercept.originalBody = rawBody;
      const parsed = JSON.parse(rawBody || "{}");

      // Sanity — the commit request MUST carry
      // expected_shard_hashes_hex, otherwise the server won't run
      // Chunk 2.3 at all and the test becomes a no-op. Fail
      // loudly if this assumption ever breaks.
      if (
        !Array.isArray(parsed.expected_shard_hashes_hex) ||
        parsed.expected_shard_hashes_hex.length !== 6
      ) {
        throw new Error(
          `commit body missing expected_shard_hashes_hex (got: ${typeof parsed.expected_shard_hashes_hex})`,
        );
      }

      const originalHash0 = parsed.expected_shard_hashes_hex[0];
      parsed.expected_shard_hashes_hex[0] = CORRUPTED_HASH;
      const modified = JSON.stringify(parsed);
      commitIntercept.modifiedBody = modified;
      commitIntercept.intercepted = true;
      log(
        "intercept",
        `zeroing shard 0 hash in commit body (was ${originalHash0.slice(
          0,
          16,
        )}…, now ${CORRUPTED_HASH.slice(0, 16)}…)`,
      );
      await route.continue({ headers, postData: modified });
    } catch (err) {
      log("intercept", `failed to rewrite commit: ${err.message}`);
      await route.continue({ headers });
    }
  });

  const page = await context.newPage();
  page.on("console", (msg) => {
    const t = msg.type();
    if (t === "error" || t === "warning") {
      log(`browser:${t}`, msg.text());
    }
  });
  page.on("pageerror", (err) => log("browser:pageerror", err.message));

  // Watch for the commit response so we can grab its status + body
  // for the assertions at the end. Separate from the request-side
  // intercept because Playwright `route` handles the request lifecycle
  // but response bodies are easier to read via page.on("response").
  page.on("response", async (resp) => {
    try {
      const url = resp.url();
      if (!/\/vault\/stream\/[^/]+\/commit$/.test(new URL(url).pathname)) {
        return;
      }
      commitIntercept.responseStatus = resp.status();
      // Only parse as JSON if we expect a JSON body — 4xx from our
      // Lambda returns JSON per `ApiError::into_response`, so it's
      // safe. We catch parse errors anyway.
      const raw = await resp.text().catch(() => null);
      try {
        commitIntercept.responseBody = raw ? JSON.parse(raw) : null;
      } catch {
        commitIntercept.responseBody = { _raw: raw };
      }
      log(
        "response",
        `commit responded ${resp.status()} — ${raw?.slice(0, 120) ?? "(no body)"}`,
      );
    } catch (err) {
      log("response", `error handling commit response: ${err.message}`);
    }
  });

  // Install the virtual WebAuthn authenticator WITH PRF enabled —
  // this test is not about the passphrase path, it's about the
  // streaming absorption check. The baseline PRF flow is fine.
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
        hasPrf: true,
      },
    },
  );
  log("webauthn", `virtual authenticator ${authenticatorId} added (PRF enabled)`);

  // ───── SIGNUP ─────
  log("signup", `navigating to ${BASE_URL}/signup/`);
  await page.goto(`${BASE_URL}/signup/`, { waitUntil: "networkidle" });

  log("signup", `filling email ${TEST_EMAIL}`);
  await page.locator('input[type="email"]').first().fill(TEST_EMAIL);
  const createBtn = page.locator('button[type="submit"]').first();
  await createBtn.waitFor({ state: "visible", timeout: 5000 });

  log("signup", "clicking Create passkey");
  await createBtn.click();
  await page.waitForURL(/\/vault\//, { timeout: 30_000 });
  log("signup", "redirected to /vault/, signup complete");

  // Bump quota to 2 GB so the 101 MB file fits. Default is 100 MB
  // per-user, which is just under our test file size — without this
  // bump the quota check fails before the absorption check even
  // runs, and we'd be testing the wrong code path.
  log("quota", "bumping test user to 2 GB");
  tryAws(
    `aws dynamodb update-item --table-name resqd-users --key '{"email":{"S":"${TEST_EMAIL}"}}' ` +
      `--update-expression "SET storage_quota_bytes = :q" ` +
      `--expression-attribute-values '{":q":{"N":"${2 * 1024 * 1024 * 1024}"}}' ` +
      `--region us-east-1 --return-values UPDATED_NEW 2>&1`,
  );

  // ───── UPLOAD (expected to fail at commit) ─────
  log("upload", `navigating to ${BASE_URL}/upload/`);
  await page.goto(`${BASE_URL}/upload/`, { waitUntil: "networkidle" });

  const fileInput = page.locator("input#resqd-file-input");
  await fileInput.waitFor({ state: "attached", timeout: 5000 });
  log(
    "upload",
    `setting input file (${TEST_FILE_SIZE} bytes — streaming path)`,
  );
  await fileInput.setInputFiles(TEST_FILE_PATH);

  // Wait for the upload page to reach ITS error state. The commit
  // intercept will flip shard 0 hash → server returns 422 → upload
  // page surfaces the absorption_failed error with a
  // user-friendly message. Race ✓ Vaulted (should never happen)
  // and the error locator.
  log("upload", "waiting for upload error state (absorption check should reject)");
  const vaultedLoc = page.locator("text=✓ Vaulted").first();
  // The upload page renders errors with an "Error: …" prefix via
  // its phase === "error" branch; match any such element.
  const errLoc = page.locator("text=/Error|Absorption/i").first();
  const raceResult = await Promise.race([
    vaultedLoc
      .waitFor({ timeout: 10 * 60_000 })
      .then(() => "vaulted")
      .catch(() => null),
    errLoc
      .waitFor({ timeout: 10 * 60_000 })
      .then(() => "error")
      .catch(() => null),
  ]);

  if (raceResult === "vaulted") {
    throw new Error(
      "FAIL: upload completed successfully despite corrupted commit hash — absorption check did not fire",
    );
  }

  // Collect the visible DOM text so we can assert on the UI error
  // message, independently of the network response check below.
  const errorText = await page
    .locator("main")
    .first()
    .innerText()
    .catch(() => "(unable to read main text)");
  log("upload", `upload page error text: ${errorText.slice(0, 200).replace(/\s+/g, " ")}`);

  // ───── ASSERTIONS ─────
  log("assert", "running negative-test assertions");

  const failures = [];

  if (!commitIntercept.intercepted) {
    failures.push("commit request was never intercepted (check route pattern)");
  }

  if (commitIntercept.responseStatus !== 422) {
    failures.push(
      `expected commit response status 422, got ${commitIntercept.responseStatus}`,
    );
  }

  const body = commitIntercept.responseBody;
  if (!body || typeof body !== "object") {
    failures.push(
      `expected JSON response body, got ${JSON.stringify(body)}`,
    );
  } else {
    if (body.code !== "absorption_failed") {
      failures.push(
        `expected body.code === "absorption_failed", got ${JSON.stringify(body.code)}`,
      );
    }
    if (body.reason !== "blake3_mismatch") {
      failures.push(
        `expected body.reason === "blake3_mismatch", got ${JSON.stringify(body.reason)}`,
      );
    }
    if (
      !Array.isArray(body.failed_shard_indices) ||
      !body.failed_shard_indices.includes(0)
    ) {
      failures.push(
        `expected body.failed_shard_indices to include 0, got ${JSON.stringify(body.failed_shard_indices)}`,
      );
    }
  }

  // The upload page's error UX should surface the absorption-failed
  // message (from Chunk 2.4 handling in web/app/upload/page.tsx).
  // Be tolerant of whitespace and exact wording — we only want to
  // confirm the error path fired on the UI side, not regress on
  // copy changes.
  if (!/absorption/i.test(errorText)) {
    failures.push(
      `upload page error text does not mention "absorption" — got: ${errorText.slice(0, 200)}`,
    );
  }

  if (failures.length === 0) {
    log(
      "verify",
      `✓ ABSORPTION NEGATIVE TEST PASS — server rejected corrupted commit with 422/${body.code}/${body.reason}, shards=${JSON.stringify(body.failed_shard_indices)}`,
    );
  } else {
    log("verify", "✗ ABSORPTION NEGATIVE TEST FAIL");
    for (const f of failures) {
      log("verify", `   - ${f}`);
    }
  }

  // ───── TEARDOWN ─────
  log("teardown", "removing virtual authenticator");
  await client.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  await browser.close();

  preflightCleanup();

  process.exit(failures.length === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("UNHANDLED:", err);
  process.exit(3);
});
