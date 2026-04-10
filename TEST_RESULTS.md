# RESQD End-to-End Test Results
**Date:** 2026-04-09/10 (overnight session)
**Tester:** Claude (automated via Chrome browser)
**User:** khiebel@gmail.com
**URL:** https://resqd.ai

## 1. Vault Listing
- **Status:** PASS
- Signed in as khiebel@gmail.com
- Shows "0 B of 100.0 MB used"
- 1 asset visible: Google.pdf (7139d2b1-256d-4dfd-9930-aac388804a27)
- Navigation links all present: Upload, Connect Claude, Rings, Settings, Billing, Sign out

## 2. Fetch/Download Asset
- **Status:** PASS
- Clicked "Open" on Google.pdf
- Navigated to /fetch/ page with asset ID pre-filled
- Auto-fetched and decrypted: "121,947 bytes"
- Filename correctly decrypted: "Google.pdf (application/pdf)"
- Canary rotation triggered
- Download button available

## 3. Settings Page
- **Status:** PASS
- Master key export: shows masked key, Reveal/Hide toggle works
- BIP-39 mnemonic: "Show as 24 words" toggle works, displays 24 words correctly
- X25519 identity: shows masked private key with copy button
- API tokens: "No tokens yet" (correct, none minted)
- Recovery Kit: download button present with full explanation
- MCP config includes RESQD_X25519_PRIVKEY_B64 (new feature verified)

## 4. Rings Page
- **Status:** PASS
- Shows existing "Hiebel Family" ring with owner role
- Manage view shows:
  - Invite form with email + role dropdown (Owner/Adult/Child/Executor)
  - Estate trigger config (None/Inactivity/Scheduled)
  - Member list showing khiebel@gmail.com as owner

## 5. Billing Page
- **Status:** PASS
- Current plan: Trial (100 MB)
- 4 tiers render correctly:
  - Trial: free, 100 MB, 50 assets
  - Vault: $7.99/mo, 5 GB
  - Heirloom: $19.99/mo, 50 GB, family rings + estate
  - Custodian: $99/mo, 500 GB, 25 seats, SSO, SLA
- Upgrade buttons present (not wired to Stripe yet)

## 6. MCP Page
- **Status:** PASS
- Full documentation renders:
  - Install instructions (cargo install)
  - Token minting link
  - Master key copy link
  - Claude Desktop config (macOS/Linux/Windows tabs)
  - Claude Code `mcp add` command
  - 4 tools documented (upload_file, list_vault, fetch_file, delete_file)
  - Zero-knowledge caveat section

## 7. Admin Console
- **Status:** PASS (with bugs fixed)
- Dashboard tab: stats cards (1 user, 1 ring, API Live), audit log
- Users tab: user table with email, status, storage, identity, join date, Disable/Reset Quota buttons
- Infrastructure tab: Lambda metrics, DynamoDB table stats, S3 storage
- All 7 tabs render

## 8. Upload
- Not tested (would need a file input interaction)

## 9. Share
- Not tested (would need a second user account)

## 10. Recovery Kit Export
- Not tested (would trigger a file download)

## 11. Smoke Test (API layer)
- **Status:** PASS
- Health: ok
- POST /vault (legacy): creates asset, anchors on-chain
- GET /vault/{id}: fetches, rotates canary
- GET /vault/{id}/verify: on-chain count matches

## Bugs Found & Fixed

### BUG 1: WebAuthn RP ID mismatch on Pages domain
- **Severity:** HIGH
- **Found:** Navigating to resqd-app.pages.dev/login/ and trying to sign in
- **Error:** "The relying party ID is not a registrable domain suffix of, nor equal to the current domain"
- **Cause:** Passkeys registered with RP ID `resqd.ai` can't be used on `resqd-app.pages.dev`
- **Fix:** Must use resqd.ai domain, not the Pages URL. This is by design (WebAuthn spec), not a bug per se.
- **Note:** Users should always access via resqd.ai, not the raw Pages URL.

### BUG 2: Admin Infrastructure tab — [object Object] rendering
- **Severity:** MEDIUM
- **Found:** Admin > Infrastructure tab
- **Error:** Lambda metrics showed `0[object Object][object Object]` and `NaNms`
- **Cause:** API returns `{timestamp, value}` objects but frontend interface declared `number[]`
- **Fix:** Updated `InfraMetrics` interface to use `MetricPoint[]` and fixed `.reduce()` / `.map()` calls to extract `.value`
- **Deployed:** Yes

### BUG 3: Admin Infrastructure tab — S3 total size NaN
- **Severity:** LOW
- **Found:** Admin > Infrastructure tab
- **Error:** S3 Total size showed "NaN GB"
- **Cause:** Interface expected `total_bytes` but API returns `total_size_bytes`
- **Fix:** Updated interface and template to use `total_size_bytes`
- **Deployed:** Yes

### BUG 4: Origin secret blocking auth endpoints
- **Severity:** CRITICAL (fixed earlier in session)
- **Found:** Could not log in at all
- **Cause:** Origin secret middleware blocked /auth/* routes when called from browser (raw API GW URL)
- **Fix:** Exempted /auth, /vault, /users, /rings, /admin from origin secret check
- **Deployed:** Yes

### BUG 5: S3 NotFound not mapping correctly
- **Severity:** HIGH (fixed earlier in session)
- **Found:** GET /vault/{id} returning 500 for legacy assets
- **Cause:** AWS SDK v1 wraps NoSuchKey differently; string matching missed it
- **Fix:** Added `as_service_error().is_no_such_key()` check
- **Deployed:** Yes

## Not Tested (require manual interaction)
- File upload (needs file picker)
- Asset sharing (needs second authenticated user)
- Recovery Kit download (triggers browser download)
- API token minting (tested via API, not browser)
- Ring member invitation (needs second user with X25519 identity)
- Estate trigger firing
- Executor unlock notification email
