# RESQD Platform Availability Strategy

**Version:** 1.0
**Date:** 2026-04-02

---

## Overview

RESQD is a quantum-secured digital vault. The core cryptographic engine (`resqd-core`) is written in Rust and compiles to both native and WASM targets. This document covers every platform where RESQD needs to be available, what each requires, costs, timeline, and prioritization.

---

## Phase Roadmap

| Phase | Platform | Timeline | Annual Cost | Priority |
|-------|----------|----------|-------------|----------|
| **MVP (Phase 1)** | Web App (PWA) + Stripe payments | 4-5 weeks | $0 | Must-have |
| **Phase 2** | iOS (WebView), Android (TWA), MCP Server | 3-4 weeks each | $124 first year | High |
| **Phase 3** | Desktop (Tauri), SSO (SAML/OIDC), Browser Extension | 4-8 weeks each | $300-600/yr | Medium |
| **Phase 4** | Native iOS/Android, SCIM, Plaid auto-vault, Marketplace listings | 6-8 weeks each | SOC 2: $30-80K | Future |

---

## 1. Web App (PWA on Cloudflare Pages)

**Priority:** MUST-HAVE for MVP

### What Exists
- Empty `web/` directory
- `resqd-core` compiles to WASM via `wasm-pack build --target web --features wasm`
- Full WASM bindings: hash, encrypt, KEM, key derivation, canary operations

### Requirements

**PWA Essentials:**
- Service worker via `@serwist/next` (successor to `next-pwa`)
  - Precache WASM binary (~2-4 MB), app shell, critical routes
  - WASM must be available even on slow networks -- the value prop is client-side crypto
- `manifest.json`: `name`, `short_name`, icons (192px, 512px), `start_url`, `display: standalone`, `theme_color`, `background_color`
- Required for "Add to Home Screen" on iOS Safari and Android Chrome

**Offline Capability:**
- Encrypt/hash files offline, queue uploads via Background Sync API
- Downloads require network (shards are in S3/GCS)
- IndexedDB for recently-accessed decrypted file metadata (never plaintext content)

**Cloudflare Pages Headers:**
```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```
Required for `SharedArrayBuffer` (Argon2id WASM parallelism).

**Limits:** 25 MB max deploy size (free tier), 500 deploys/month.

### Cost
$0 -- Cloudflare Pages free tier. Domain already on Cloudflare.

### Timeline
3-4 weeks for MVP: auth + upload + download + vault view.

---

## 2. iOS App (App Store)

**Priority:** Phase 2

### Requirements
- **Apple Developer Program:** $99/year. Enrollment 24-48 hours (individual).
- **App Store Review:** 24-48 hours typical. Crypto apps get extra scrutiny -- must file Export Compliance declaration (self-classification exemption under Category 5 Part 2 Note 4 for "personal use" encryption). Budget 1-2 weeks for first review cycle.
- **Minimum iOS:** 16+ (95%+ of active devices). iOS 16 has CryptoKit improvements and better LAContext biometric APIs.

### Key Storage (Secure Enclave)
- `SecureEnclave.P256` (CryptoKit) for device-bound signing key
- Master key from Argon2id cannot go in Secure Enclave directly (only supports P256/P384 keys it generates)
- Pattern: generate SE P256 key -> wrap/unwrap Argon2id master key -> store wrapped blob in Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- Result: master key at rest is encrypted by hardware that never leaves the device

### Biometric Auth
- `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` for Face ID / Touch ID
- `NSFaceIDUsageDescription` in `Info.plist`
- `kSecAccessControlBiometryCurrentSet` on Keychain items (re-enrolling biometrics invalidates access)

### Implementation Path
1. **Phase 2:** WebView wrapper (WKWebView loading PWA) -- ships in 2-3 weeks
2. **Phase 4:** Native Swift/SwiftUI with Rust FFI via `cbindgen` + Swift bridging header -- 6-8 weeks

### Cost
$99/year (Apple Developer Program). CI is free (GitHub Actions macOS runners).

### Timeline
2-3 weeks (WebView wrapper) or 6-8 weeks (native Swift with Rust FFI).

---

## 3. Android App (Google Play)

**Priority:** Phase 2

### Requirements
- **Google Play Console:** $25 one-time. Account review 2-7 days.
- **Play Review:** 1-3 days typically. Less strict than Apple on crypto. New developer accounts get slower initial reviews.
- **Minimum API:** 28 (Android 9 Pie), compile against 35. API 28 introduced `BiometricPrompt` and `StrongBox Keystore`. Covers 93%+ active devices.

### Key Storage (StrongBox Keystore)
- `KeyGenParameterSpec.Builder` with `.setIsStrongBoxBacked(true)` for hardware-backed AES-256 key
- Wrap Argon2id master key, store in Android Keystore
- Fall back to TEE-backed Keystore if StrongBox unavailable (older/cheaper devices)

### Biometric Auth
- `BiometricPrompt` with `BIOMETRIC_STRONG` (Class 3 biometrics: fingerprint, face with depth)
- `setUserAuthenticationRequired(true)` binds Keystore key access to biometric

### Implementation Path
1. **Phase 2:** TWA (Trusted Web Activity) -- runs PWA in Chrome with no browser UI. Google Play accepts TWAs. Ships in 2-3 weeks.
2. **Phase 4:** Native Kotlin/Jetpack Compose with Rust via JNI (`jni` crate + `cargo-ndk`) -- 6-8 weeks

### Cost
$25 one-time.

### Timeline
2-3 weeks (TWA) or 6-8 weeks (native Kotlin).

---

## 4. Desktop App (Tauri)

**Priority:** Phase 3

### Architecture
Tauri 2.x with Rust backend reuses `resqd-core` directly -- native speed, no WASM overhead. Frontend is the same Next.js web app in a webview.

### macOS
- Code signing: Apple Developer ID certificate ($99/year, shared with iOS)
- Notarization required since 10.15 -- submit to Apple notary service (5-15 min/build). Without it, Gatekeeper blocks.
- Universal binary via `--target universal-apple-darwin` (Tauri handles lipo)
- Distribute as DMG or `.app` in zip

### Windows
- Code signing: EV (Extended Validation) cert from DigiCert/Sectigo: $200-500/year. Without it, SmartScreen warns "unknown publisher" and kills conversion.
- OV certs ($100-200/year) work but need reputation building.
- MSI or NSIS installer (Tauri generates both)
- DPAPI via `windows-targets` crate for credential storage

### Linux
- No code signing needed
- AppImage (universal) + `.deb` for Debian/Ubuntu (Tauri generates both)
- `libsecret` for key storage (GNOME Keyring / KDE Wallet via `secret-service` D-Bus API)

### Cost
$99/year (Apple, shared with iOS) + $200-500/year (Windows EV cert).

### Timeline
4-6 weeks.

---

## 5. Browser Extension

**Priority:** Phase 3-4

### Concept
Detect when users upload files to Google Drive, Dropbox, email attachments. Offer to intercept and vault through RESQD, or vault a copy.

### Chrome (Manifest V3)
- Content scripts hook `<input type="file">` and drag-drop events (better than `webRequest` which is limited in MV3)
- Service worker background script
- WASM in service workers supported since Chrome 120+
- **Chrome Web Store:** $5 one-time. Review 1-3 business days.

### Firefox (WebExtensions)
- Nearly identical API to Chrome MV3 (Firefox kept `webRequest.onBeforeRequest` blocking)
- **Firefox Add-ons:** Free. Manual review 1-5 days.

### Safari (Web Extensions)
- Must be bundled in native macOS/iOS app container
- Requires Apple Developer Program ($99/year, shared)
- Safari Web Extensions API is a subset of Chrome's -- thorough testing needed
- Distributed via App Store only

### Cost
$5 (Chrome) + $0 (Firefox) + $0 (Safari, shared with Apple Developer).

### Timeline
6-8 weeks post-MVP.

### Notes
High complexity for UX polish. Must not feel intrusive. This is a differentiator but not a launch requirement.

---

## 6. MCP Marketplace (Anthropic Model Context Protocol)

**Priority:** Phase 2-3

### Concept
RESQD as an MCP server that AI assistants (Claude, etc.) use to securely store and retrieve files.

### Integration Architecture
```
AI Assistant (Claude Code, etc.)
  --> MCP Client
       --> resqd-mcp-server (stdio or SSE transport)
            - Tool: vault_store(file_path, metadata) -> asset_id
            - Tool: vault_retrieve(asset_id) -> decrypted file
            - Tool: vault_list(query) -> asset summaries
            - Tool: vault_verify(asset_id) -> canary chain status
            - Tool: vault_share(asset_id, recipient) -> share link
            - Resource: vault://assets/{id} (read access)
```

### Implementation
- Rust MCP server using `mcp-rust-sdk` or raw JSON-RPC over stdio
- Wraps `resqd-core`, handles auth via OAuth 2.0 device flow or API key
- User pre-authorizes with RESQD credentials. Server holds session token, not master key.
- Key derivation at invocation time (user provides passphrase via AI conversation)
- **Blind vault mode:** MCP server returns only asset ID + metadata, not content. AI can store files without reading back vault contents.

### Distribution
Anthropic's MCP registry is still evolving. Currently distributed as npm packages, Docker containers, or via `claude mcp add`. No formal marketplace yet -- but early positioning is valuable.

### Cost
$0.

### Timeline
3-4 weeks. The Rust core already has all primitives.

### Why This Matters
"Your AI can use your vault" is a compelling pitch for both consumers and enterprise. Low cost, high signal.

---

## 7. Bank/Payment Platform Integration

### Payment Processing (Phase 1)

**Stripe** -- standard integration for subscriptions.
- Stripe Checkout or Elements for payment UI
- Stripe Billing for subscription management
- 2.9% + $0.30 per transaction
- Timeline: 1-2 weeks
- No marketplace listing needed

**PayPal** -- optional, adds payment flexibility via Braintree SDK. Similar pricing.

### Financial Document Auto-Vaulting (Phase 4+)

**Concept:** Connect bank accounts via Plaid, auto-vault monthly statements with quantum encryption and tamper detection.

**Plaid:**
- Apply for Production access (2-8 week review)
- $0.30-1.50/link/month depending on products
- Use `Statements` product for PDF statement retrieval
- Use `Transactions` for data export

**Yodlee:** Enterprise pricing, $10K+/year minimum. Better for institutional use. Skip for now.

**Compliance:**
- PCI-DSS does not directly apply (RESQD vaults documents, not card data)
- Client-side encryption simplifies compliance posture
- SOC 2 Type II required for Plaid Production access and bank partnerships
  - Budget $30-80K, 3-6 months for initial audit
  - This is the real gate on bank integrations

### Cost
Stripe: transaction fees only. Plaid: per-link. SOC 2: $30-80K.

### Timeline
Stripe payments: 1-2 weeks. Plaid: 4-6 weeks + review wait. SOC 2: 3-6 months.

---

## 8. Enterprise / SSO

**Priority:** Phase 3

### SAML 2.0
- Implement SAML Service Provider
- Receive assertions from customer IdP (Okta, Entra ID, Ping)
- Configurable per-tenant: SP metadata endpoint, ACS URL, SLO URL
- Library: `saml2-js` (Node) or `onelogin/saml`

### OIDC (OpenID Connect)
- Simpler than SAML
- Authorization Code Flow + PKCE
- Works with any OIDC provider: Okta, Entra ID, Auth0, Google Workspace, Keycloak
- Build on `next-auth` with custom provider config

### SCIM 2.0
- Automated user provisioning/deprovisioning
- Required for enterprise sales
- Deprovision must revoke vault access and rotate affected key rings

### Marketplace Listings
| Marketplace | Cost | Requirements | Review Time |
|-------------|------|-------------|-------------|
| **Okta Integration Network (OIN)** | Free | SAML/OIDC + SCIM | 2-4 weeks |
| **Microsoft Entra ID Gallery** | Free | SAML/OIDC + SCIM | 2-6 weeks |
| **Google Workspace Marketplace** | Free | OIDC with Google as IdP | 2-4 weeks |

### Multi-Tenancy
- Isolated key rings per organization
- Separate canary chains
- Configurable storage policies ("all shards in EU regions" for GDPR)

### Cost
$0 for listings. Engineering investment is the real cost.

### Timeline
SAML + OIDC: 3-4 weeks. SCIM: 2-3 weeks. Marketplace listings: 2-6 weeks review each.

---

## Decision Framework

### Must-Have for MVP
1. Web App (PWA) -- primary interface, client-side WASM crypto
2. Stripe payments -- revenue from day one

### High-Value / Low-Cost (Phase 2)
3. iOS WebView wrapper -- 2-3 weeks, $99/year
4. Android TWA -- 2-3 weeks, $25 one-time
5. MCP Server -- 3-4 weeks, $0, strong differentiation

### Enterprise Enablers (Phase 3)
6. Desktop (Tauri) -- power users, offline-capable
7. SSO (SAML/OIDC) -- table stakes for any enterprise deal
8. Browser Extension -- differentiator, high polish required

### Long-Term / Capital-Intensive (Phase 4)
9. Native mobile apps -- better UX, Secure Enclave / StrongBox
10. SCIM provisioning -- enterprise automation
11. Plaid auto-vaulting -- requires SOC 2 ($30-80K)
12. Marketplace listings (Okta, Entra, Google) -- visibility in enterprise directories

---

## Total Year-1 Cost Estimate

| Item | Cost |
|------|------|
| Cloudflare Pages | $0 |
| Apple Developer Program | $99/year |
| Google Play Console | $25 one-time |
| Chrome Web Store | $5 one-time |
| Windows EV Code Signing | $200-500/year |
| Stripe | Transaction fees only |
| **Total (before SOC 2)** | **$329-629** |
| SOC 2 Type II (if pursuing bank integration) | $30,000-80,000 |
