# RESQD Billing Model

**Status:** Placeholder / design. Not implemented — no payment processing yet. Used to drive pricing copy and the mock `/billing` page in the web app.

## Principle — security is never gated

The single most important rule of the RESQD pricing model:

> **Every tier gets the same cryptographic guarantees.**

No "pro-only" post-quantum crypto. No "business-only" on-chain anchoring. No "enterprise-only" zero-knowledge. The entire security stack — XChaCha20-Poly1305, BLAKE3, ML-KEM-768, Reed-Solomon 4+2 multi-cloud, Base L2 canary anchoring, WebAuthn passkey auth — is delivered to every paying and free user, forever.

Tiers differ on **capacity** and **convenience**:

- how much you can store
- how many assets
- how many people in your vault
- how much support response we promise
- which power features (estate triggers, SSO, audit logs) you get

This is the trust commitment. If we ever break it — gate a security feature behind a paywall — the zero-knowledge story stops being honest, because a freeloading adversary's crypto would be weaker than a paying user's. We can't compromise that without compromising the product.

## Cost structure (unit economics)

From `project_resqd.md`:

| users | infra cost |
| --- | --- |
| 0 | ~$3.50 / mo |
| 100 | ~$95–145 / mo |
| 10,000 | ~$6.5K–11K / mo |

Dominant variable costs per user:

1. **Storage** — S3 + GCS + Azure Blob, ~$0.023/GB/mo each × 3 copies (erasure-coded 4+2, so effective 1.5× raw storage). Call it $0.10/GB/mo all-in.
2. **Egress** — fetches download shards direct from S3/GCS, $0.09/GB typical.
3. **Lambda + API Gateway** — negligible for normal usage; roughly $0.0001 per API call.
4. **Base L2 anchoring** — $0.0027 per canary anchor. At 10 fetches/day per user: $0.80/user/mo.
5. **DynamoDB** — $0.0000025 per on-demand read, $0.00000125 per write. Negligible.

A user storing 10 GB and fetching 5× per day costs roughly:

- storage: 10 × $0.10 = $1.00
- egress: 10 × 5 × 30 × $0.09 = eep. Actually if they download the full asset every fetch, that's $13.50/mo. Realistically they don't — they fetch small subsets. Budget $1–3.
- anchoring: 5 × 30 × $0.0027 = $0.40
- compute: $0.05
- **total: $2.50 – $5.00 / user / mo**

So the $7.99 Personal tier has ~40–60% gross margin on a typical 5 GB user, leaving room for the free tier to be carried and support costs.

## Tiers

### Free — "Trial"

**$0 / mo**

- 100 MB storage
- Up to 50 assets
- Single user
- Full PQ crypto, multi-cloud, on-chain anchoring *(same as every other tier)*
- Community support only (GitHub / Discord)
- Alpha user program

**Why this exists:** let anyone try the complete security stack with zero friction, so the decision isn't *"is this worth $8?"* but *"do I want more than 100 MB?"*. Anyone whose family photos or tax returns blow past 100 MB upgrades naturally.

### Personal — "Vault"

**$7.99 / mo** or **$79 / yr** (save 2 months)

- 5 GB storage
- Unlimited assets
- Single user
- Email support, 48-hour response
- Passkey + hardware key registration
- API tokens + MCP access

**Why this price:** sits between iCloud+ ($0.99/50GB) which has no zero-knowledge, and 1Password Family ($4.99) which has no blockchain anchor, but below Prisidio ($11.99) which has weaker crypto. We're the premium consumer tier that actually delivers on "quantum-secured."

### Family — "Heirloom"

**$19.99 / mo** or **$199 / yr**

- 50 GB storage
- Unlimited assets
- Up to 5 family members
- **Estate triggers** — designated beneficiary gets read access on one of:
  - Owner death (verified via a trusted-person multi-party confirmation)
  - Owner-set inactivity period (e.g., no canary rotation in 90 days)
  - Scheduled unlock date
- Shared vault folders with per-member permissions
- Priority support, 24-hour response

**Why this is the anchor tier:** the single killer differentiator RESQD has over every password manager and cloud drive is the combination of *zero-knowledge* with *verifiable posthumous access*. Prisidio and Gentreo target this market with weaker crypto; 1Password targets it without the heritage angle. "Heirloom" is the tier where RESQD's full product promise shows up, and it's the tier the marketing funnel should center on.

### Business — "Custodian"

**$99 / mo** base + $9 / seat above 5

- 500 GB pooled storage
- Unlimited assets
- Up to 25 seats (then contact sales)
- SSO (OIDC / SAML)
- Audit log export
- Admin console with per-member access policies
- 99.9% SLA
- Dedicated support, 4-hour response

**Why this exists:** regulated-industry customers who need an auditable vault. Not the primary focus until after consumer tier proves PMF, but listed so enterprises know it's coming.

### Enterprise — "Sovereign"

**Custom pricing.** Self-hostable on customer infrastructure. BYO-KMS. Compliance add-ons (SOC 2 attestation, HIPAA BAA, GDPR DPA). Dedicated key ceremony. Not a near-term offering but documented so the category exists.

## Add-ons

- **Extra storage:** $2 / mo per additional 10 GB on any paid tier.
- **Hardware key registration:** free on all tiers (security — never gated).
- **Notary integration** *(future)*: $5 per notarized document, with the notary's signature anchored on-chain.
- **Dedicated chain relay** *(future)*: $15 / mo private RPC pinning to avoid public Base L2 replica lag, for users who want instant read-after-write.

## Not charging for

- Post-quantum encryption. Ever.
- Multi-cloud storage. Every tier spans S3 + GCS + Azure.
- On-chain canary anchoring. Every fetch anchors, every tier.
- Zero-knowledge architecture. Not a feature — it's the product.
- Passkeys / WebAuthn. Auth hygiene is free.

## Billing mechanics (when we turn it on)

- Stripe Checkout for self-serve (Personal, Heirloom).
- Invoice billing for Custodian.
- Annual commits get a 2-month discount across the board.
- Free-to-paid upgrade is instant; cap increases apply immediately.
- Downgrade with over-capacity storage: user gets 30 days read-only grace to download or delete before writes are blocked. Never silently delete user data.

## Open questions

- **Lifetime plans?** Prisidio offers a one-time $299 lifetime tier. Tempting for heritage/estate positioning ("I bought this vault for my kids"), but a commitment shaped like "I'll be running this infrastructure forever" is a promise I shouldn't make until the business is more proven. Revisit after 6 months of Personal tier data.
- **Crypto payments?** Base L2 native would be thematic (the vault already uses Base for anchoring), and it side-steps payment processor chargebacks. Not blocking but worth trialing once there's volume.
- **Anonymous payments?** The product promise is "we don't know what you store." It's awkward that we still know who pays. Proton handles this with cash payments; we could do the same. Low priority, strong principle signal.
