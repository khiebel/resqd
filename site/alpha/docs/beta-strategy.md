# RESQD Beta User Acquisition Strategy

**Version:** 1.0
**Date:** 2026-04-02
**Goal:** 500 beta users across 5 segments, zero cost, zero guarantees

---

## Target Segments

| Segment | Why They Care | Target Count |
|---------|---------------|-------------|
| **Privacy/Security Enthusiasts** | Post-quantum crypto, zero-knowledge, client-side encryption | 150 |
| **Crypto/Web3 Users** | Seed phrase backup, wallet key storage, blockchain integrity | 100 |
| **Estate Planning / Digital Legacy** | Dead man's switch, family sharing, tamper-proof documents | 75 |
| **Developers / Technical Early Adopters** | Rust + WASM, open core, MCP integration | 100 |
| **Small Business / Freelancers** | Secure document vault, multi-cloud redundancy, compliance | 75 |

---

## Channel Strategy

### 1. Reddit

**Target Subreddits:**

| Subreddit | Subscribers | Fit | Approach |
|-----------|------------|-----|----------|
| r/privacy | 1.8M+ | Core audience | Share architecture deep-dive, not product pitch |
| r/selfhosted | 400K+ | Values data ownership | Post about the open Rust core |
| r/netsec | 500K+ | Security professionals | Technical post on post-quantum encryption choices |
| r/crypto | 2M+ | Seed phrase backup angle | Practical use case post |
| r/ethereum | 2M+ | On-chain canary anchoring | Technical integration post |
| r/rust | 300K+ | Rust community | Share the Rust + WASM architecture |
| r/webdev | 1M+ | WASM / PWA angle | Technical build post |
| r/personalfinance | 18M+ | Document vaulting | Estate planning angle |
| r/EstatePlanning | 30K+ | Dead man's switch | Digital legacy post |
| r/sysadmin | 800K+ | Enterprise/compliance | Multi-cloud redundancy angle |

**Reddit Rules:**
- Never direct-link to landing page in post body (gets removed as spam)
- Write a genuine technical post. Link to resqd.ai only in comments if asked.
- Post from your personal account, not a brand account
- Engage in comments for at least 2 hours after posting

**Template: r/privacy**

> **Title:** I built a digital vault that encrypts files client-side with post-quantum crypto before splitting them across multiple clouds
>
> I've been working on a project called RESQD that takes a different approach to file storage security. Instead of trusting one cloud provider, it:
>
> 1. Derives your encryption key from your passphrase using Argon2id (client-side, server never sees it)
> 2. Encrypts with XChaCha20-Poly1305 (AEAD, not AES-CBC)
> 3. Wraps per-file keys with ML-KEM-768 (FIPS 203 post-quantum KEM) for sharing
> 4. Splits encrypted files into 6 erasure-coded shards using Reed-Solomon (any 4 of 6 reconstruct)
> 5. Distributes shards across AWS, GCP, and Azure (no single provider has the complete file)
> 6. Maintains a canary chain -- every access produces a cryptographic commitment, so silent observation is impossible
>
> The crypto engine is Rust compiled to WASM, so all encryption/decryption happens in your browser. The server is a dumb shard router.
>
> I'm looking for beta testers who want to break it. Zero cost, zero guarantees, zero data promises during beta. If you're the kind of person who reads CVEs for fun, I'd love your feedback.
>
> Happy to answer questions about the architecture, threat model, or crypto choices.

**Template: r/selfhosted**

> **Title:** Open-source Rust crypto engine for a self-sovereign file vault -- looking for testers
>
> I've been building RESQD, a quantum-hardened file vault. The core engine is open-source Rust that compiles to both native and WASM. It handles:
>
> - BLAKE3 hashing (8+ GB/s)
> - XChaCha20-Poly1305 AEAD encryption
> - ML-KEM-768 post-quantum key encapsulation (FIPS 203)
> - Reed-Solomon erasure coding (4+2, any 4 of 6 shards reconstruct)
> - Canary-based tamper detection (every access rotates a commitment chain)
>
> The web frontend runs entirely client-side via WASM. Your encryption keys never leave your browser. The server just routes encrypted shards to S3/GCS/Azure.
>
> Looking for beta testers to stress-test the crypto and find edge cases. No cost, no SLA, no promises. Just a vault and your feedback.
>
> Code architecture and threat model in comments if interested.

**Template: r/crypto / r/ethereum**

> **Title:** Built a quantum-resistant vault for seed phrases and wallet keys -- uses ML-KEM-768 + on-chain canary commitments
>
> Problem: Your seed phrase backup is either in a safe deposit box (single point of failure, not fire/flood proof) or in a password manager (trusts one vendor, not quantum-resistant).
>
> RESQD takes a different approach:
>
> - Client-side encryption with post-quantum ML-KEM-768 (lattice-based, quantum computer resistant)
> - File is split into 6 erasure-coded shards across 3 cloud providers (any 4 reconstruct)
> - Every access to your vault creates a cryptographic canary commitment anchored on-chain (Base L2)
> - If someone accesses your seed phrase backup without your knowledge, the canary chain shows it
>
> Also has a dead man's switch: if you don't check in for N days, designated contacts can access your vault.
>
> Looking for crypto-native beta testers. Free, no guarantees, no data promises. I want people who will try to break it.

---

### 2. Hacker News

**Approach:** Single "Show HN" post. HN rewards technical depth and honesty about trade-offs.

**Template:**

> **Title:** Show HN: RESQD -- Quantum-hardened file vault (Rust/WASM, ML-KEM-768, multi-cloud erasure coding)
>
> Hi HN, I built RESQD (https://resqd.ai) to solve a problem I had with my own family's digital legacy -- what happens to your important files if you're not around?
>
> The technical approach:
> - All crypto runs client-side in WASM (Rust compiled via wasm-pack)
> - Encryption: XChaCha20-Poly1305 with per-file random keys
> - Post-quantum key exchange: ML-KEM-768 (FIPS 203) for sharing
> - Key derivation: Argon2id (memory-hard, no rainbow tables)
> - Integrity: BLAKE3 hashing + canary commitment chains
> - Redundancy: Reed-Solomon erasure coding (4+2), shards across AWS/GCP/Azure
> - Tamper detection: every vault access rotates a canary and produces a commitment -- silent observation is cryptographically impossible
>
> What I'd love feedback on:
> 1. The threat model (what am I missing?)
> 2. The crypto choices (why not X instead of Y?)
> 3. UX of the zero-knowledge vault concept
>
> Open beta, free, no SLA. Looking for people who want to find bugs and argue about cryptography.

**Timing:** Post between 8-10 AM ET on a Tuesday or Wednesday. Avoid Mondays (crowded) and Fridays (low traffic).

---

### 3. Product Hunt

**Approach:** Launch as a "beta" on Product Hunt. Recruit a hunter with followers if possible, or self-launch.

**Tagline:** "Quantum-encrypted multi-cloud file vault with dead man's switch"

**Template Description:**

> RESQD encrypts your most important files with post-quantum cryptography, splits them across multiple clouds, and detects if anyone accesses them without your knowledge.
>
> Built for people who take security seriously:
> - Zero-knowledge architecture: your encryption keys never leave your browser
> - Post-quantum: ML-KEM-768 protects against future quantum computers
> - Multi-cloud: files are erasure-coded across AWS, GCP, and Azure
> - Tamper-proof: cryptographic canary chain detects unauthorized access
> - Dead man's switch: if you don't check in, designated contacts get access
>
> Free beta. No credit card. Looking for feedback from security-conscious users.

**Timing:** Tuesday launch. Have 10+ friends/contacts ready to upvote in the first hour.

---

### 4. Discord Servers

**Target Servers:**

| Server | Focus | Approach |
|--------|-------|----------|
| **Rust Programming Language** (official) | Rust devs | Share in #showcase, mention WASM compilation |
| **The Programmer's Hangout** | General dev | Post in #project-showcase |
| **Cryptography** | Crypto academics/practitioners | Deep technical discussion |
| **Privacy Guides** | Privacy community | Architecture overview |
| **Ethereum / Solidity** | Web3 devs | On-chain canary anchoring |
| **IndieHackers** | Solo founders | Building in public angle |
| **Security BSides** (various city servers) | Security professionals | Threat model review |

**Template (Discord - concise):**

> Building RESQD -- a quantum-hardened file vault in Rust/WASM. Client-side ML-KEM-768 + XChaCha20-Poly1305 encryption, Reed-Solomon erasure coding across 3 cloud providers, canary-based tamper detection.
>
> Looking for beta testers who want to try to break it. Free, no promises. Feedback is the only currency.
>
> resqd.ai if curious. Happy to discuss the architecture here.

---

### 5. Privacy and Security Forums

| Forum | URL | Approach |
|-------|-----|----------|
| **Privacy Guides forum** | discuss.privacyguides.net | Architecture post in Security category |
| **Wilders Security** | wilderssecurity.com | Detailed technical review thread |
| **Schneier on Security comments** | schneier.com | Comment on relevant crypto/PQ articles |
| **Lobsters** | lobste.rs | Technical post (invite-only, need existing member) |
| **Tildes** | tildes.net | Thoughtful technical post |

**Template (Forum post):**

> **Subject:** Feedback wanted: quantum-hardened file vault using ML-KEM-768 + multi-cloud erasure coding
>
> I'm building a file vault called RESQD that uses a zero-knowledge architecture with post-quantum cryptography. Looking for feedback from this community on the threat model and crypto choices.
>
> Architecture summary:
> - Client-side Rust/WASM: all crypto runs in the browser
> - Argon2id key derivation from passphrase (server never sees it)
> - XChaCha20-Poly1305 AEAD encryption (192-bit nonces, safe random generation)
> - ML-KEM-768 (FIPS 203) for key encapsulation when sharing with family members
> - Reed-Solomon (4,2) erasure coding: file split into 6 shards, any 4 reconstruct
> - Shards distributed across AWS S3, GCP GCS, Azure Blob (no single provider has the file)
> - Canary commitment chain: every access produces a BLAKE3 commitment, anchored on-chain. Silent observation is impossible.
>
> Known limitations during beta:
> - No formal audit yet (planned after beta stabilization)
> - No SLA, no data durability guarantee
> - Single-developer project
>
> What I'd specifically like feedback on:
> 1. Are there weaknesses in using ML-KEM-768 for key exchange in a vault context?
> 2. Is the canary chain approach sound, or are there known attacks on this pattern?
> 3. What would you want to see in a security whitepaper before trusting this with real data?
>
> Free beta at resqd.ai. No account needed to read the threat model docs.

---

### 6. Crypto Communities

| Community | Platform | Angle |
|-----------|----------|-------|
| **Bitcoin Talk** | bitcointalk.org | Seed phrase backup |
| **Ethereum Magicians** | ethereum-magicians.org | On-chain canary anchoring on Base L2 |
| **DeFi Llama Discord** | Discord | Portfolio key management |
| **Ledger community** | Reddit/Discord | Hardware wallet seed backup |
| **MetaMask community** | Discord | Browser extension + wallet backup |

**Template:**

> Looking for beta testers for a quantum-resistant vault specifically designed for seed phrase and wallet key backup.
>
> Instead of writing your seed phrase on paper or trusting a single cloud backup, RESQD:
> - Encrypts with post-quantum ML-KEM-768 (resistant to quantum computers)
> - Splits your encrypted backup into 6 shards across 3 different cloud providers
> - Any 4 of 6 shards can reconstruct your backup (Reed-Solomon erasure coding)
> - Every access creates a cryptographic proof, so you know if someone accessed your backup
> - Dead man's switch: designate someone who gets access if you don't check in
>
> Free beta, no guarantees. I want crypto-native users who will stress test the recovery flows.

---

### 7. Estate Planning / Digital Legacy Groups

| Community | Platform | Approach |
|-----------|----------|----------|
| **r/EstatePlanning** | Reddit | Digital legacy angle |
| **r/personalfinance** | Reddit | Document security |
| **Bogleheads forum** | bogleheads.org | Financial document vaulting |
| **Estate planning Facebook groups** | Facebook | (less technical, focus on the problem) |
| **Elder law attorney networks** | LinkedIn | Professional referral angle |

**Template (non-technical audiences):**

> **What happens to your digital life if something happens to you?**
>
> I built RESQD to solve a problem I faced planning for my family's digital legacy. It's a secure vault for your most important files -- wills, insurance policies, account information, family photos -- with a "dead man's switch."
>
> How it works:
> - Your files are encrypted on your device before upload (the service can't read them)
> - Files are stored across multiple cloud providers for redundancy
> - You designate family members who can access the vault
> - If you don't check in for a set number of days, your designated contacts are notified and given access
>
> It uses military-grade encryption that's also resistant to future quantum computers (yes, that's a real concern for documents that need to last decades).
>
> I'm looking for beta testers -- people who care about digital estate planning and want to try it for free. No cost, no commitment. Just looking for feedback on whether this solves a real problem for you.

---

### 8. Developer Communities

| Community | Platform | Angle |
|-----------|----------|-------|
| **Rust users forum** | users.rust-lang.org | Rust + WASM architecture |
| **WASM community** | Discord/GitHub | WASM crypto performance |
| **Dev.to** | dev.to | Technical blog post |
| **Hashnode** | hashnode.com | Technical blog post |
| **GitHub** | github.com | Open the core crate, add README, star-bait |

**Template (Dev.to / Hashnode blog post):**

> **Title:** Building a Quantum-Hardened File Vault with Rust, WASM, and ML-KEM-768
>
> I've been building RESQD, a file vault where all cryptography runs client-side in WASM compiled from Rust. Here's the architecture and what I learned.
>
> [Technical deep-dive: 1500-2000 words covering crypto choices, WASM compilation, erasure coding, canary chain design]
>
> **What I need:** Beta testers who want to stress-test the crypto. If you find a bug in the encryption, I want to hear about it before anyone else does.
>
> [Link to beta signup]

---

## Outreach Sequence

### Week 1: Soft Launch
1. Open GitHub repo for `resqd-core` (the Rust crate, not the web app)
2. Post to r/rust (Rust showcase) and Rust Discord #showcase
3. Post technical blog on Dev.to

### Week 2: Security Community
4. Post to r/privacy, r/netsec
5. Post to Privacy Guides forum
6. Post to Lobsters (if you can get an invite)

### Week 3: Hacker News + Product Hunt
7. Show HN post (Tuesday 8-10 AM ET)
8. Product Hunt launch (same week, different day)
9. Cross-post to IndieHackers

### Week 4: Crypto + Estate Planning
10. Post to r/crypto, r/ethereum, Bitcoin Talk
11. Post to r/EstatePlanning, r/personalfinance
12. Post to Bogleheads forum

### Ongoing
- Engage in every comment thread for 48+ hours after posting
- DM anyone who asks good questions and offer direct access
- Track which channels produce the most engaged users (not just signups)

---

## Beta Signup Mechanics

### Landing Page (resqd.ai/beta)
- Email + one question: "What's the most important file you'd want to protect?"
- No credit card, no phone number
- Immediate access after signup (no waitlist gating unless you hit infra limits)

### Onboarding
1. Create passphrase (show entropy meter)
2. Upload one file (guided tutorial)
3. Download it back (prove the roundtrip works)
4. Invite one family member (test sharing)

### Feedback Loop
- In-app feedback button (text only, no screenshots -- we can't see their vault)
- Weekly email with 1 question (rotating: "What's confusing?", "What's missing?", "Would you pay for this?")
- Discord channel for beta users

---

## Success Metrics

| Metric | Target | Timeline |
|--------|--------|----------|
| Beta signups | 500 | 4 weeks |
| Activated (uploaded 1+ file) | 200 (40%) | 4 weeks |
| Retained at 2 weeks | 100 (20%) | 6 weeks |
| Shared with family member | 50 (10%) | 6 weeks |
| Bug reports filed | 50+ | 4 weeks |
| Security issues reported | 5+ | 4 weeks |
| "Would pay" responses | 30%+ of survey respondents | 6 weeks |

---

## What NOT to Do

1. **Don't spam.** One post per community, max. Follow up only if asked.
2. **Don't pitch.** Share the architecture, the problem, the trade-offs. Let people come to you.
3. **Don't promise security.** Say "looking for people to break it" not "unbreakable vault."
4. **Don't hide limitations.** Single developer, no audit yet, beta = beta.
5. **Don't gate access.** Waitlists kill momentum for beta. Let everyone in.
6. **Don't collect unnecessary data.** Email only. No phone, no address, no payment info during beta.
