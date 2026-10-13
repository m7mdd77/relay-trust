# Relay Trust â€” hosted synthetic laboratory

Hosted companion to the dependency-free Node.js local prototype in the repository root. Built with the supplied Sites Vinext starter and Cloudflare D1. The original Ed25519 crypto and fifteen-check policy are reused unchanged.

Every visitor receives a separate anonymous synthetic sandbox. Its five key pairs stay server-side in a D1 record. A 256-bit HttpOnly, Secure, SameSite=Strict cookie locates the record by its hash; a separate mutation token binds browser writes. No account, model key, wallet, real site, or personal data is needed. Visitors control only their own synthetic owner. This grants no authority over real resources or another visitor.

The API commits each action with a D1 revision guard. Any concurrent revocation or effect forces a reload and full reevaluation. A successful effect also carries a database-time expiry guard. The request, consumed quota, events, and receipt are committed as one row update; replay returns the existing signed receipt. The session survives Worker restarts and lasts 24 hours. Keys are plaintext within private server-side database storage; no key-management or administrator-compromise protection is claimed.

Task/credential counts and mutations per minute are bounded within a sandbox. Active sessions are atomically capped at 256. Start fresh rotates keys and session cookies. Expired rows are purged in batches during session creation. The public demo is not an abuse-resistant production authority service: an anonymous attacker could fill the session capacity or consume request resources. No real owner login, third-party issuer authentication, process isolation, or external credential-standard compliance is claimed.

## Setup and checks

Node.js 24 recommended. Install the lockfile dependencies through the Sites plugin's installation helper or `npm run install:ci`. Declare `DB` in `.openai/hosting.json`. Apply the checked-in Drizzle migration to the local D1 preview, build, then `npm start -- --port 3252` to preview the built Worker on loopback. Follow the Sites skill for registration, source synchronization, migration application, and publication.

```powershell
node --test test/*.test.js
npm run build
```

`test/api.test.js` covers cookie isolation, private-key-free public export, Origin/token gates, all adversarial fixtures, concurrent idempotency, revocation, narrowed quota, persistence, expiry, and key rotation. The dependency-free local build separately passes its broader 34-test cryptographic/HTTP suite.

AI tools used: OpenAI Codex for implementation, tests, publication preparation, and verification. Source publishing into the Sites-managed repository is part of hosting; a separate public clean-clone repository for the DOO checklist remains pending.

Public walkthrough uses the same operations as the local prototype: valid handoff, execution, replay, out-of-scope request, spoof/tamper, revocation after approval, narrowed quota. The UI links the architecture, 252-word thesis, and 90-second narration script. Only screenshots and a recording script are supplied; no live video has been recorded.
