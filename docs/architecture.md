# Architecture snapshot

```mermaid
flowchart LR
  O[Workshop Owner: pinned Ed25519 root] -->|signed ticket.create grant| D[Scoped delegation: Scout → Steward]
  L[Evidence Lab: pinned Ed25519 root] -->|signed inspection receipts + attestation| A[Issuer-backed action history]
  S[Scout: distinct Ed25519 identity] -->|signed request binds exact D + A| V[Patch Steward verifier]
  D --> V
  A --> V
  R[(Live revocation registry)] --> V
  V --> P[All policy checks must pass]
  P --> T[SQLite transaction: fresh quota + trust recheck]
  T -->|allowed| E[One synthetic repair ticket + signed receipt]
  T -->|denied| N[Explain failed checks; no effect]
  E --> I[Replay request ID returns original receipt]
```

**Identity → claims → verification → policy:** identity is a SHA-256 fingerprint of an Ed25519 public key. Claims separately express the owner's authority and the lab's observed synthetic history. Verification establishes issuer and subject binding, proof of requester key possession, audience, exact credential hashes, validity, live revocation, and signed history integrity. Policy requires ticket.create on SITE-17 and available quota. Self-reported reputation is irrelevant.

**Attack boundary:** Mirror can copy Scout's name, identifier, public key, signed claims, and high reputation number. Without Scout's private key its request signature fails. Changing a grant invalidates the owner signature; a valid key does not authorize a different capability or recipient. Initial acceptance conveys no irrevocable execution authority.

**Execution boundary:** `BEGIN IMMEDIATE` serializes the authoritative recheck, quota query, receipt insert, and event. Each signed request is stored before execution; receipt `decision_id` is unique. Revocation before this boundary blocks a task. Revocation after a committed effect cannot undo it; subsequent replay only returns history. Owner renewal/narrowing revokes the old grant instead of mutating a signed credential. A narrowed grant inherits the same capability/resource/audience and a reduced quota.

**Local operator boundary:** owner and lab custody share a process with the agent fixtures; public roots come from the local registry. Browser requests only select test cases. Session token, Origin/Host gates, CSP, input validation, loopback binding, and body/rate limits reduce browser-driven local abuse. They do not establish a real owner login or protect against machine compromise.

**Storage and disclosure:** SQLite stores private identities, public envelopes, revocation flags, prepared tasks, receipts, settings, and timeline events. Only public identities/envelopes/receipts/events leave the server. The export omits private keys and the mutation token. Signed history is independently verifiable; timeline events and revocation state are trusted local state, not signed external facts.
