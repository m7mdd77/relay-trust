# Release verification

Public companion: https://relay-trust-agent-lab.choggyacc.chatgpt.site . Public repository: https://github.com/m7mdd77/relay-trust . The source includes the dependency-free local build and full hosted companion, with the author Site ID removed. The 90-second captioned video uses verified UI captures; it has no audio and is not a continuous live screencast.

1. Review source, thesis, synthetic labels, and evidence. The source remains unlicensed, with no license grant asserted on the author's behalf.
2. Publish the reviewed source only. Exclude `.local/`, SQLite/WAL/SHM files, logs, mutation tokens, keys, environment files, and unrelated projects. Check a fresh public default-branch clone before mission submission.
3. Hosting design implemented: HTTPS, isolated per-visitor D1 sessions, high-entropy HttpOnly cookies and mutation tokens, same-origin writes, server-side key storage, live CAS rechecks, and bounded synthetic state. Anonymous visitors act as simulated owners only within their own sandbox. The local Node server remains loopback-bound.
4. ChatGPT Sites deployment completed and the live trust flows were verified. No paid model integration or separately purchased hosting service was used. Future changes to real authority or integrations require their own review.
5. Include the reviewed [90-second captioned video](relay-trust-walkthrough.mp4) and [WebVTT captions](relay-trust-walkthrough.vtt).
6. Check the live mission form, public repository, demo and video URLs, AI-tool notes, and thesis before the user-authorized submission. Keep its external receipt separately because this source commit precedes submission.

Draft submission summary: “Relay Trust is a local repair-agent laboratory with distinct Ed25519 identities, issuer-attested synthetic inspection history, revocable scoped delegation, and an explainable receiving-agent policy. Requests bind exact credentials; live execution rechecks authority inside an atomic idempotent effect transaction. Concrete spoofing and tampering fixtures show cryptographic refusal.”

Verification baseline: 34 local tests, 8 hosted API tests, separate published-runtime checks, and desktop/mobile browser checks. No submission is claimed by this source commit.
