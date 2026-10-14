# Relay Trust hosted companion

The public Vinext/Cloudflare Workers/D1 companion provides isolated interactive trust fixtures, W3C VC 2.0 / eddsa-jcs-2022 credentials, Ed25519 did:key identifiers, the verified independent-AI transcript, and the continuous 90-second live walkthrough.

Each visitor receives a synthetic sandbox. Five key pairs stay in private server-side D1 state; the public export omits private keys and mutation tokens. Cookie, same-origin, revision/deadline, quota, and session-capacity gates remain in place. Keys are not protected from hosting administrators, and this is not a real-world owner-authentication service.

Scout and Steward's actual DeepSeek runtime is in the repository root: separate local Node processes and separate signing keys, using the existing private AgentRouter configuration through the supported installed Claude Code client. Workers cannot launch that desktop client, so the hosted page exposes the verified evidence and recording without exposing the owner's paid inference endpoint.

Use Node 24. Install lockfile dependencies with `npm run install:ci`, run `node --test test/*.test.js`, then `npm run build`. Follow the Sites workflow for D1 migration, source synchronization, packaging, and publication. Preserve the existing project ID in the deployment checkout; the public GitHub copy removes it.

The hosted suite passes 13 tests, including W3C's published B.3 proof/hash vector. The local suite passes 40 tests. See `STANDARDS.md` for the supported credential profile, live-agent setup, and limits.

OpenAI Codex assisted design, implementation, tests, documentation, and release. Agents, pinned issuers, inspection history, and repair effects remain explicitly synthetic; signatures and model calls are real.
