# Standards and independently running AI agents

New authority and evidence use W3C VC Data Model 2.0 documents, secured with Data Integrity `eddsa-jcs-2022`. Issuer keys use the Ed25519 `did:key` Multikey encoding. Verification checks the proof, its purpose, the pinned issuer key, exact application claims, and the original policy constraints. A signed profile marker prevents stripping a VC to downgrade a new grant. Earlier persisted lab credentials remain readable; start fresh or renew to obtain new credentials.

The verifier passes the published W3C B.3 signature vector and both published SHA-256 canonicalization hashes. The implementation supports one proof and Ed25519 keys; it does not claim support for every DID method, cryptosuite, proof chain, selective disclosure, or remote issuer governance.

Sources: [W3C EdDSA](https://www.w3.org/TR/vc-di-eddsa/), [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/), [did:key method](https://w3c-ccg.github.io/did-key-spec/).

The local live demo starts Scout and Steward as separate Node processes. Each process creates and retains its own signing key in ignored `.local/agent-processes/<role>/identity.json`. The controller receives public identities and signed messages only. Owner and lab remain local synthetic pinned issuers; operating-system account isolation, remote deployment of agents, and hardware custody are outside scope.

Both agents call `deepseek-v4-flash` through AgentRouter using the actual installed Claude Code client, with tools/MCP/session persistence disabled. Model proposals are validated, and deterministic policy controls effects. Each process allows one model call, capped by the supported client at $0.02. Provider errors fail without fallback or application retries. Prepared requests can explicitly reuse the original AI proposal for the revocation demonstration.

Run with an existing private environment file:

```powershell
$env:RELAY_AGENT_ENV='C:/path/to/private/.env'
npm start
```

Required names: `AGENTROUTER_API_KEY`, `AGENTROUTER_BASE_URL` (`https://agentrouter.org` or `/v1`), `AGENTROUTER_TRANSPORT=claude-code`, and `CLAUDE_CODE_PATH`. The selected model is fixed to `deepseek-v4-flash`. No key is copied into this repository.

In the live section: Run AI handoff → Execute → Replay → Spoof test → Prepare fresh request → Revoke grant → Execute. Actual verification evidence is in `independent-ai-agents.json`. Effects remain synthetic repair drafts.

The hosted Worker provides interactive trust fixtures, standard credentials, and the public verified AI transcript. The live independent processes run locally because Cloudflare Workers cannot spawn this installed desktop client. The hosted demo does not expose the owner's model key or paid inference endpoint.

For a continuous walkthrough, choose Record this tab, select only the Relay Trust browser tab in the browser sharing picker, and let the timed demonstration run for 90 seconds. The app records an actual continuous WebM capture without microphone audio. The recording is saved by the local server in its configured recording directory. The reviewed live recording replaces the earlier captioned-capture walkthrough as the current submission video.
