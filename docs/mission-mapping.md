# Mission mapping and scope

Official mission: [The Agent That Earns Trust](https://build.doo.ooo/challenges/agent-earns-trust), rendered checklist rechecked October 12, 2026 (Asia/Riyadh). Its brief permits a live demo or walkthrough; its submission checklist explicitly requires a public repository and live demo. The release plan follows the stricter checklist.

| Mission requirement | Concrete implementation / evidence | Status |
| --- | --- | --- |
| Profiles with action history | Scout and Steward key-bound profiles; three lab-signed seeded inspections; Steward-signed executions | Local, synthetic |
| Credentials, attestations, authority | Separate pinned owner and evidence lab; actual Ed25519 signed envelopes; subject/audience, validity, capabilities, resource, quota | Implemented |
| Grant, scope, revoke trust | Renew 3-ticket grant; narrow to 1; revoke; every replacement revokes previous grant | Implemented |
| Counterparty-based accept/refuse | Scout sends signed request to distinct Steward identity; fifteen visible checks determine decision | Implemented |
| Architecture snapshot | `architecture.md` plus vector `architecture.svg` | Supplied |
| Malicious/spoofed failure test | Wrong requester signing key; altered quota; scope, audience, expiry and revocation failures | Tested |
| 90-second walkthrough | Captioned MP4 from verified UI captures; labeled capture-based, no audio | Supplied |
| Two-year thesis ≤300 words | `thesis.md` | Supplied |
| Public repository, clean clone runs | https://github.com/m7mdd77/relay-trust ; no dependencies/API keys; public clone checked before submission | Public source |
| Live demo link | Local review at 3250 plus https://relay-trust-agent-lab.choggyacc.chatgpt.site | Public companion deployed and tested |
| Notes / AI tools / decisions / limits | README, architecture, release checklist | Supplied |
| Existing standard bonus | Native Ed25519 cryptography; versioned local envelope and key-fingerprint URNs | No VC/DID/JCS compliance claimed |
| Cross-agent bonus | Two separately keyed named actors and signed handoff; synthetic simulation in one server | Demonstrated locally; no process isolation |

No external credential standard is partially marketed as complete. Real signing demonstrates authorship and payload integrity, not real-world organization identity or the truth of an issuer's claim. Issuer selection remains an explicit local trust assumption.
