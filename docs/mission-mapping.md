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
| 90-second walkthrough | Continuous 90-second MediaRecorder capture of the actual independent-agent interaction, no audio | Supplied |
| Two-year thesis ≤300 words | `thesis.md` | Supplied |
| Public repository, clean clone runs | https://github.com/m7mdd77/relay-trust ; no dependencies/API keys; public clone checked before submission | Public source |
| Live demo link | Local review at 3250 plus https://relay-trust-agent-lab.choggyacc.chatgpt.site | Public companion deployed and tested |
| Notes / AI tools / decisions / limits | README, architecture, release checklist | Supplied |
| Existing standard bonus | Ed25519 did:key, VC 2.0, eddsa-jcs-2022; published W3C vector verified | Supported standards profile |
| Cross-agent bonus | Separate Scout and Steward Node processes and signing keys; actual DeepSeek calls and signed handoff | Tested locally; same OS account |

No external credential standard is partially marketed as complete. Real signing demonstrates authorship and payload integrity, not real-world organization identity or the truth of an issuer's claim. Issuer selection remains an explicit local trust assumption.
