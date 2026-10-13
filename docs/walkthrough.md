# 90-second walkthrough

Target duration: 90 seconds. Read at roughly 150–160 words/minute with short pauses. This is a script for an actual browser recording. Screenshots are supplied; no live screencast or Loom has been recorded.

| Time | Screen action | Narration |
| --- | --- | --- |
| 0–10 s | Show Scout and Patch Steward profiles. | “This is Relay Trust. Scout requests a repair ticket; Patch Steward decides whether to accept. These are synthetic actors with distinct real Ed25519 keys.” |
| 10–22 s | Show owner grant, 3 inspections, self-reported 999 jobs. | “Scout claims 999 jobs. We ignore that number. The Evidence Lab signs three synthetic inspection receipts. The owner separately grants ticket creation for SITE-17, with a quota and expiry.” |
| 22–36 s | Valid repair ticket → Check → Execute. | “The requester signs the handoff, including hashes of the exact credentials. Steward checks identities, issuers, audiences, scope, evidence, and revocation. At execution it checks again, then signs a receipt.” |
| 36–44 s | Repeat execution. | “Repeating this task returns the same receipt. The unique request ID prevents duplicate effects.” |
| 44–54 s | Out of scope → Check. | “Now a real Scout asks to delete the site. Its signature is authentic, but deletion is outside the delegation. Steward refuses and explains which boundary failed.” |
| 54–66 s | Spoofed Scout → Check; Tampered grant → Check. | “Mirror copies Scout's identity but signs with the wrong key. Verification catches it. Inflating a signed grant's quota also breaks the owner's signature.” |
| 66–82 s | Renew → Valid request → Check → Revoke → Execute. | “An initial approval is provisional. Here we revoke trust after approval. The live execution check refuses the task, and the ticket count does not increase.” |
| 82–90 s | Show public signature verifier and architecture. | “Authority is evidence plus policy, not a reputation score. Public signatures are independently verifiable. This local format is not a claim of VC or DID compliance.” |

Preparation: renew a grant before recording, keep the authority and handoff panels in view, close raw JSON details, and use a desktop viewport. Do not display `.local/`, browser network-token headers, or any unrelated account. The recording only needs public synthetic profiles and signed envelopes. If the quota is consumed, renew before the next allowed task; renewal intentionally invalidates old prepared tasks.

For a second demonstration, narrow to one ticket, execute one new handoff, and show the next request fails quota. Expired request and wrong audience fixtures are also available.
