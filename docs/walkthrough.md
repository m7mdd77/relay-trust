# Continuous 90-second live walkthrough

[Watch the live capture](https://relay-trust-agent-lab.choggyacc.chatgpt.site/relay-trust-live-walkthrough.mp4). This is one continuous browser MediaRecorder capture of the actual local independent-agent interaction, without microphone audio. It is not a screenshot montage. The two DeepSeek calls finish before recording; signed requests and trust decisions run live during the capture.

| Time | Actual interaction |
| --- | --- |
| 0–12 s | Separate Scout/Steward processes are ready. Scout signs a fresh request using the actual AI proposal; Steward verifies all fifteen checks. |
| 12–25 s | Steward executes one synthetic repair draft and signs its receipt. |
| 25–38 s | Replay returns the same receipt without another effect. |
| 38–51 s | A copied Scout identity signed with Mirror's key is refused: `request_signature`. |
| 51–64 s | Scout signs another fresh request; Steward prepares it. |
| 64–76 s | Owner revokes the grant. |
| 76–90 s | Steward rechecks at execution and blocks the pending task: `revocation`. |

The live demo also exposes the raw transcript, signed requests, issuer credentials, and checks. New authority/evidence use W3C VC 2.0 / eddsa-jcs-2022 proofs and Ed25519 did:key identifiers. The public hosted fixture flows remain interactive; the model-backed process runner is local, with the owner's API key kept out of hosted public access.

To record another run, start the local app with `RELAY_AGENT_ENV` pointing to a private environment file, click Run AI handoff, close the raw transcript disclosure, then click Record this tab. Select only Relay Trust in the browser sharing picker. The timed flow runs automatically and the server saves a WebM file in `RELAY_RECORDING_DIRECTORY` or ignored `.local/recordings`. Review the capture before publication. The earlier captioned-capture MP4 remains an archival artifact.
