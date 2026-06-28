# Muhuri — 60-Second Pitch & Recording Guide

## The script (≈150 wpm lands at ~60s)

Bracketed lines are screen actions, not spoken.

**0:00 — Hook**
*[Demo open on the chain: Alice → Orchestrator → Worker → Bank]*
"Every AI agent today acts with a borrowed password. Watch what that costs — and how we fix it. Alice lets an assistant move **up to fifty dollars** from her account. That permission passes down a chain of agents to her bank."

**0:12 — Legit request**
*[Click "Move $40." Green AUTHORIZED stamp.]*
"A normal request — move forty dollars. The gate checks it against Alice's signed permission and approves. Instantly, and completely offline."

**0:22 — Prompt injection**
*[Click "send Alice's money to Bob." Red BLOCKED.]*
"Now a prompt injection tells the agent to send her money to Bob. Same agent, same credential — blocked. It was never in scope."

**0:33 — Splice attack**
*[Click "Splice in a forged $1,000,000 permission." Muhuri halves fracture red.]*
"An attacker splices in a forged million-dollar permission. The two halves of the credential don't fit — and the gate sees it. Blocked."

**0:44 — Tamper (the kicker)**
*[Open "Show the cryptography," click Tamper.]*
"Don't take my word for it — let's cheat. I rewrite the fifty-dollar limit to nine thousand, right inside the credential. The signature breaks, live on screen. Blocked."

**0:55 — Close**
*[Cut to the chain, full view.]*
"Every action, tied by math to a real person's permission. Two hundred fifty bytes, no server to phone home. That's Muhuri."

## Delivery notes

- Let each red stamp sit a full beat before talking over it. The silence sells it.
- The tamper moment is the strongest. If you only have 30 seconds: chain → legit → splice → tamper.
- The closing line is for the non-technical buyer. Slow down and land it.

## Recording shot list (screen capture is the spine)

The persuasive force is that the cryptography is *real and live*. Record an actual
screen capture of `muhuri-demo.html`; do not substitute a generated video for the
demo itself.

1. Full-window shot of the chain, 2s hold.
2. Click **Move $40** → hold on green AUTHORIZED + the check trace.
3. Click **send Alice's money to Bob** → hold on red BLOCKED + reason.
4. Click **Splice in a forged $1,000,000 permission** → hold on the fractured muhuri halves.
5. Expand **Show the cryptography** → click **Tamper & re-test** → hold on the broken signature.
6. Click **Restore**, end on the full chain + the footer line.

Optional cinematic bookend (only if you want one): a 5-second cold-open title card
("What if your AI agent could be stopped — by math?") generated in a video tool,
spliced *before* the screen capture. Keep it short; the live demo must carry the pitch.
