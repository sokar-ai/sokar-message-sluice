# SL08 — Refuse a payload spread over several messages, design

How [SL08](README.md) would be built. **Nothing here exists yet**, and none of it has been measured.
Moved here unchanged from the design of the original issue 001, where it was stage C.

## Correlation across the context

An attacker can cut a file or a secret into pieces that are each unremarkable. `sent/` holds
everything accepted so far, and A2A's `contextId`/`taskId` give the grouping for free, which makes
this far more solid than a heuristic over file names.

Grouping is `contextId`, then `taskId`, then `referenceTaskIds`, falling back to a time window when
none is present. Order is arrival order in `sent/`, refined by explicit sequence markers in the
text (`part 3/12`). The fragment index per accepted message holds only fragment metadata - offset,
length, alphabet, entropy, hash - never full text.

| Rule | What it catches |
|---|---|
| `AccumulatedPayloadRule` | the sum of suspicious fragment characters per context: 20 characters are harmless, 40 × 20 are a file. Default threshold 512. |
| `ConsistentAlphabetRule` | fragments across messages of one context using exactly the same alphabet throughout |
| `ReconstructionRule` | the fragments concatenated in the determined order, decoded, and checked for **magic bytes** (`MZ`, `ELF`, `PK`, `%PDF`, `\x89PNG`), a PEM block or a secret pattern - the refusal then names every `messageId` involved |
| `SplitSecretRule` | a secret that only exists once assembled: PEM header in message 7, body in 8-14, footer in 15; or an AWS key id and its secret key in separate messages |
| `SequenceMarkerRule` | explicit continuation markers beside suspicious fragments; also supplies the ordering |
| `NearDuplicateRule` | many messages with nearly identical sentence structure and a changing payload share - a script rather than a dialogue, found with SimHash |
| `BurstRateRule` | a conspicuous cluster in time; `SUSPICIOUS` only, never blocking on its own |

What one check reads is capped (default: the last 500 messages, or 30 days).

## Configuration

| Parameter | Default | Where it comes from |
|---|---|---|
| `accumulatedPayloadThreshold` | 512 | from there on a meaningful file transfer is possible |
| `contextHistoryLimit` / `MaxAge` | 500 messages / 30 days | bounds the work per check, not the corpus |

`--rebuild-index` rebuilds the index from the corpus and exits. The index lives in
`filter/.index/`, is a cache, and is never what a verdict is read from when it disagrees with the
corpus.

## Known limits, and what each would take

| Limit | What would lift it |
|---|---|
| Correlation only over `contextId`/`taskId` or a time window | sender identity from `metadata` as a further grouping key |
| Reconstruction tries few orderings | greedy reconstruction along decodable fragment boundaries |
| The corpus grows for the life of the task | partition it by date; the index stays the working structure |
| Pieces spread over two tasks of the same operator | a corpus shared across tasks - which would make one task's traffic readable to the check of another, so it is an accepted gap |
