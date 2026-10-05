# SL04 — An external content detector, measured before it is adopted

**Status:** later.

**What must be true.** Somebody else's detector catalog can sit behind the filter's detector
interface and is adopted only once a measurement shows it catches something the built-in detectors
do not, without weakening anything the frame promises.

## Why

The envelope checks, the decision model, the answer format and the directory contract are this
repository's own work and are what Sokar leans on. The catalog behind the content checks is not
special: credential patterns age as providers invent new prefixes, and de-obfuscation is a
specialist's game. The interface and the built-in detectors are described in
[`doc/filter.md`](../doc/filter.md) and [`doc/detectors.md`](../doc/detectors.md), the reasoning in
[`doc/decisions.md`](../doc/decisions.md).

## The shape

- **An external implementation is a separate module**, invoked as a subprocess, pinned by version
  and by digest, and every receipt records what it is and which version answered, so a verdict can
  still be explained a year later.
- **It fails closed** like every detector: absent, timed out, crashed or answering outside its
  contract means the message is not accepted.
- **Its findings pass through the frame's redaction** like any other detector's, and it can neither
  release a message nor turn a report into a block.
- **Only single-message detectors are pluggable.** Correlation across messages stays built-in
  ([SL08](README.md)): measured with the surveyed scanner on a VM, it reassembles a payload split
  over two requests only while one long-running process holds the session, and a process per
  message - how this filter invokes a detector - starts empty every time.

      whole secret, one request                         deny  (the pattern works)
      halves, shared session, one process               allow, then deny as a cross-request fragment
      halves, no session                                allow, allow
      halves, shared session, the server restarted      allow, allow - the first half is forgotten

- **A catalog in another language is allowed**: reusing a maintained catalog beats keeping our own.
  It is pinned, in the bill of materials, and named in `AGENTS.md` with its reason once adopted.

## Acceptance

- One external implementation behind the interface is **measured** on this repository's fixtures:
  false positives against the clean English corpus, catches against the negative samples per
  category, and the cost per message.
- An implementation that is absent, hangs past its timeout, exits non-zero or prints something
  unparseable **must** each be seen to stop the message from being accepted, asserted on what
  reaches `accepted/`, not on a log line.
- The same fixture through the built-in and the external implementation **must** give findings of
  the same shape, differing only in rule ids and what was caught.
