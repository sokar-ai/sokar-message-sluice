# SL08 — Refuse a payload spread over several messages

**Status:** later.

**What must be true.** A payload cut into pieces that are each unremarkable and sent by one task over
several messages is refused once the pieces add up, and the refusal names every message involved.

## Why

This is the third of the three things the filter exists to catch: no single message is refused by
the encoded-data checks or by [SL07](README.md), yet together they are a file. A payload cut into
pieces inside one message is already caught ([`doc/detectors.md`](../doc/detectors.md)); this is the
correlation across messages. How it would be built is
[SL08-Refuse-A-Payload-Spread-Over-Several-Messages_design.md](SL08-Refuse-A-Payload-Spread-Over-Several-Messages_design.md).

## The shape

- Messages are correlated over `contextId`, `taskId` and `metadata.thread` against **what this task
  has already sent**, and caught at the latest when the accumulated size crosses the threshold.
- The corpus lives with the task's mailbox and dies with it. **The accepted gap:** a sender that
  spreads its pieces over two tasks it started itself is seen by neither.
- A persistent index over the corpus is written forward and rebuildable at any time; it is a cache,
  never the source of truth, and holds fragment metadata only, never full text.
- What one check reads is capped, so the cost per message does not grow with the life of the task.
- **The detector is built-in**: correlation cannot be delegated to an external engine invoked once
  per message, as measured in [SL04](README.md).

## Acceptance

- A ZIP or a PEM file, base64-encoded and spread over 2, 5, 20 and 100 messages of one task, is
  refused at the latest when the threshold is crossed.
- **200 real English messages** in one thread produce no correlation finding at all.
- Scenario directories with a pre-filled corpus - with and without sequence markers, with noise
  messages in between, and with messages that have no `contextId` - each have a stated outcome, and
  each test is seen to fail with the detector switched off.
- The index deleted between two runs gives the same verdicts after it is rebuilt.
