# SL24 — A code comment, the filter's side

**Status:** soon; blocked by Sokar B166, which defines the comment model and what the host checks.

**What must be true.** A comment on code - a message of the kind `comment` - passes the filter only in
its exact shape: an anchor that names a place, prose that is prose, and at most a suggestion that is
a few lines of code for exactly that place. Anything else in it is refused by a rule that names what
is wrong, in both directions: what a task sends to a review or a forge, and what arrives from a forge.

## Why

A comment is a message, so it passes the controls a message passes. The filter refuses data dressed
as prose ([`doc/filter.md`](../doc/filter.md#the-envelope)); a comment brings two things it has no
rule for today:

- **The anchor names a commit by its id.** A 40-digit hex string is exactly what the detectors refuse
  in any field. Judged as text, every comment would be refused; let through unchecked, the anchor is
  a field an agent can fill with anything.
- **A suggestion is code, not prose.** The detectors are measured against English prose
  (`EncodedPayloadRatesTest`); code has other letter, symbol and token shapes, and would be refused
  for being code. Let through unjudged, a suggestion would be a field for a payload of any size.

## The shape

- **The anchor is checked by its shape, field by field, and is not text:** repository a peer name,
  commit 40 or 64 lower-case hex digits, file a relative path (no `..`, no leading `/`, bounded
  length, printable characters only), lines one number or a range within a bound, side `old` or `new`.
  Whether that commit, file and line exist is the host's to check, as B166 decides; the filter only
  makes sure the anchor can hold nothing but a place.
- **The text is prose**, judged by the detectors as every text part is, with today's length limit.
- **The suggestion is a field of its own, optional:** at most as many lines as the anchor spans plus a
  small allowance, each line bounded, the whole bounded. It goes to the detectors that find encoded
  data (long tokens, signatures, window entropy), with thresholds measured against code rather than
  prose; the detectors that judge whether text reads like a language do not see it. A suggestion
  without an anchor, or longer than its bounds, is refused by its own rule.
- **Thread fields** (thread id, reply-to) follow today's id rule; the state is `open` or `resolved`.
- **The origin is not the sender's to state.** A comment that names its own origin is refused; the
  host adds who it came from after the filter.
- **The same rules both ways.** An inbound comment from a forge is held to the same shape and the same
  detectors before it is delivered into a task; which forge accounts are delivered at all is the
  host's list, not the filter's.
- **One rule per refusal**, named in the answer, as for every envelope rule.

## Acceptance

- One fixture per refused shape - a malformed commit id, a path with `..`, a line range beyond its
  bound, a side other than the two, an origin field, a suggestion without an anchor, a suggestion too
  long, a base64 blob inside a suggestion - each refused by its own rule, each test seen to fail with
  that rule removed.
- A comment in the exact shape passes, with and without a suggestion, inbound and outbound.
- **A code corpus** beside the English one: real code lines from this repository's own sources, frozen
  as a test resource, on which the suggestion's detectors measure their false positives, and 32
  characters of encoded payload per encoding on which they measure their misses, as for prose.

## To be checked

- How the comment kind sits beside SL23's five kinds: a sixth kind of the narrowed schema, or a part
  of its own.
- The suggestion's bounds (lines beyond the anchor, line length, total) - taken from B166 once it says
  them, or measured here on real review suggestions.
- Whether the host already refuses an anchor that does not exist before the filter sees the comment.
