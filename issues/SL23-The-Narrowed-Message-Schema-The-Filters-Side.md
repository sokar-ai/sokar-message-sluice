# SL23 — The narrowed message schema, the filter's side

**Status:** soon; blocked by Sokar B108, which decides the schema and which side checks what.

**What must be true.** A message Sokar sends has exactly the shape B14's narrowed schema allows, and
the filter refuses anything else by a rule that names what is wrong.

## Why

Today the filter takes any A2A 1.0 message and refuses only what carries data instead of prose
([`doc/filter.md`](../doc/filter.md#the-envelope)). B14's design narrows that for Sokar's messages:
`metadata` holds `kind`, `to`, `from` and `thread` and nothing else; `kind` is one of `question`,
`answer`, `review-request`, `handover` or `status`, each with its fixed data part; exactly one text
part; `extensions` exactly a Sokar messaging extension URI. The filter is where the envelope is
checked ([`doc/decisions.md`](../doc/decisions.md), *Content detectors sit behind an interface, and
the envelope stays ours*), so the shape is the filter's to enforce, and whom `to` may name stays the
host's.

## The shape

- **A data part is refused today** (`ENVELOPE/DATA_PART_NOT_ALLOWED`, always blocking). A kind's
  fixed data part is let through by its exact shape - its fields, their types, their lengths - and
  nothing else, and every string in it still goes to the detectors, as `metadata` does now.
- **`metadata` outside the four keys, a `kind` outside the five, more than one text part, an
  `extensions` other than the one URI** - each is refused by a rule of its own, named in the answer.
- **The schema is written down, not compiled against**: Sokar and the filter each read it from one
  document, and a test on each side holds them to it.
- A message from before the schema is enforced is refused, not converted: the filter never rewrites
  a message.
- **A person as a sender:** `metadata.from` must be a plain name today, so a Matrix user id
  (`@michi:localhost`) is refused (`ENVELOPE/PEER_NAME_MALFORMED`). A person's message is not
  filtered, so nothing needs it now. If B108's schema names a person by a Matrix id, the rule takes
  it only in a `ROLE_USER` message's `from`, never in `to` and never from an agent, in Matrix's own
  grammar (`@` a lower-case localpart of `a-z 0-9 . _ = - / +`, `:` a host name or IPv4 address, an
  optional port), and the detectors still judge it as text.

## Acceptance

- One fixture per refused shape - an extra `metadata` key, an unknown `kind`, a second text part, a
  foreign extension URI, a data part of the wrong shape - is refused by its own rule, and each test
  is seen to fail with that rule removed.
- One message per kind in the exact shape passes, and its data part's strings still reach the
  detectors.
- The schema document is read by the filter's test, which fails when the document and the rules
  disagree.

## To be checked

- Whether the host checks the same shape before the filter sees it, or leaves it to the filter.
- Where the one schema document lives, and how both sides' tests read it.
