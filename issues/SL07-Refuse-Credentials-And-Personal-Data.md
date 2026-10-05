# SL07 — Refuse credentials and personal data

**Status:** soon.

**What must be true.** A message carrying a key, an API token, a private key, a connection string,
or personal or financial data is refused, while ordinary English that merely looks like one is not.

## Why

This is the second of the three things the filter exists to catch. A credential looks statistically
like ordinary text, so the encoded-data checks ([`doc/detectors.md`](../doc/detectors.md)) do not
find it; a targeted catalog of **pattern, surrounding context and checksum** does, and the checksum
is what separates a finding from noise. How it would be built is
[SL07-Refuse-Credentials-And-Personal-Data_design.md](SL07-Refuse-Credentials-And-Personal-Data_design.md).

## The shape

- Every text part, and every string in `metadata`, is checked against the catalog through the
  detector interface and nothing else. **It always sees the original text**, so a token inside a
  URL's query string cannot slip through the masking the encoded-data checks use.
- Every category can be switched on or off and re-graded between `INFO`, `SUSPICIOUS` and
  `BLOCKING`, with the defaults in the design.
- Known test values - `4111 1111 1111 1111`, `AKIAIOSFODNN7EXAMPLE` - are in an extensible list and
  count as `INFO` only.
- A context word alone can carry a finding: *"my password is hunter2"*.

## Acceptance

- **One sample per category** inside a natural English sentence (*"Sure, the key is AKIA…"*) is
  refused in blocking mode, and a credential in `metadata` rather than a text part is refused too.
- Invalid credit card numbers, IBANs and JWT headers **must not** cause a refusal.
- The rejection for every sample **must not** contain the matched value in clear text.
- False positives stay under 1 % against the clean English the encoded-data checks are measured on.
- Each sample's test is seen to fail with its category switched off.
