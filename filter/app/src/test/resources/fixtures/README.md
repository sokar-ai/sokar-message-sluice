# Fixtures

One message per file, for running the filter against something known - in this repository's tests
and on Sokar's host side. `FixturesTest` runs every one of them in both modes, so a file here stays
true as the code changes.

The name says what happens to it:

| Prefix | Reporting mode (the default) | Blocking mode (`--blocking`) |
|---|---|---|
| `accept-` | accepted | accepted |
| `detector-` | accepted, and the receipt names the finding | refused by a detector |
| `envelope-` | refused | refused |
| `unprocessable-` | moved to `error/` and answered | moved to `error/` and answered |

Every message carries a unique `messageId`, so the whole set can go through one mailbox in one pass.
The payload in the `detector-long-token` files is 64 characters of base64 and not a real secret.
Three files exercise the Unicode normalization, so a native build runs it too: fullwidth letters
(folded by NFKC, no finding), a Cyrillic look-alike inside a Latin word (`UNICODE/MIXED_SCRIPT`,
suspicious, so accepted in both modes) and twelve zero-width spaces between words
(`UNICODE/INVISIBLE_CHARACTER`, blocking from eight on - and, once they are removed, one long token). None of these
files is signed: sign them on the host as a message from a task would be.
