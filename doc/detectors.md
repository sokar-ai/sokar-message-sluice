# What the filter looks for in the text

After the envelope ([`filter.md`](filter.md)), every text and every string in a message goes through
the **detectors**. The ones built catch **encoded data**. Credentials and personal data, and a payload
spread over several messages, are not built yet.

A detector only reports findings; the verdict is decided on all of them together
([`filter.md`](filter.md#the-verdict)), and every excerpt is masked before it goes anywhere.

## Before the detectors

Every text is normalized once, and every finding still points into the original text:

- **Unicode NFKC**, and line endings made one.
- **Invisible characters are removed and reported** (`UNICODE/INVISIBLE_CHARACTER`): zero-width
  characters, bidi controls, tag characters, the soft hyphen and variation selectors. A few are
  `SUSPICIOUS`, eight or more in one text `BLOCKING`. The joiners and selectors that make up an
  ordinary emoji are not reported.
- **Look-alike letters are read as Latin** in a word that mixes Latin with Cyrillic or Greek, and the
  word is reported (`UNICODE/MIXED_SCRIPT`, `SUSPICIOUS`): *"раssword"* with a Cyrillic `р` and `а` is
  read as *"password"*.

For the statistical checks, shapes that are known to be harmless are taken out first: URLs (but not
their query, and not an over-long path or host label), up to four UUIDs, up to eight short commit
hashes, IP addresses, timestamps, numbers, dates, amounts and short acronyms. More UUIDs or hashes than
that are treated as the payload they then are.

## The rules

| Detector | Rule | Severity | What it catches |
|---|---|---|---|
| `builtin/long-token@1` | `ENCODING/LONG_TOKEN` | `BLOCKING` | more than 35 characters without a space or a separator |
| `builtin/token-shape@1` | `ENCODING/DIGIT_UPPER_TOKEN` | `SUSPICIOUS` | a word of more than 8 characters, over half digits and capitals |
| | `ENCODING/VOWELLESS_TOKEN` | `SUSPICIOUS` | a word of more than 12 characters with under 15 % vowels |
| | `ENCODING/SYMBOL_HEAVY_TOKEN` | `SUSPICIOUS` | over 20 % of `+ / = % _ -` in a mostly alphanumeric word |
| | `ENCODING/PUNCTUATION_HEAVY_TOKEN` | `SUSPICIOUS` | over 20 % of other punctuation |
| `builtin/entropy@1` | `ENCODING/WINDOW_ENTROPY` | `BLOCKING` | a 64-character stretch above 4.5 bits per character |
| `builtin/english-distribution@1` | `ENCODING/LETTER_DISTRIBUTION` | `SUSPICIOUS` | 200 characters or more whose letters are not distributed like English |
| | `ENCODING/WHITESPACE_SHARE` | `SUSPICIOUS` | the same, with under 8 % whitespace |
| `builtin/encoding-signature@1` | `ENCODING/BASE64`, `BASE64URL`, `BASE58`, `BASE32`, `BASE85`, `HEX`, `URL_ENCODING`, `QUOTED_PRINTABLE`, `UUENCODE`, `BINARY_STRING`, `PEM`, `DATA_URI` | `BLOCKING` | the named encoding, from 32 characters on |

**Two different `SUSPICIOUS` rules in one message refuse it**; one rule firing many times counts once.

**Base64 is told from an identifier by how it switches case**: words keep a run of lower-case letters
after a capital, random letters switch every one or two characters. Words joined by dashes or
underscores are a name, not base64url.

**A full hash in hex is refused**, because 32 hex characters of a payload and an MD5 look the same.
Name a commit by its short form.

**A payload cut into pieces is the payload.** Pieces of one alphabet that stand in a row with only
whitespace between them - spaces, line breaks, tabs, or `\n` written out - are joined and judged as
one run, under the encoding's own rule. Words, numbers and names joined by dashes or slashes at
either end of such a row are the sentence around it and are left out; a row that is more than two
thirds words is prose and is never joined. Measured on 13342 paragraphs agents wrote to each other:
no more than three short commit hashes ever stood in a row, and two paragraphs of the 13342 - a
table and a command line - are refused by this alone.

## Configuration

Every threshold is a key, `detector.<name>.<parameter>`, and every detector can be switched off with
`detector.<name>.enabled=false`. An unknown key stops the start.

| Key | Default | Where it comes from |
|---|---|---|
| `detector.longToken.maxTokenLength` | 35 | the longest common English word is about 30 characters |
| `detector.tokenShape.maxDigitUpperShare` | 0.5 | the design |
| `detector.tokenShape.minVowelShare` | 0.15 | the design |
| `detector.tokenShape.maxSymbolShare` | 0.2 | the design |
| `detector.entropy.threshold` | 4.5 | measured, below |
| `detector.entropy.windowSize` / `step` / `minLength` | 64 / 16 / 64 | measured: 64-character windows tell base64 from English, 128 do not |
| `detector.distribution.minLength` | 200 | shorter is noise |
| `detector.distribution.maxChiSquarePerLetter` | 2.0 | measured, below |
| `detector.distribution.minWhitespaceShare` | 0.08 | measured, below |
| `detector.signature.minLength` | 32 | the shortest payload that must not pass |

## Calibration

```
sokar-message-sluice-filter --calibrate --dir <task state>/mail/sent > calibrated.properties
```

It reads a directory of messages, moves nothing, and prints a properties file for `--config`: how many
messages blocking would refuse and by which rule, and for each statistical measure a suggested value
between that traffic and random base64. Where the two overlap, it keeps the current value and says so.
**The defaults block from the start**; calibration shows how a mailbox's own traffic fares, when it is
refused more often than it should be.

## How well it works

With the defaults:

- **English that must pass:** every paragraph of this repository's documentation, none refused (a test
  keeps it so), and 2869 paragraphs agents wrote to each other, with paths, hashes and command lines:
  one refused.
- **Encodings that must not pass:** 500 random samples of each encoding at 32, 48 and 64 characters,
  each inside a sentence: under 1 % missed for every one (a test keeps it so). The same payloads cut into
  groups of 2 to 24 characters by spaces, line breaks, tabs or written-out escapes: under 1 % missed for
  base64, base32, base58 and hex (a test keeps it so).
- **The thresholds:** English windows reach at most 4.56 bits per character, base64 has a median of
  4.75; English letters reach at most 1.64 chi-squared per letter, base64 at least 2.69; English has at
  least 8.7 % whitespace, base64 none.

## What these detectors cannot see

- **Fewer than 32 characters of an encoding** that nothing else gives away.
- **A payload in a URL path** of short segments, up to 256 characters; the query is checked.
- **Up to four UUIDs and eight short hashes per text**, which pass as ids: about 64 bytes per message.
- **Anything that is not English prose**, which the letter test may refuse.
- **Code quoted at length** may be refused: long identifiers, shell commands, fingerprints.
  Calibration shows how often that happens in a mailbox's own traffic.
