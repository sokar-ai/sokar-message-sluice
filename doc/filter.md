# The filter

`sokar-message-sluice-filter` reads the messages in a task's mailbox, refuses the ones that carry
data instead of prose, and answers every message with what it found. It has no queue, no network and
no knowledge of any transport: it reads a file, decides, answers and moves the file.

What it looks for in the text is in [`detectors.md`](detectors.md). This page is the frame around
that: the directories, the envelope, the verdict, the answers and the command line.

## The directories

Sokar lays out the mailbox and gives the filter its paths. The filter creates no directory and does
not start when one is missing:

```
<task state>/mail/
├─ incoming/            messages to check, each with <name>.sig beside it
├─ filter/
│   ├─ accepted/        what passed, with its signature; Sokar sends it on from here
│   ├─ feedback/        one answer per message
│   ├─ rejected/        the refused originals, in clear text - 0700
│   └─ error/           files that are not a message, with <name>.error.txt - 0700
└─ sent/                what was sent before, where a repeated message id is looked up
```

`--mail <dir>` names them all at once. **Every one must be a real directory, not a link**, and the
filter remembers what each one is - its device and inode - and checks it again before every pass: a
directory replaced since the start, or reached through a parent that was, stops the pass before
anything is read or filed. **`rejected/` and `error/` must also be `0700`**, owned by the filter's
user: they hold what it refused, secrets included.

**What is in `accepted/` counts as checked and is never checked again**, so nothing but the filter may
write there.

## Per message

- Only `*.json` files are read; a file still being written is left for the next pass.
- Only a plain file is read: a link, a second hard link or a special file is refused unread. The same
  holds where the filter looks up message ids already seen: there, anything but a plain file of at most
  a message's size counts for nothing.
- **The file name** is 1 to 128 letters, digits, `.`, `_` and `-`, starts with a letter or digit and
  ends in `.json`. It travels with the message, so the detectors check it like a text.
- **The signature** beside it must have exactly the shape Sokar writes (an OpenSSH Ed25519 signature,
  at most 1 KiB), so nothing can ride along in it. The filter checks the shape; Sokar checks the
  signature itself.
- The JSON is parsed strictly, and **only strict UTF-8** is read.

**The filter never changes a message.** What it files is exactly the bytes it checked, because those
are the bytes Sokar signs and sends. **Every message gets an answer**, written before the message is
filed, so a crash leads at worst to a second answer, never to a message dropped in silence.

## The envelope

A message is **A2A 1.0** in its JSON form. A2A 0.3 is refused, never converted.

| What | Rule | Severity |
|---|---|---|
| a part with `raw` | `ENVELOPE/RAW_PART_NOT_ALLOWED` | `BLOCKING` |
| a part with `url` | `ENVELOPE/URL_PART_NOT_ALLOWED` | `BLOCKING`, or `SUSPICIOUS` by `check.urlPartSeverity` |
| a part with `data` | `ENVELOPE/DATA_PART_NOT_ALLOWED` | `BLOCKING` |
| a part with two content fields | `ENVELOPE/AMBIGUOUS_PART` | `BLOCKING` |
| a part with none | `ENVELOPE/EMPTY_PART` | `SUSPICIOUS` |
| a role that is not allowed | `ENVELOPE/UNEXPECTED_ROLE` | `BLOCKING` |
| `filename` on a text part | `ENVELOPE/FILENAME_ON_TEXT_PART` | `SUSPICIOUS`, `BLOCKING` for a binary extension |
| a `mediaType` other than `text/plain` | `ENVELOPE/UNEXPECTED_MEDIA_TYPE` | `SUSPICIOUS`, `BLOCKING` for octet-stream, zip or JSON |
| an id too long or not `[A-Za-z0-9._:-]` | `ENVELOPE/ID_MALFORMED` | `BLOCKING` |
| `metadata.to` or `.from` not a plain name (letters, digits, `.` `_` `-` `@`) | `ENVELOPE/PEER_NAME_MALFORMED` | `BLOCKING` |
| metadata too deep or too large | `ENVELOPE/METADATA_TOO_DEEP`, `…_TOO_LARGE` | `BLOCKING` |
| too many parts, a text too long | `ENVELOPE/TOO_MANY_PARTS`, `…/TEXT_TOO_LONG` | `BLOCKING` |
| too many `referenceTaskIds` | `ENVELOPE/TOO_MANY_REFERENCES` | `BLOCKING` |
| an extension that is not a URI | `ENVELOPE/EXTENSION_MALFORMED` | `SUSPICIOUS` |
| a field A2A 1.0 does not have | `ENVELOPE/UNKNOWN_FIELD` | `SUSPICIOUS` |
| a message id seen before | `ENVELOPE/DUPLICATE_MESSAGE_ID` | `BLOCKING` |

**Every string goes to the detectors**, not only the text parts: file names, media types, every key
and value of `metadata`, extensions, unknown fields and the ids. A UUID passes as an id; a long hex
string does not, whatever field it is in.

**Roles:** a message may be the agent's (`ROLE_AGENT`) or a person's (`ROLE_USER`); both are checked
alike. That a person really wrote it is Sokar's to check, not the filter's.

**A file that is not a message** - empty, not UTF-8, not JSON, not A2A 1.0 - goes to `error/` and still
gets an answer, so a broken file is never a way to make a message vanish. What `error/` keeps is the
bytes that were read, never the file they came from; a file changed since stays for the next pass. A
link or a special file is not read, so it is moved as it is, a link as a link, never followed.

## The verdict

Findings are `INFO`, `SUSPICIOUS` or `BLOCKING`, and no detector decides on its own:

- **`THRESHOLD`** (the default): one `BLOCKING` finding refuses, and so do `SUSPICIOUS` findings from
  two different rules (`decision.suspiciousCombineCount`).
- **`SCORE`**: findings are weighed (`decision.weight.<rule>`), and the sum refuses from
  `decision.scoreThreshold`.
- **Always refused**, whatever is configured: a `BLOCKING` envelope finding, a detector that failed,
  and a finding that could not be masked.
- Detector rules can be switched off (`decision.disabledRules`) and their categories re-graded
  (`decision.severity.<category>`).

**Reporting or blocking.** With `--blocking` the verdict above refuses. Without it the filter only
reports: only the envelope refuses, and each answer says what blocking would have refused
(`wouldReject: true`). **Sokar runs it blocking**, for what a task sends and for what arrives from a
peer it does not vouch for. A project may set its outgoing check to report only, on purpose
(`mail.outgoing_filter: reporting`); Sokar then holds every message the filter would have refused,
and every message whose answer is missing, until a person releases it, and shows the verdict there.

## The answers

Every message gets one answer in `feedback/`: a **receipt** when it passed (`receiptOnApproval=false`
switches these off, but never for a message blocking would have refused: its receipt is how the host
learns it was flagged), a **rejection** when it did not. An answer is itself an A2A 1.0 message:

- a text part listing every finding: severity, rule, where, and the reason in English;
- a `data` part with the decision, the mode, the deciding rule and every finding, for a program to
  read.

**Nothing a rule matched appears in clear text** - not in an answer, a log line or a file name.
`redaction.mode` is `PARTIAL` (the first four characters, then stars), `FULL` (`[REDACTED:<category>]`)
or `HASH`. A file kept in `rejected/` or `error/` loses its name when the name itself was suspicious.
A key of `metadata` above a finding, and a field the envelope reports, is named by its position
(`metadata.#0`, `#3`), never in clear: a name is text its writer chose.

## The command line

```
sokar-message-sluice-filter --mail <dir> [--blocking] [--watch] [--config <file>] [--<key> <value> ...]
sokar-message-sluice-filter --dry-run --file <message> [--blocking]   # checks one file, moves nothing
sokar-message-sluice-filter --calibrate [--dir <messages>]            # prints a configuration
sokar-message-sluice-filter --agent-card --mail <dir>                 # prints its A2A agent card
```

**Exit codes:** 0 everything passed, 1 something was refused, 2 a technical error or a configuration
that cannot be used. One instance runs per mailbox; a second exits with 2. `--watch` keeps running
and checks whenever a file arrives. **Whatever the exit code, `accepted/` holds only what was checked
and passed:** a file that met a technical error is not judged, nothing of it is filed, and it stays in
`incoming/` for the next pass. Exit 2 puts nothing in `accepted/` in doubt.

**Configuration**, later beating earlier: the defaults, `--config <file>` (a properties file), and
`--<key> <value>`. **The environment is never read**, so nothing a shell exported can switch a rule
off. **An unknown key stops the start**, and the configuration in force is logged at start, each key
with where its value came from. The detectors' keys are in [`detectors.md`](detectors.md).

## What the operator has to guarantee

1. **The agent has no other way out.** A filter the agent can send around checks only part of what
   leaves.
2. **Nothing but the filter writes into `accepted/`**, and nothing but Sokar's sending takes from it.

## Known limits

| Limit | What would lift it |
|---|---|
| A secret described in words (*"the dog's name plus 77"*) | only a model, which this filter refuses to be |
| Information hidden in word choice | out of scope |
| A2A 1.0 only | a lossless conversion in front |
| Files only, no A2A protocol operation | a transport adapter; the checks would stay the same |
| A repeated message id is found only among this mailbox's files | Sokar's own check, by id |
