# Issues

What is open in this repository, ordered by what to do next rather than by number. The number is
identity, not sequence.

**Grouped by the MVP**: one person, one machine, one agent - Sokar installed, work started, the
agent working safely, its result reviewed and pushed, for someone who has never used Sokar. What
serves that is **now**, what follows right after it **soon**, the rest **later**. A defect of the
filter that a person meets on that path is an issue in Now.

## Now

Nothing open: the filter as it is, kept working.

## Soon

| # | Status | Blocked by | What it covers | Open questions |
|---|---|---|---|---|
| [SL07](SL07-Refuse-Credentials-And-Personal-Data.md) | open | — | Credentials and personal data, caught by a catalog of pattern, context and checksum. | 0 |
| [SL23](SL23-The-Narrowed-Message-Schema-The-Filters-Side.md) | blocked | Sokar B108 | B14's narrowed message schema enforced in the envelope: four `metadata` keys, five kinds with their fixed data parts, one text part, one extension URI. | 2 |

## Later

| # | Status | Blocked by | What it covers | Open questions |
|---|---|---|---|---|
| [SL08](SL08-Refuse-A-Payload-Spread-Over-Several-Messages.md) | open | — | A payload cut into pieces and sent over several messages, caught by correlating against what the task already sent. | 0 |
| [SL04](SL04-An-External-Detector-Measured.md) | open | — | Somebody else's detector catalog behind the interface, measured before anything is adopted. | 0 |
| [SL11](SL11-Refuse-A-Pointer-To-Something-That-Is-Gone.md) | open | — | A test that refuses a link to an issue's file, and a citation carrying an index link whose issue is gone. | 1 |
| [SL12](SL12-Refuse-A-Description-That-Stopped-Being-True.md) | open | — | A test that refuses a description contradicted by something the build can read - the modules named against the modules that exist. | 0 |

**Status** means: `open` - nobody is on it. `in progress` - somebody is. `handed on` - the work
belongs to another repository and this row tracks what has to change here afterwards. `blocked` -
waiting on something else, and **Blocked by** names it: an issue here by its number, a Sokar
requirement as `Sokar B<n>`.

## One module, one job

`filter/` decides what may pass and knows no transport. The transports that carry what passed live
in repositories of their own; what the filter shares with them is the directory contract and the
message format, both written down rather than compiled against.

## Where Sokar comes in

Nothing here is blocked by Sokar: this is a program that reads and writes directories. **Sokar
requirement B14** is the other half - the mailbox mounted into a task, who feeds this filter, which
transport a peer uses, and what may be in a message in the first place.
