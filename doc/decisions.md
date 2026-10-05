# Decisions

What holds and why, grouped by what it covers: one row per decision, and its full text below. An
accepted risk is among them, with what the exposure is, why it is not being removed, and what would
change the answer.

| Covers | Decision |
|---|---|
| The whole | [No language model inside the filter](#no-language-model-inside-the-filter) |
| The whole | [The filter and the transports are separate programs](#the-filter-and-the-transports-are-separate-programs) |
| The whole | [The filter does not learn which transport carries a message](#the-filter-does-not-learn-which-transport-carries-a-message) |
| The whole | [A person may read and deliver a refused message; the filter never does](#a-person-may-read-and-deliver-a-refused-message-the-filter-never-does) |
| The whole | [Sokar runs the filter blocking, both ways](#sokar-runs-the-filter-blocking-both-ways) |
| Filter | [Our own A2A model rather than the SDK, and A2A 1.0 only](#our-own-a2a-model-rather-than-the-sdk-and-a2a-10-only) |
| Filter | [The filter reads no environment](#the-filter-reads-no-environment) |
| Filter | [Only strict UTF-8 is read](#only-strict-utf-8-is-read) |
| Filter | [The filter never rewrites a message](#the-filter-never-rewrites-a-message) |
| Filter | [The filter files the bytes it checked, not the file it read them from](#the-filter-files-the-bytes-it-checked-not-the-file-it-read-them-from) |
| Filter | [A person's message is accepted, and who wrote a file is the host's check](#a-persons-message-is-accepted-and-who-wrote-a-file-is-the-hosts-check) |
| Filter | [Ids are text to the detectors, and a key is shown only while nothing says it is a payload](#ids-are-text-to-the-detectors-and-a-key-is-shown-only-while-nothing-says-it-is-a-payload) |
| Detectors | [Content detectors sit behind an interface, and the envelope stays ours](#content-detectors-sit-behind-an-interface-and-the-envelope-stays-ours) |
| Detectors | [An external detector catalogue may be in another language](#an-external-detector-catalogue-may-be-in-another-language) |
| Detectors | [The encoded-data thresholds are measured on agents' prose, not taken from textbook English](#the-encoded-data-thresholds-are-measured-on-agents-prose-not-taken-from-textbook-english) |
| Detectors | [A full hash in hex is refused](#a-full-hash-in-hex-is-refused) |
| Build | [Every action is pinned to a commit, and Dependabot moves it](#every-action-is-pinned-to-a-commit-and-dependabot-moves-it) |
| Build | [The binaries are compiled for the x86-64 baseline](#the-binaries-are-compiled-for-the-x86-64-baseline) |
| Build | [NullAway checks the main compile, configured in this repository's root POM](#nullaway-checks-the-main-compile-configured-in-this-repositorys-root-pom) |

## No language model inside the filter

The thing being checked is an agent that may have been manipulated. A checker that itself asked a
model would be open to the same manipulation, through exactly the text it is reading, and its
verdicts would be neither reproducible nor explainable to the agent they are sent back to.

So the filter is deterministic: fixed rules over files, the same verdict every time for the same
input, and every refusal traceable to one rule with a rule id, a part index and an offset.

**What this gives up**, stated rather than discovered later: a secret described in words rather than
written out (*"the password is the dog's name plus 77"*) passes, and so does steganography in word
choice. Those are named as limits in `AGENTS.md`, not as things the filter tries and sometimes
catches.

**What would change the answer:** nothing about false positives - a model would be reached for only
if a measured class of exfiltration gets through that rules cannot describe at all, and then it
would run beside the rules and be allowed to hold a message, never to release one.

## The filter and the transports are separate programs

The filter is a program of its own, and no transport is built beside it: the transports live in
repositories of their own, the Matrix transport in `sokar-message-matrix`. The filter decides what may
pass and has no queue, no timer, no address and no knowledge that any particular transport exists; a
transport carries what passed and decides nothing.

The reason is not tidiness. A transport that could see the rules could be asked to apply them, and
then the answer to "was this checked?" would depend on which route a message took. Keeping the
decision in one program means the answer is the same for every transport that will ever be added,
including ones written by somebody else.

What they share is the directory contract and the message format. Both are written down rather than
compiled against, so neither program is a library the other links.

## The filter does not learn which transport carries a message

The filter moves every accepted message, with its signature, into one directory,
`filter/accepted/`. The host resolves `metadata.to` to a peer and the peer to a transport, and moves
the pair into that transport's queue. The filter writing into `queue/<transport>/` itself, told which
by an option, is the alternative not taken.

Resolving a peer is policy, and policy is the host's - the same reason the container never sees an
address. A filter that knew the destinations could be asked to invent one, and one invocation could
not accept messages for three peers on three transports. Resolving them is Sokar's half.

**The exposure:** `accepted/` is one more directory whose content counts as checked. Whoever can write
there bypasses the filter, exactly as with a transport queue. **What would change the answer:**
nothing about convenience - only a transport that needs something from the filter that the host
cannot give it, which would first have to be argued on the channel.

## A person may read and deliver a refused message; the filter never does

A person deciding about a message the filter refused can read it in full, at the terminal and in the
interface, and can still deliver it or refuse it for good. The filter's verdict is advice to that
person, not the last word; a machine that could never send what its filter refused would leave the
operator no way to correct a false positive except by editing rules.

**The filter's part stays what it is**: it never releases a message, and everything it writes - the
answer, the receipt, the log - is redacted. Reading an original from `filter/rejected/` and delivering
it are the host's methods, not the filter's. Three conditions keep "was this checked?" one answer:

- **A delivered refusal does not go through `filter/accepted/`**, which means *the filter passed it*.
  It goes from `rejected/` to the transport queue, and the host's record names the refusal and the
  person who overrode it.
- **`filter/error/` is never delivered.** It holds what the filter could not check at all; showing it as
  text is harmless, sending it would hand a peer bytes no reader here could parse.
- **An `external` recipient checks it again.** A person's override on one machine is no verdict on
  another.

**The exposure:** a refused original, secrets included, crosses the forwarded socket when a person
reads it. It is read by the operator, not by the agent, so the rule that a refusal must not
exfiltrate what it prevents - about what the agent and the logs see - still holds. **What would
change the answer:** an interface that stores what it shows, which would make every read a copy of the
refused payload.

## Sokar runs the filter blocking, both ways

**What holds:** Sokar runs the filter with `--blocking` for what a task sends and for what arrives
from a peer it does not vouch for. A project may set its outgoing check to report only, on purpose,
with `mail.outgoing_filter: reporting`; Sokar then holds every message the filter would have refused
(`wouldReject: true`), and every message whose answer is missing, until a person releases it, and
shows the filter's verdict there. A person can still read a refused message and deliver it.

**Why:** a filter whose refusals nobody reads checks nothing - a reporting check whose verdict the
host did not read let a payload in plain text leave as `approved`. The thresholds are measured on
agents' own prose, where blocking refused one paragraph in 2869
([below](#the-encoded-data-thresholds-are-measured-on-agents-prose-not-taken-from-textbook-english)),
and a false refusal costs a rephrased message or a person's release.

**What would change the answer:** a project's traffic that blocking refuses often, which its own
calibration (`--calibrate`) shows, and which a project then answers with its own thresholds or, on
purpose, reporting.

## Our own A2A model rather than the SDK, and A2A 1.0 only

The binding reference is A2A 1.0 (`specification/a2a.proto`, tag `v1.0.1`), whose JSON form is the
ProtoJSON mapping: no `kind` discriminator, enums in `SCREAMING_SNAKE_CASE`, and one unified `Part`
carrying exactly one of `text`, `raw`, `url` or `data`.

The official `org.a2aproject.sdk:a2a-java-sdk-spec` (1.3.2.Final) carries `Message.kind()` and
separate `TextPart`/`FilePart`/`DataPart` records - the 0.3 shape - and brings no serialization at
all, so the JSON binding would have to be written here anyway.

For a security filter a parser that sees a different structure than the file actually has is a
bypass path: the difference between what the model exposes and what is in the bytes is where a
smuggled field lives. So the model is ours, small, and exactly the 1.0 structure.

**0.3 messages are refused, never converted.** A silent conversion would have to guess how
`file.bytes` maps onto `raw`, and that field is the one transfer channel this filter exists to stop.

## The filter reads no environment

Its settings come from the defaults, `--config` and the command line, never from an environment
variable. Measured with the environment still read: `SOKAR_MSGSLUICE_DECISION_DISABLEDRULES`, naming
the four rules that caught it, turned a base64 payload the filter refused into one it accepted, and
`blocking`, `decision.*` and every `detector.*.enabled` could be set the same way. Whoever starts the
filter passes on whatever their shell, profile or agent session had exported, and nobody reads the
start-up log that would name the source before a message leaves. **A security control is not
configured by something nobody sees.**

Starting the filter from a chosen environment is Sokar's half; this half does not rely on it. A test starts the filter as its own process with variables that would switch every rule and
detector off, and the payload is still refused.

**What would change the answer:** nothing about convenience. A setting that has to differ per
machine goes in the configuration file, where it is written on purpose and can be read.

## Only strict UTF-8 is read

A parser that detects encodings by itself reads UTF-16 and UTF-32 files and accepts an overlong UTF-8
sequence inside a string. A receiver that reads the same bytes strictly sees another text, and a
difference between two readers is where a smuggled field lives. A file is decoded as UTF-8 with every
malformed sequence reported before it is parsed, and a byte-order mark or a NUL byte refuses it too:
`UNPROCESSABLE/NOT_UTF8`, with a fixed reason. **What would change the answer:** a sender that
legitimately writes another encoding - A2A's JSON is UTF-8, so none is expected.

## The filter never rewrites a message

It reads a message and files exactly the bytes it read; it does not reformat, re-serialize, normalize
or annotate them.

The host signs the exact bytes that leave, and the receiving side verifies those bytes. Anything the
filter changed - even re-indenting JSON - would invalidate every signature downstream, and the
failure would appear at the far end as an attribution error rather than as a formatting bug. The test
for it is a hash of the file before and after a run.

## The filter files the bytes it checked, not the file it read them from

A name in `incoming/` is not a promise about content. Measured: a link `incoming/link.json` that is
checked through its target and then moved as a link leaves `accepted/link.json` pointing into another
directory, and rewriting the target afterwards makes the accepted message say something nobody
checked. A second (hard) link, or a rewrite between the read and the move, does the same without a
link in sight.

Two ways close it. **Verify, then move**: compare size, times, inode and a hash right before an atomic
rename - which still leaves a window between the comparison and the rename, and a rename of a hard
link still hands over an inode somebody else can write. **Write what was checked**: read the file once,
through one open file and never further than the size limit, then write exactly those bytes into
`accepted/` or `rejected/` through a new temporary file and a rename, and delete the original only if
its stamp - inode, size, modification and change time - is what it was when read. **The second is
chosen**, because what lands in `accepted/` is then the checked bytes by construction rather than by
a comparison that has to hold at the right moment. A link, a hard-linked file or a special file is not
read at all; it is unprocessable. The signature beside it is read the same way and written from what
was read.

**What this costs:** a copy of every message instead of a rename, at most `check.maxFileSizeBytes`
each, and the original's own inode, owner and times are not carried over - the filter writes a new
file. The bytes are identical, so no signature downstream notices.

**Accepted risk:** the file type is looked at before the file is opened, and Java cannot open a file
without blocking on a FIFO. A FIFO swapped in at that moment would hang the pass. Only whoever can
write `incoming/` can do that, which is the host, and a hang is loud. What would change the answer: a
writer of `incoming/` that is not the host.

**The file name is part of the message.** It travels to the peer, so it must match a plain pattern
and it goes through the detectors like a text. The pattern leaves 128 characters, room for a
transport's `<account>--` in front of a timestamp and a UUID; a tighter one would need Sokar's naming,
which is not written down here.

## A person's message is accepted, and who wrote a file is the host's check

The filter accepts `ROLE_AGENT` and `ROLE_USER` and runs the same content checks on both. A person
writes into a conversation signed with their own key and marked `ROLE_USER`, so that the receiving
side can tell a person from an agent; refusing `ROLE_USER` would stop every such message.

What a rule against `ROLE_USER` would protect - a task must never write a message that claims to be
from a person - is a property of where the file came from. The filter sees only files and cannot know
that. Sokar's intake knows it, so **the host refuses a `ROLE_USER` that a container wrote into its
outbox.** A marker file beside each message is the alternative not taken: it would be a second input
the filter has to trust, written by the same host.

**The exposure:** if the host's intake check is missing or broken, a task can pass as a person. The
filter would still check every word of it; what it would not catch is the claim of authorship.
**What would change the answer:** a transport that delivers into the filter without passing Sokar's
intake. Then the role would have to be established some other way before the filter runs.

## Ids are text to the detectors, and a key is shown only while nothing says it is a payload

An id's alphabet, `[A-Za-z0-9._:-]` up to 128 characters, is hex's and base64url's: the id check
proves the shape and nothing about the content. 5000 ids of 128 hex characters in
`referenceTaskIds` - 660 KB - pass a shape check with no finding, and so does a 128-hex `messageId`.
So every id goes to the detectors like any other string, `referenceTaskIds` is counted
(`check.maxReferenceTaskIds`), and an answer echoes an id only when nothing was found in it. A UUID,
alone or behind a short prefix, stays clean; a dashless UUID is 32 hex characters and is refused like
a hash.

The same holds for names. A metadata key or an unknown field's name shown in clear would put a
20-character key the detectors refused whole into the answer and the log, beside its masked excerpt.
**A key is named by its position whenever a finding points at it, and every key is when the envelope
refused before the detectors ran**, since then nothing has vouched for it. Naming every key by
position would be simpler, and would make an ordinary answer (`UNKNOWN_FIELD at priority`) harder to
act on.

## Content detectors sit behind an interface, and the envelope stays ours

A third-party scanner in the same problem space is open source under a permissive licence, written in
another language, and built as a proxy that mediates an agent's network traffic. What it carries is
worth knowing, because several parts of it are things this project would otherwise have to write and
then keep current:

- a maintained catalogue of roughly seventy provider credential patterns, with checksum validators
  for card numbers, IBANs, routing numbers and wallet keys;
- Unicode de-obfuscation beyond what the filter's own normalization does - zero-width and tag
  characters, homoglyph folding, leetspeak;
- reassembly of a payload fragmented across several requests, with byte and bit budgets, which is
  the most expensive feature in this design;
- regular-expression families for prompt injection, including non-English ones;
- signed receipts with key rotation and an optional transparency-log anchor;
- **no language model anywhere in its decision path**, the same conclusion this project reaches
  independently.

**What it does not carry is most of what the filter's own frame specifies**: the closed A2A schema, the
refusal of payload parts, the rule that the bytes are never rewritten, the directory contract, the
per-peer trust decision, and the answer written as a bounce the sending agent already knows how to
read. Its own detection is also thinner in places this design is explicit about - personal data
coverage is narrow and country-specific, there is no distribution test against English at all, and
its core findings block regardless of how an operator configured the action, which leaves a project
no way to report only, on purpose.

**The decision.** The filter keeps the envelope, the bytes and the verdict. The *content* detectors -
what this design calls stages B and C - are reached through one interface, so the catalogue behind
them can be this project's own, somebody else's, or both; somebody else's is adopted only once it
is measured against this project's own.

**Nothing external is adopted before it is measured** against fixtures from this repository, and if
one is adopted it is pinned, its findings are inputs to the decision model here rather than the
verdict itself, and the floors and the redaction guarantee stay in this code.

**The exposure, if an external engine is ever adopted:** a second language in the build (allowed as
an exception - *An external detector catalogue may be in another language*), its vulnerabilities and its release cadence in the deciding path of a security
boundary, and a verdict that can change when somebody else edits a rule. The surveyed one is young
and has very few maintainers, which is fine for a catalogue and uncomfortable for a decision. **What
would change the answer:** a measurement showing its false-positive rate on clean English and whether
its cross-message correlation works in a one-shot invocation - it is session-scoped, and delegating it
may require running a long-lived service beside the daemon, which is a cost this product does not
otherwise pay.

## An external detector catalogue may be in another language

**An exception to *a Java repository builds in one language*.** A maintained catalogue of credential
patterns, de-obfuscation rules and prompt-injection families is somebody else's specialist work, and
reusing it beats writing our own and keeping it current as providers invent new prefixes. So a
catalogue behind the detector interface may be written in another language, run as a subprocess.

**The conditions, which make it an exception rather than a second build:** it is adopted only after
it is measured against this repository's fixtures; it is pinned by version and by digest; it is in
the bill of materials; and once adopted it is named in `AGENTS.md` with this reason, as the shared
rule asks of every file in another language. Everything that decides - the envelope, the redaction,
the verdict, failing closed - stays in Java, here.

**The exposure:** its vulnerabilities and its release cadence sit in the deciding path of a security
boundary, and a verdict can change when somebody else edits a rule - which is why its findings are
inputs to the decision model and never the verdict. **What would change the answer:** a Java
catalogue that carries as much, or a measurement showing the external one catches nothing ours does
not.

## The encoded-data thresholds are measured on agents' prose, not taken from textbook English

Numbers taken from the properties of English - entropy 3.5 to 4.3 bits per character, a threshold of
4.5 over 128-character windows, and a chi-squared test at 1 % significance - do not hold for what
agents write. Agents write English with code spans, paths, rule ids, capitals and hashes in it:

- **Raw entropy** of that prose reaches 5.14 bits in 128-character windows, as high as base64; over
  raw text the detectors refuse 27 % of this repository's own documentation. The entropy is taken
  over **folded** text: case ignored, whitespace one symbol, punctuation one symbol. Digits stay
  themselves, because folding them too makes base36 indistinguishable from English. Folded,
  64-character windows of 2916 paragraphs of agent prose stay at or below 4.56, while base64 and
  base36 sit at a median of 4.75 and 4.80.
- **Chi-squared at a fixed significance** fails a long English text for being long, because real
  prose never matches a reference table. The statistic is divided by the number of letters instead,
  which measures how far a text is from English at any length. English stays at or below 1.64 per
  letter, base64 at 2.69 or more, and the threshold is 2.0.
- **Numbers, times, IPv4 addresses and a few short commit hashes** are masked before the statistics,
  because agents quote them constantly.

**The corpora**: this repository's documentation, which is in the repository and kept under test,
and the agents' coordination channel, which is not in the repository and was measured locally.
**The exposure:** both are prose by the same kind of writer, so the thresholds fit agents that write
like these. A mailbox whose agent writes differently is calibrated (`--calibrate`) and given its own
thresholds. **What would change the answer:** a calibration on real traffic that puts the
English of one mailbox above these thresholds.

## A full hash in hex is refused

Thirty-two hex characters of a payload and an MD5 are the same string, and so are 40 hex characters
and a commit's full SHA-1. The filter cannot tell them apart and refuses both. Up to eight **short**
hashes (7 to 12 hex characters) in one text are masked as the way agents name commits.

**The exposure** is the opposite of a leak: an agent that pastes a full hash has its message refused,
and has to name the commit by its short form. **Why it is not removed:** a whitelist of hash-shaped
strings would let 16 or 20 bytes of arbitrary data through per string, and any number of them per
message. **What would change the answer:** a way to tell a real hash from data - a repository the
filter could look the hash up in - which this filter deliberately does not have.

## Every action is pinned to a commit, and Dependabot moves it

A tag or a branch can be moved to other code at any time, and the workflow that builds and publishes
the packages would run it - one of them in the job that holds the Artifactory token. So every `uses:`
names a commit, as `@<40 hex> # vX.Y.Z`. A pin does not move by itself: Dependabot proposes the new
commits as one grouped pull request, once a release is three days old, which a person reviews; nothing
is merged automatically. The Maven `mvnw` downloads is checked against its `distributionSha256Sum`.
**`sokar-release check-actions` runs in the build and refuses what breaks any of it** - a tag or a
branch, a release line where one release belongs, a JDK setup action, a Dependabot missing, ungrouped
or without its cooldown, and the wrapper's missing digest - naming the file and the line. It is the
one check for it in every repository here, so this repository keeps no test of its own beside it;
each of those refusals was watched to fail against this repository's own files. An action's commit also fixes
what it downloads where its defaults are fixed - `setup-jfrog-cli` brings a fixed `jf` version.

**The JDK is pinned the same way.** A pinned action still installs whichever JDK its version input
names, and `setup-graalvm` with `'25'` would take the newest GraalVM 25 at run time with no digest
checked. So the build runs `sokar-machines jdk --github` instead: it installs the GraalVM
`sokar-machines`' pom pins, checks the archive against the pinned digest before unpacking it, and
sets `JAVA_HOME` for the job. The runner's own Java 25 only runs that step and builds nothing that is
published. Measured on a machine with no
JDK and no Maven cache of its own, standing in for a runner: GraalVM CE 25.0.2 installed and verified,
the native build and `LinkageIT` green with it, and CI's fixture step green on the packages it wrote;
CI then ran it green.
The pin moves with `sokar-machines`: a new snapshot of it brings the new JDK.

## The binaries are compiled for the x86-64 baseline

GraalVM 25 compiles for `x86-64-v3` unless told otherwise, and such a binary refuses to start on a
CPU without AVX, AVX2, BMI1, BMI2, FMA, F16C or LZCNT - measured from the feature list the binary's
own start-up check names. The packages say `amd64` and `x86_64`, which promise the x86-64 baseline
and nothing more, so `apt` and `dnf` install them on older CPUs and on virtual machines with a basic
CPU model, where the program would fail at its first start. The root POM passes `-march=x86-64`;
GraalVM's `-march=compatibility` names the same features, and the explicit level says what the
packages promise. `x86-64-v2` would still exclude the basic QEMU models `qemu64` and `kvm64`, which
lack SSE4.1, SSE4.2 and POPCNT - that is QEMU's documented CPU model, not measured here. `LinkageIT`
holds the binary to exactly the baseline.

**What it costs**: GraalVM names no cost for this. Measured on the build machine, the filter's
`--dry-run` on one 270 KB prose message, 30 alternating runs of each binary, twice: medians of 621
and 587 ms for `x86-64-v3` against 642 and 577 ms for the baseline - no difference beyond the noise
between two runs of the same binary. The work is short and dominated by start-up and regular
expressions, not by vector arithmetic.

**What would change the answer**: a package format that can declare a CPU level, or a supported
distribution that itself requires a higher one - then the level goes into the packages and the
test together.

## NullAway checks the main compile, configured in this repository's root POM

Every package with main code is `@NullMarked`. Error Prone runs NullAway, and only NullAway, on the
`default-compile` execution of the filter, limited to marked code by `OnlyNullMarked`: tests
pass `null` on purpose and are not checked. A planted `return null;` from a method not declared
`@Nullable` turns the build red naming its line, and green again without it. A filesystem
that does not report a file attribute fails as an `IOException`, which the callers treat as a check
that could not be made.

**Where it lives**: in this root POM, not in the parent `org.fuin:pom`, which is not ours to change.
It moves there the day the parent takes it, together with the same block in the other Sokar
repositories.

**What it needs**: `.mvn/jvm.config` opens javac's internals to Error Prone. Without it JDK 25 refuses
Error Prone before checking a file. `./mvnw` reads that file, locally and in CI.

**An unmarked package is skipped in silence**, so each program's `NullMarkedPackagesTest` fails,
naming the package, on one that is not marked - read from the compiled `package-info`, so it checks
what the compiler saw. Measured: one `package-info.java` taken out per program turns exactly that
program red naming exactly that package, and the test pointed at the wrong source root fails rather
than passing on nothing.

**What would change the answer**: the parent POM configuring it, or a JDK that no longer needs the
exports.
