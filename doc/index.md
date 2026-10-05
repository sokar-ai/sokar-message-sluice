# Sokar Message Sluice

The filter that every message an AI agent sends under Sokar passes through. It lets plain English
prose through and refuses a message that carries data instead: an encoded payload, a file in a
message part, a link or data part where text belongs.

It is an **egress filter**: it stops an agent from sending data out, whether by accident or because
a prompt injection told it to. Sokar also runs it over messages that arrive from a peer it does not
vouch for.

**There is no language model inside it.** Fixed rules, the same verdict every time for the same
message, and every refusal names the rule that made it. A checker built on a model could be talked
round by the same text it is checking.

## What it refuses

- **Encoded data** in any text or field: base64 and its relatives, hex, base32, base58, base85,
  URL-encoding, PEM, data URIs and the like from 32 characters on, and text whose statistics are
  not those of English. See [What it looks for](detectors.md).
- **Content that is not text**: raw bytes, data parts, links as parts, binary file names and media
  types. See [the envelope](filter.md#the-envelope).
- **Hidden characters**: zero-width and bidi characters, and words that mix Latin with look-alike
  letters, are reported; enough of them refuse the message.

Sokar runs it **blocking**, in both directions: a refused message does not reach the peer unless a
person reads it and delivers it. Its sender gets an answer naming each finding, with what was found
masked. A project may set the outgoing check to report only, on purpose:
`mail.outgoing_filter: reporting`.

## What it does not catch

- a secret written out in words, and anything hidden in word choice;
- credentials and personal data written as plain text - not yet built;
- a payload cut into pieces under 32 characters and sent over several messages - not yet built;
- anything that is not English prose, which it may refuse.

## Where it sits

```
task's outbox ──▶ incoming/ ──▶ [ filter ] ──▶ accepted/ ──▶ [ transport ] ──▶ peer
                                    │
                                    └─ refused ─▶ an answer back to the sender
```

The filter comes with Sokar's package, which recommends it, and with every transport, which depends
on it. Sokar drives it; nobody calls it by hand. Without it Sokar sends nothing. It works on files in
a task's mailbox, so it carries nothing itself and knows no transport. The transport that carries
what passed is [`sokar-message-matrix`](https://github.com/sokar-ai/sokar-message-matrix).

To see what it says about one message:

```
/usr/libexec/sokar/sokar-message-sluice-filter --dry-run --file message.json --blocking
```

## The pages

- [The filter](filter.md): its directories, what it does with each message, the envelope it
  checks, the verdict and the answers, its command line, and its known limits.
- [What it looks for](detectors.md): the rules that read the text, their configuration and
  calibration, how well they work, and what they cannot see.
- [Decisions](decisions.md): why it is built the way it is, one decision at a time.
