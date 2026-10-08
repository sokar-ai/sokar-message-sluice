# app

The filter's code: it reads a message from the mailbox, decides from fixed rules whether it may
pass, answers it and moves it. With `-Pnative` it becomes the native executable the packages carry.
It is not a transport, and it holds no queue and no network.

- **No language model inside it**, and Jackson is its only runtime dependency - every library that
  parses an attacker's text before the rules see it is surface. Why:
  [`doc/decisions.md`](../../doc/decisions.md).
- **What it refuses and how it reads a message:** [`doc/filter.md`](../../doc/filter.md) and
  [`doc/detectors.md`](../../doc/detectors.md).
