# SL12 — Refuse a description that stopped being true

**Status:** later.

**What must be true.** Where a sentence in this repository has a counterpart the build can read, the
build refuses the two disagreeing: the modules a description names are the modules that exist.

## Why

[SL11](README.md) asks whether what a document names still exists; nothing asks whether what exists
is still described. A description of the modules here once named fewer than the reactor held, and no
pointer check could see it, since everything it named existed.

## The shape

- **The modules named in `AGENTS.md` are the modules in `pom.xml`**, the same set, and the count in
  the sentence matches what it names.
- **Every module has a contract in `doc/`**, and every contract in `doc/` names a module that exists.
- **Three sources, not two**: the prose, the reactor, and the directories on disk that carry a
  `pom.xml`, so a module directory outside the build cannot let prose and reactor agree while both
  are wrong.
- **Out of scope:** a description of behaviour, a rationale, an accepted risk, or anything with no
  counterpart a build can read. That counterpart is the test for adding a fourth item.

## Acceptance

- Seen to fail: remove a module from the prose, or add one to the reactor, and exactly one test goes
  red naming both sides, e.g. *"`AGENTS.md` names filter; `pom.xml` has filter, other"*.
- The walk asserts it found modules and prose items, so an empty list cannot pass or fail wholesale.
- It runs in this repository's own build, against its own `pom.xml`.
