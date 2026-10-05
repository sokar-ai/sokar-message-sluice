# SL11 — Refuse a pointer to something that is gone

**Status:** later.

**What must be true.** The build refuses a link to an issue's own file from anywhere but
`issues/README.md`, and a citation that carries an index link to an issue that no longer exists.

## Why

The shared rules require linking to a requirement by its number and the index, and a repository
that can test this, does. Dangling pointers here have been found only by accident: by searching for
an issue as it was deleted, or after somebody named the defect.

## The shape

- **A citation is classified by its shape, not by its sentence:**

      carries an index link                    a pointer to this repository -> must resolve
      names a repository beside the number     a cross-repository dependency -> not checked here
      bare, naming neither                     a record of a moment -> never checked

  The one case this gets wrong, a bare number meant as a pointer, already breaks the rule the guard
  enforces. A citation of another repository's number cannot be checked from here at all.
- **The scan reads the whole text and strips Markdown emphasis first**: documents wrap at 100
  columns, so the words that classify a citation often land on the line before, and this repository
  writes `Sokar requirement **B14**`, which a pattern without the markers does not match.
- **A standing document stays linkable**; only a numbered issue file and its design file die.
- **Both refusals name the file, the line and the target.**

## Acceptance

- Each refusal is seen to fail: put a dangling pointer back, and exactly one test goes red, naming
  file, line and target.
- The walk asserts it found documents **and** live issues: an empty set of documents passes forever,
  and an empty set of live issues - a filename pattern that missed after a rename - reports every
  citation as dangling. "Everything is dangling" is treated as a fault of the check.
- `CHANGELOG.md` can still say which issues it closed.

## To be checked

- Does a retired number leave this repository's documents with its file? Repairs so far took the
  number out and named the thing instead, but `CHANGELOG.md` rightly keeps closed numbers as its
  record, so the rule cannot be "every cited number must exist".
