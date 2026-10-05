# SL07 — Refuse credentials and personal data, design

How [SL07](README.md) would be built. **Nothing here exists yet**, and none of it has been measured.
Moved here unchanged from the design of the original issue 001, where it was stage B, step 5, and
the catalog.

## Pattern, context and checksum

**Each rule** (~1 ms for all of them) - here the principle inverts, from anomaly detection to
targeted matching, because a credential looks statistically like ordinary text. Every rule combines
three signals: a **pattern** (`AKIA[0-9A-Z]{16}`, `ghp_…`, `-----BEGIN … PRIVATE KEY-----`, IBAN,
card format), the **context** within ±40 characters (`password`, `secret`, `token`, `apikey`,
`credential`, `ssn`, …), which both raises severity and catches the cases where only the context
gives it away (*"my password is hunter2"*), and a **validation** wherever one exists - Luhn for
cards, MOD-97 for IBANs, structural decoding for a JWT. The validation is what keeps the false
positive rate down.

**It always sees the original text**, never the masked text of the encoded-data checks
([`doc/detectors.md`](../doc/detectors.md)), so a token inside a URL's query string cannot slip
through.

## The catalog

Every category can be switched on or off (`enabledCategories`) and re-graded freely between `INFO`,
`SUSPICIOUS` and `BLOCKING` (`severityOverrides`, CLI `--category EMAIL=BLOCKING`). The defaults
below follow one line: `BLOCKING` for data that has no legitimate place in a natural-language message
and whose escape does immediate harm; `SUSPICIOUS` for data that may be legitimate depending on the
business; `INFO` for what is no reliable signal alone.

**Credentials.** `PRIVATE_KEY` (header/footer pair), `CLOUD_KEY` (AWS `AKIA…`/`ASIA…`, GCP service
account JSON, Azure connection string), `VCS_TOKEN` (`ghp_`, `glpat-`, npm, PyPI), `API_KEY_GENERIC`
(high entropy ≥ 20 characters **with** a context word), `PASSWORD` (context pattern), `JWT` (three
base64url segments whose header decodes to JSON with `alg`), `CONNECTION_STRING` (URI parse with a
credential part), `SSH_AUTH` - all `BLOCKING`. `CERTIFICATE` and `HASH` are `SUSPICIOUS`.

**Personal and financial.** `CREDIT_CARD` (Luhn + IIN), `IBAN` (MOD-97) and `NATIONAL_ID` are
`BLOCKING`; `EMAIL`, `PHONE`, `IP_ADDRESS` and `DATE_OF_BIRTH` are `SUSPICIOUS`; `POSTAL_ADDRESS` is
`INFO`. **`EMAIL`/`PHONE` is the practical dial**: contact data is a legitimate part of many business
processes, and a strict data-protection reading puts it on `BLOCKING`.

**Infrastructure.** `INTERNAL_HOSTNAME` (configurable suffixes), `FILE_PATH`, `STACK_TRACE`,
`SQL_STATEMENT` - `SUSPICIOUS`.


**False alarms.** Known test values such as `4111 1111 1111 1111` or `AKIAIOSFODNN7EXAMPLE` are in an
extensible `dummyValues` list and count as `INFO` only.

Redaction is not this issue's: the frame ([`doc/filter.md`](../doc/filter.md)) masks every finding, whichever detector
produced it, and a detector returns offsets rather than excerpts.

## Known limits, and what each would take

| Limit | What would lift it |
|---|---|
| Secret patterns age as new token prefixes appear | load the pattern catalog from an external, versioned resource - or an external detector behind the interface, which is issue [SL04](README.md) |
| A secret described rather than written | nothing within the rule against a language model; stated in [`doc/filter.md`](../doc/filter.md) |
