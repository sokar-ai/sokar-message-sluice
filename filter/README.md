# filter

The filter, as one program and its packages: the Java code and native executable in
[`app`](app/README.md), and with `-Pnative,dist` one package per format,
[`dist-deb`](dist-deb/README.md) and [`dist-rpm`](dist-rpm/README.md). It is not a transport and
knows none; it reads and writes the directories Sokar gives it.

- **It depends on no Sokar artifact**: what it shares with Sokar and the transports is the directory
  contract and the message format, written down in [`doc/filter.md`](../doc/filter.md).
