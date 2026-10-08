# dist-deb

The `.deb` package of the filter: it installs the native executable as
`/usr/libexec/sokar/sokar-message-sluice-filter`, where Sokar looks for it. It packs no code of its
own and builds only with `-Pnative,dist`, so it never packs a binary from an earlier build.

- **Its library floors** (glibc, zlib) are declared in the root `pom.xml` and held to the binary by
  `LinkageIT`, shared with [`dist-rpm`](../dist-rpm/README.md) from `dist-common`.
