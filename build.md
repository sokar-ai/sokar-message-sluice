# Building

Nothing here needs a checkout of [Sokar](https://github.com/sokar-ai/sokar). The filter is a
standalone program: it reads files and writes files, and Sokar drives it by placing files where it
reads them.

```
./mvnw -B -s settings.xml verify                                   # the code, unit tests
JAVA_HOME=<graalvm> ./mvnw -B -s settings.xml -Pnative verify      # and the native executable
JAVA_HOME=<graalvm> ./mvnw -B -s settings.xml -Pnative,dist verify # and the packages
```

Java 25. `-s settings.xml` declares the snapshot repository and keeps a developer's own
`~/.m2/settings.xml` out of what the build resolves.

## The modules

One program, a module with its code and its packages below it:

| Module | Artifact | What it is |
|---|---|---|
| `filter/app/` | `sokar-message-sluice-filter` | the filter's code: decides what may pass, knows no transport |
| `filter/dist-deb/`, `filter/dist-rpm/` | `…-filter-deb`, `…-filter-rpm` | its `.deb` and `.rpm` |

The `dist-*` modules exist only in the `dist` profile. They package a file and build nothing. The
native binary is not a Maven artifact, so they find it by path, `../app/target/<name>`. Their
dependency on `app` only orders the reactor.

## What the build is allowed to bring in

**Jackson is the only runtime dependency**, and that is a requirement rather than a preference: the
fewer libraries parse an attacker's text before the rules see it, the smaller the surface. The chi
squared test and every other statistic are written here rather than pulled in.

Test scope is JUnit 5 and AssertJ, as in every other Sokar repository.

## Native executables

**The filter ships as a native executable**, like every other Sokar tool. The profile `native`
needs a GraalVM 25 as `JAVA_HOME`, and writes `filter/app/target/sokar-message-sluice-filter`. It is
**compiled for the x86-64 baseline** (`-march=x86-64`), not GraalVM's
default `x86-64-v3`, because a package saying `amd64` installs on every such CPU - see
[the decision](doc/decisions.md#the-binaries-are-compiled-for-the-x86-64-baseline).

**The binary is linked dynamically against glibc and zlib.** What a host needs is the highest
symbol version the binary uses, not the build host's glibc: measured with `readelf`, `GLIBC_2.34` and
`ZLIB_1.2.2`. A fully static binary would need a musl toolchain. Nothing in the
program uses the foreign-function API, so that option stays open.

## Packages

**One package per format**: `sokar-message-sluice-filter` installs
`/usr/libexec/sokar/sokar-message-sluice-filter`, the path Sokar's host looks in. Each package also carries its CycloneDX bill of materials and its copyright or licence
file, and depends on `sokar`, `libc6 (>= 2.34)` and `zlib1g (>= 1:1.2.2)`, or on the RPM names
`rpmbuild` would generate for them.

`jdeb` and `de.dentrassi.maven:rpm` run in the profile `dist`, **on `verify`, not `package`**: native-image runs on `package`,
and a packaging plugin there would pack the binary of the build before. Three things hold that:

- **`dist` requires `native` in the same run.** An enforcer rule refuses `-Pdist` alone, so no
  package holds a binary from an earlier build.
- **`LinkageIT`**, run by failsafe after native-image and before the packages are written, holds
  the packages to the binary. The RPM's `requires` are the reference: the binary needs
  exactly the libraries they name, and its highest symbol version of each is exactly the declared
  floor (`sluice.glibc.floor`, `sluice.zlib.floor` in the root POM) - neither above nor below it.
  The `.deb`'s `Depends` must name the same packages with the same floor properties, and the CPU
  features the binary's start-up check requires must be exactly the x86-64 baseline its architecture
  promises. Its source, `dist-common/src/test/java`, is compiled into the program's tests in the
  `dist` profile, so it checks the build without becoming part of what ships.
- **CI runs the binary unpacked from both formats**, with an empty environment so that no Java is
  involved, against the fixtures.

**The version**: `0.4.0-SNAPSHOT` becomes `0.4.0~snapshot.<run>`, and a release `0.4.0` is packaged as
it is. `~` sorts below the release in
dpkg and rpm alike, and `-` would sort above it. CI passes its run number. A local build is marked
`0+local.<timestamp>`.

**Publishing happens on a push to `main` and on a tag `v<version>`**, into Sokar's two Artifactory
repositories: `sokar-dist-deb` under `pool/main/s/<package>/`, and `sokar-dist-rpm`. A push to `main`
publishes to the `snapshots` channel, a tag to `releases`. A tag is refused unless it is `v` plus the
version the commit carries and that version is not a snapshot, and a release already published is
never uploaded again. The
upload uses `jf rt upload`, with `JF_URL` as a repository variable and `JF_ACCESS_TOKEN` as a
secret. The `.deb`'s properties are what put it into the index. Then the step *"The packages are
indexed, not merely stored"* reads both indexes back, anonymously and with `-L`, until they name the
very files just uploaded.

**The bill of materials is not made offline.** `cyclonedx-maven-plugin` skips itself in Maven's
offline mode and only warns, and the packaging then fails for the missing file. Build packages
online.

## Installed for real, before a push

The packages are installed on a rented machine before they are pushed, never only unpacked: Sokar's
`sokar-machines acceptance` (profile `ci-tools`) installs Sokar and the candidate packages with the
package manager and runs [`buildtools/acceptance.sh`](buildtools/acceptance.sh) as an unprivileged
user. That script checks what an operator would: the package is registered, the binary sits where
Sokar looks and runs with no Java, and it refuses a payload and passes prose.

## On this machine

`./install-local.sh` after a native build copies the binary to `$XDG_DATA_HOME/sokar/filter/`, where
Sokar looks for it; `--uninstall` removes it again.

**Fixtures** for running the filter against something known are in
[`filter/app/src/test/resources/fixtures/`](filter/app/src/test/resources/fixtures/README.md). A test
keeps every one of them true.
