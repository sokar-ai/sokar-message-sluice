package org.fuin.sokar.msgsluice.linkage;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

/**
 * Holds a program's packages to its native binary: the binary needs exactly the libraries the packages
 * declare, its highest symbol version of each is exactly the declared floor, and it requires no CPU
 * feature beyond what the packages' architecture promises. A floor below the binary lets a package install
 * where the program then fails at its first start; a floor above it refuses hosts the program would run on;
 * a CPU target above the baseline installs on every amd64 host and fails at first start on older ones.
 * <p>
 * The RPM's requires are the reference, because they name the libraries and their symbol versions as the
 * binary does; the .deb's Depends is checked against them. The program's {@code app} module compiles this
 * source in the {@code dist} profile and runs it with failsafe, after native-image and before the packages
 * are written: this is a check of the build, not part of the program.
 */
class LinkageIT {

    /** What "amd64" and "x86_64" promise: the x86-64 baseline, in the names GraalVM gives the features. */
    private static final Set<String> X86_64_BASELINE = Set.of("CX8", "CMOV", "FXSR", "MMX", "SSE", "SSE2");

    /**
     * The Debian package that provides a library. Debian derives the name from the soname only by
     * convention, and zlib does not follow it, so a library the packages start to depend on is added here.
     */
    private static final Map<String, String> DEBIAN_PACKAGE = Map.of("libc.so.6", "libc6", "libz.so.1", "zlib1g");

    private static final Pattern NEEDED = Pattern.compile("\\(NEEDED\\)\\s+Shared library: \\[([^]]+)]");

    private static final Pattern VERSION_FILE = Pattern.compile("^\\s*\\S+: Version: \\d+\\s+File: (\\S+)");

    private static final Pattern VERSION_NAME = Pattern.compile("^\\s*\\S+:\\s+Name: (\\S+)");

    private static final Pattern FAMILY_VERSION = Pattern.compile("([A-Za-z]+)_([0-9]+(?:\\.[0-9]+)*)");

    private static final Pattern RPM_REQUIRE = Pattern.compile("<require>([^<]+)</require>");

    private static final Pattern RPM_LIBRARY = Pattern
            .compile("([^()\\s]+\\.so\\.[0-9]+)\\(([A-Za-z]+)_\\$\\{([^}]+)}\\)\\(64bit\\)");

    private static final Pattern RPM_ARCHITECTURE = Pattern.compile("<architecture>([^<]+)</architecture>");

    private static final Pattern DEB_DEPENDENCY = Pattern
            .compile("([a-z0-9][a-z0-9+.-]*)(?:\\s*\\(>= (?:[0-9]+:)?\\[\\[([^]]+)]]\\))?");

    /** The message the binary prints when it refuses to start on a CPU, naming the features it was built for. */
    private static final Pattern REQUIRED_CPU_FEATURES = Pattern
            .compile("CPU features that are required by the image: \\[([A-Z0-9_, ]*)]");

    /** A library the packages declare, the symbol version family it is held to, and that floor. */
    private record Declared(String library, String family, String floorProperty, String floor) {
    }

    @Test
    void theBinaryNeedsExactlyWhatThePackagesDeclare() throws Exception {
        final Path binary = binary();
        final Map<String, Declared> declared = rpmLibraries();

        assertThat(declared).as("libraries the RPM declares").isNotEmpty();
        assertThat(needed(binary)).as("libraries the binary needs").isEqualTo(declared.keySet());

        final Map<String, Map<String, String>> highest = highestVersions(binary);
        assertThat(highest.keySet()).as("libraries with versioned symbols").isEqualTo(declared.keySet());
        for (final Declared d : declared.values()) {
            assertThat(highest.get(d.library())).as("highest symbol version the binary uses from %s", d.library())
                    .isEqualTo(Map.of(d.family(), d.floor()));
        }
    }

    @Test
    void theDebDependsOnWhatTheRpmRequires() throws Exception {
        final Map<String, Declared> libraries = rpmLibraries();
        final Set<String> otherRequires = rpmRequires().stream().filter(r -> !r.contains(".so."))
                .collect(Collectors.toCollection(TreeSet::new));

        final Map<String, String> expected = new TreeMap<>();
        otherRequires.forEach(r -> expected.put(r, ""));
        for (final Declared d : libraries.values()) {
            final String pkg = DEBIAN_PACKAGE.get(d.library());
            assertThat(pkg).as("the Debian package that provides %s", d.library()).isNotNull();
            expected.put(pkg, d.floorProperty());
        }
        assertThat(debDepends()).as("the .deb's Depends: package and the floor property it names")
                .isEqualTo(expected);
    }

    @Test
    void theBinaryRequiresNoCpuFeatureBeyondThePackagesArchitecture() throws Exception {
        assertThat(debControl("Architecture")).as("the .deb's architecture").isEqualTo("amd64");
        final Matcher arch = RPM_ARCHITECTURE.matcher(read(property("sluice.rpm.pom")));
        assertThat(arch.find()).as("the RPM names its architecture").isTrue();
        assertThat(arch.group(1)).as("the RPM's architecture").isEqualTo("x86_64");

        final String image = new String(Files.readAllBytes(binary()), StandardCharsets.ISO_8859_1);
        final Set<Set<String>> lists = new TreeSet<>(Comparator.comparing(Set::toString));
        final Matcher m = REQUIRED_CPU_FEATURES.matcher(image);
        while (m.find()) {
            lists.add(Arrays.stream(m.group(1).split(",")).map(String::trim).filter(s -> !s.isEmpty())
                    .collect(Collectors.toCollection(TreeSet::new)));
        }
        assertThat(lists).as("the CPU feature lists the binary's start-up check names").hasSize(1);
        assertThat(lists.iterator().next()).as("the CPU features the binary requires")
                .isEqualTo(new TreeSet<>(X86_64_BASELINE));
    }

    private static Map<String, Declared> rpmLibraries() throws IOException {
        final Map<String, Declared> result = new TreeMap<>();
        for (final String require : rpmRequires()) {
            if (!require.contains(".so.")) {
                continue;
            }
            final Matcher m = RPM_LIBRARY.matcher(require);
            assertThat(m.matches()).as("RPM require '%s' names a library, its version family and a floor property",
                    require).isTrue();
            result.put(m.group(1), new Declared(m.group(1), m.group(2), m.group(3), property(m.group(3))));
        }
        return result;
    }

    private static List<String> rpmRequires() throws IOException {
        return RPM_REQUIRE.matcher(read(property("sluice.rpm.pom"))).results().map(r -> r.group(1).trim())
                .toList();
    }

    private static Map<String, String> debDepends() throws IOException {
        final Map<String, String> result = new TreeMap<>();
        for (final String entry : debControl("Depends").split(",")) {
            final Matcher m = DEB_DEPENDENCY.matcher(entry.trim());
            assertThat(m.matches()).as(".deb dependency '%s'", entry.trim()).isTrue();
            result.put(m.group(1), m.group(2) == null ? "" : m.group(2));
        }
        return result;
    }

    private static String debControl(final String field) throws IOException {
        final Matcher m = Pattern.compile("(?m)^" + field + ":\\s*(.+)$").matcher(read(property("sluice.deb.control")));
        assertThat(m.find()).as("the .deb control file has %s", field).isTrue();
        return m.group(1).trim();
    }

    private static Set<String> needed(final Path binary) throws IOException, InterruptedException {
        return NEEDED.matcher(run("readelf", "-d", "-W", binary.toString())).results().map(r -> r.group(1))
                .collect(Collectors.toCollection(TreeSet::new));
    }

    /** Per library, per version family, the highest version the binary's symbols require. */
    private static Map<String, Map<String, String>> highestVersions(final Path binary)
            throws IOException, InterruptedException {
        final Map<String, Map<String, String>> result = new TreeMap<>();
        final String versions = run("readelf", "-V", "-W", binary.toString());
        final String needs = versions.substring(Math.max(0, versions.indexOf("Version needs section")));
        String file = null;
        for (final String line : needs.split("\n")) {
            final Matcher f = VERSION_FILE.matcher(line);
            final Matcher n = VERSION_NAME.matcher(line);
            if (f.find()) {
                file = f.group(1);
            } else if (n.find()) {
                assertThat(file).as("a version name before any library: %s", line).isNotNull();
                final Matcher fv = FAMILY_VERSION.matcher(n.group(1));
                assertThat(fv.matches()).as("%s requires %s, which is no numbered version", file, n.group(1))
                        .isTrue();
                result.computeIfAbsent(file, k -> new TreeMap<>()).merge(fv.group(1), fv.group(2),
                        (a, b) -> compare(a, b) >= 0 ? a : b);
            }
        }
        return result;
    }

    private static int compare(final String a, final String b) {
        final int[] xs = Arrays.stream(a.split("\\.")).mapToInt(Integer::parseInt).toArray();
        final int[] ys = Arrays.stream(b.split("\\.")).mapToInt(Integer::parseInt).toArray();
        for (int i = 0; i < Math.max(xs.length, ys.length); i++) {
            final int c = Integer.compare(i < xs.length ? xs[i] : 0, i < ys.length ? ys[i] : 0);
            if (c != 0) {
                return c;
            }
        }
        return 0;
    }

    private static Path binary() {
        final Path binary = Path.of(property("sluice.binary"));
        assertThat(binary).isExecutable();
        return binary;
    }

    private static String property(final String name) {
        final String value = System.getProperty(name);
        assertThat(value).as("system property %s", name).isNotBlank();
        return value;
    }

    private static String read(final String path) throws IOException {
        return Files.readString(Path.of(path), StandardCharsets.UTF_8);
    }

    private static String run(final String... command) throws IOException, InterruptedException {
        final ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
        // readelf translates its labels otherwise, and the patterns above are the English ones.
        builder.environment().put("LC_ALL", "C");
        final Process process = builder.start();
        final String out = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertThat(process.waitFor()).as(String.join(" ", command) + ": " + out).isZero();
        return out;
    }

}
