package org.fuin.sokar.msgsluice.filter;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jspecify.annotations.NullMarked;
import org.junit.jupiter.api.Test;

/**
 * NullAway checks only {@code @NullMarked} code, so a package without the annotation compiles green with nothing
 * checked. Read from the compiled {@code package-info}, which is what the compiler saw.
 */
class NullMarkedPackagesTest {

    private static final Path SOURCES = Path.of("src", "main", "java");

    @Test
    void everyPackageWithMainCodeIsNullMarked() throws IOException {
        final Set<String> packages = packagesWithCode();

        // A wrong root finds nothing and would pass: the package of a class named here must be among them.
        assertThat(packages).contains(MessageSluice.class.getPackageName());
        assertThat(packages.stream().filter(p -> !nullMarked(p)).toList()).as("packages not @NullMarked").isEmpty();
    }

    private static Set<String> packagesWithCode() throws IOException {
        assertThat(SOURCES).isDirectory();
        try (Stream<Path> files = Files.walk(SOURCES)) {
            return files.filter(f -> f.getFileName().toString().endsWith(".java"))
                    .filter(f -> !f.getFileName().toString().equals("package-info.java"))
                    .map(f -> SOURCES.relativize(f.getParent()).toString().replace(f.getFileSystem().getSeparator(), "."))
                    .collect(Collectors.toCollection(TreeSet::new));
        }
    }

    private static boolean nullMarked(final String packageName) {
        try {
            return Class.forName(packageName + ".package-info").isAnnotationPresent(NullMarked.class);
        } catch (final ClassNotFoundException ex) {
            return false;
        }
    }

}
