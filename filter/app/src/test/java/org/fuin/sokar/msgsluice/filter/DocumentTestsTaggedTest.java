package org.fuin.sokar.msgsluice.filter;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * A change to documents runs only the tests tagged {@code documents} ({@code -Pdocuments}), so a test that reads a
 * document without the tag would be skipped exactly when it matters. A test reads a document when its source names
 * one as a path: a string literal that is a Markdown file name, the Markdown suffix, the documentation directory or
 * the site's navigation. A page quoted inside a longer text is test data, not a read.
 */
class DocumentTestsTaggedTest {

    private static final Path SOURCES = Path.of("src", "test", "java");

    private static final Pattern DOCUMENT_PATH = Pattern.compile(
            "\"([\\w.-]*\\.md|doc|issues|mkdocs\\.yml)\"");

    @Test
    void everyTestThatReadsADocumentIsTaggedDocuments() throws IOException {
        final Set<String> readers = documentReaders();

        // A wrong root or pattern finds nothing and would pass; a quoted page in a sentence must not count.
        assertThat(readers).as("tests that read a document").contains(IssueCitationTest.class.getName())
                .doesNotContain("org.fuin.sokar.msgsluice.filter.detect.MaskedTest");
        assertThat(readers.stream().filter(c -> !taggedDocuments(c)).toList())
                .as("tests that read a document without @Tag(\"documents\")").isEmpty();
    }

    private static Set<String> documentReaders() throws IOException {
        assertThat(SOURCES).isDirectory();
        final Set<String> readers = new TreeSet<>();
        try (Stream<Path> files = Files.walk(SOURCES)) {
            for (final Path file : files.filter(f -> f.getFileName().toString().endsWith(".java")).toList()) {
                if (DOCUMENT_PATH.matcher(Files.readString(file)).find()) {
                    readers.add(className(file));
                }
            }
        }
        return readers;
    }

    private static String className(final Path file) {
        final String relative = SOURCES.relativize(file).toString();
        return relative.substring(0, relative.length() - ".java".length())
                .replace(file.getFileSystem().getSeparator(), ".");
    }

    private static boolean taggedDocuments(final String className) {
        try {
            final Tag tag = Class.forName(className).getAnnotation(Tag.class);
            return tag != null && tag.value().equals("documents");
        } catch (final ClassNotFoundException ex) {
            return false;
        }
    }

}
