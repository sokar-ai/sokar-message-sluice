package org.fuin.sokar.msgsluice.filter;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * A change to documents runs only the tests tagged {@code documents} ({@code -Pdocuments}), so a test that reads a
 * document without the tag would be skipped exactly when it matters. A test reads a document when its source names
 * one as a path: a string literal that is a Markdown file name, the Markdown suffix, the documentation directory, the
 * issues or the site's navigation. A page quoted inside a longer text is test data, not a read. Tagged itself, so the
 * profile runs the guard even where no test reads a document.
 */
@Tag("documents")
class DocumentTestsTaggedTest {

    private static final Path SOURCES = Path.of("src", "test", "java");

    private static final Pattern DOCUMENT_PATH = Pattern.compile(
            "\"([\\w.-]*\\.md|doc|issues|mkdocs\\.yml)\"");

    @Test
    void everyTestThatReadsADocumentIsTaggedDocuments() throws IOException {
        final Map<String, String> sources = testSources();

        // A wrong root reads nothing and would pass: this test and one beside it must be among the sources read.
        assertThat(sources).as("test sources read").containsKeys(DocumentTestsTaggedTest.class.getName(),
                NullMarkedPackagesTest.class.getName());
        assertThat(sources.entrySet().stream().filter(e -> DOCUMENT_PATH.matcher(e.getValue()).find())
                .map(Map.Entry::getKey).filter(c -> !taggedDocuments(c)).toList())
                .as("tests that read a document without @Tag(\"documents\")").isEmpty();
    }

    @Test
    void aDocumentIsANamedPathAndNotAQuotedPage() {
        for (final String read : List.of("Path.of(\"doc\", \"filter.md\")", "f.endsWith(\".md\")",
                "Path.of(\"..\", \"..\", \"README.md\")", "Path.of(\"issues\")", "root.resolve(\"mkdocs.yml\")")) {
            assertThat(DOCUMENT_PATH.matcher(read).find()).as(read).isTrue();
        }
        for (final String data : List.of("\"The design is at https://example.org/doc/filter.md\"",
                "\"See fixtures/README.md and the rest\"", "\"documents\"", "\"docs\"")) {
            assertThat(DOCUMENT_PATH.matcher(data).find()).as(data).isFalse();
        }
    }

    private static Map<String, String> testSources() throws IOException {
        assertThat(SOURCES).isDirectory();
        final Map<String, String> sources = new TreeMap<>();
        try (Stream<Path> files = Files.walk(SOURCES)) {
            for (final Path file : files.filter(f -> f.getFileName().toString().endsWith(".java")).toList()) {
                sources.put(className(file), Files.readString(file));
            }
        }
        return sources;
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
