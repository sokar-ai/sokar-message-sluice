package org.fuin.sokar.msgsluice.filter;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Code, configuration and anything that ships never cite an issue or requirement number: the issue is deleted
 * once it is finished, and the number then points nowhere. The pages in {@code doc/} are published, so they are
 * read too; the other Markdown - issues, rules, the changelog - is where numbers belong.
 */
@Tag("documents")
class IssueCitationTest {

    private static final Path ROOT = Path.of("..", "..");

    /** Any repository's prefix, one or two capitals, with two or three digits. */
    static final Pattern NUMBER = Pattern.compile("\\b[A-Z]{1,2}[0-9]{2,3}\\b");

    /**
     * Text that must keep the shape of issue numbers: the corpus is measured agents' prose, and the split-payload
     * test proves that such a list is not joined into a payload.
     */
    private static final Set<Path> MEASURED = Set.of(
            Path.of("filter", "app", "src", "test", "resources", "english-corpus.txt"),
            Path.of("filter", "app", "src", "test", "java", "org", "fuin", "sokar", "msgsluice", "filter", "detect",
                    "SplitPayloadTest.java"));

    @Test
    void nothingThatShipsCitesAnIssueNumber() throws IOException {
        final List<Path> read = new ArrayList<>();
        final List<String> citations = new ArrayList<>();
        for (final Path file : files()) {
            final String text = utf8(file);
            if (text == null) {
                continue;
            }
            read.add(ROOT.relativize(file));
            final String[] lines = text.split("\n", -1);
            for (int i = 0; i < lines.length; i++) {
                final Matcher m = NUMBER.matcher(lines[i]);
                while (m.find()) {
                    citations.add(ROOT.relativize(file) + ":" + (i + 1) + ": " + m.group());
                }
            }
        }

        // A wrong root reads nothing and would pass: the build file, a published page and this test must be read.
        assertThat(read).as("files read").contains(Path.of("pom.xml"), Path.of("doc", "filter.md"),
                Path.of("filter", "app", "src", "test", "java", "org", "fuin", "sokar", "msgsluice", "filter",
                        "IssueCitationTest.java"));
        assertThat(citations).as("issue numbers outside issues and rules; name the thing instead").isEmpty();
    }

    @Test
    void theNumbersAreFoundAndTheLookAlikesAreNot() {
        for (final String number : List.of("B" + "14", "B" + "114", "SL" + "07", "MX" + "12", "Q" + "4")) {
            assertThat(NUMBER.matcher("see " + number + " for it").find()).as(number)
                    .isEqualTo(!number.equals("Q" + "4"));
        }
        for (final String word : List.of("X509TrustManager", "SHA256", "UTF8", "v1.19", "base64", "x86-64")) {
            assertThat(NUMBER.matcher("the " + word + " here").find()).as(word).isFalse();
        }
    }

    private static List<Path> files() throws IOException {
        try (Stream<Path> walk = Files.walk(ROOT)) {
            return walk.filter(Files::isRegularFile).filter(IssueCitationTest::isReadHere).sorted().toList();
        }
    }

    private static boolean isReadHere(final Path file) {
        final Path relative = ROOT.relativize(file);
        if (MEASURED.contains(relative)
                || relative.getFileName().toString().endsWith(".md") && !relative.startsWith("doc")) {
            return false;
        }
        for (final Path part : relative) {
            final String name = part.toString();
            // Build output, and dot directories other than the workflows, are not what is committed.
            if (name.equals("target") || name.equals("site") || name.startsWith(".") && !name.equals(".github")) {
                return false;
            }
        }
        return true;
    }

    /** The file as strict UTF-8, or null for a binary file. */
    private static String utf8(final Path file) throws IOException {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(Files.readAllBytes(file)))
                    .toString();
        } catch (final CharacterCodingException e) {
            return null;
        }
    }

}
