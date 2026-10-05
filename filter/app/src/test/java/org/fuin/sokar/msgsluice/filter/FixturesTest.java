package org.fuin.sokar.msgsluice.filter;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import org.fuin.sokar.msgsluice.filter.MessageSluice.FileResult;
import org.fuin.sokar.msgsluice.filter.MessageSluice.Outcome;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Every file in {@code fixtures/} does what its name says, in both modes - see the README there. */
class FixturesTest {

    static final Path FIXTURES = Path.of("src/test/resources/fixtures");

    @TempDir
    Path tmp;

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void everyFixtureEndsWhereItsNameSays(final boolean blocking) throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        final List<Path> fixtures;
        try (Stream<Path> files = Files.list(FIXTURES)) {
            fixtures = files.filter(p -> p.toString().endsWith(".json")).sorted().toList();
        }
        assertThat(fixtures).hasSizeGreaterThan(10);
        for (final Path fixture : fixtures) {
            Files.copy(fixture, mail.incoming().resolve(fixture.getFileName()));
        }

        final MessageSluice.RunSummary summary = mail.sluice("blocking", String.valueOf(blocking)).runOnce();

        assertThat(summary.results()).hasSameSizeAs(fixtures);
        for (final FileResult result : summary.results()) {
            assertThat(result.outcome()).as(result.name()).isEqualTo(expected(result.name(), blocking));
            if (result.name().startsWith("detector-")) {
                assertThat(result.findings()).as(result.name()).isNotEmpty();
            }
        }
        assertThat(mail.files(mail.feedback())).hasSameSizeAs(fixtures);
    }

    static Outcome expected(final String name, final boolean blocking) {
        if (name.startsWith("accept-")) {
            return Outcome.ACCEPTED;
        }
        if (name.startsWith("detector-")) {
            return blocking ? Outcome.REJECTED : Outcome.ACCEPTED;
        }
        if (name.startsWith("envelope-")) {
            return Outcome.REJECTED;
        }
        if (name.startsWith("unprocessable-")) {
            return Outcome.UNPROCESSABLE;
        }
        throw new IllegalArgumentException("A fixture's name says what happens to it: " + name);
    }

}
