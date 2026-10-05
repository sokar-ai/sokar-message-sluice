package org.fuin.sokar.msgsluice.filter.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Map;

import org.fuin.sokar.msgsluice.filter.io.DirectoryLock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MainTest {

    @TempDir
    Path mail;

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    @BeforeEach
    void mailbox() throws Exception {
        for (final String dir : List.of("incoming", "sent", "filter/accepted", "filter/feedback")) {
            Files.createDirectories(mail.resolve(dir));
        }
        for (final String dir : List.of("filter/rejected", "filter/error")) {
            Files.createDirectories(mail.resolve(dir),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        }
    }

    int run(final String... args) {
        return Main.run(args, new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    void deliver(final String name, final String text) throws Exception {
        Files.writeString(mail.resolve("incoming").resolve(name), """
                {"messageId":"%s","role":"ROLE_AGENT","parts":[{"text":"%s"}]}""".formatted(name, text));
    }

    @Test
    void anInheritedEnvironmentCannotLetAPayloadThrough() throws Exception {
        // Its own process, because only main() sees the real environment: every rule and detector that could
        // refuse the payload switched off by variables of the kind a shell or a session might have exported.
        deliver("b.json", "Take this: " + "QUJD".repeat(20));
        final ProcessBuilder filter = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java")
                .toString(), "-cp", System.getProperty("java.class.path"), Main.class.getName(), "--mail",
                mail.toString(), "--blocking", "--stabilityDelayMillis", "0").redirectErrorStream(true)
                .redirectOutput(mail.resolve("output.txt").toFile());
        filter.environment().putAll(Map.of("SOKAR_MSGSLUICE_DECISION_MODE", "THRESHOLD",
                "SOKAR_MSGSLUICE_DECISION_SCORETHRESHOLD", "1000",
                "SOKAR_MSGSLUICE_DETECTOR_LONGTOKEN_ENABLED", "false",
                "SOKAR_MSGSLUICE_DETECTOR_ENTROPY_ENABLED", "false",
                "SOKAR_MSGSLUICE_DETECTOR_SIGNATURE_ENABLED", "false",
                "SOKAR_MSGSLUICE_DETECTOR_TOKENSHAPE_ENABLED", "false",
                "SOKAR_MSGSLUICE_DETECTOR_DISTRIBUTION_ENABLED", "false"));

        assertThat(filter.start().waitFor()).isEqualTo(1);
        assertThat(mail.resolve("filter/rejected/b.json")).exists();
        assertThat(Files.readString(mail.resolve("output.txt"))).doesNotContain("SOKAR_MSGSLUICE");
    }

    @Test
    void exitCodesAreZeroForAllAcceptedAndOneForARefusal() throws Exception {
        deliver("a.json", "All good here.");
        assertThat(run("--mail", mail.toString(), "--blocking", "--stabilityDelayMillis", "0")).isZero();

        deliver("b.json", "Take this: " + "QUJD".repeat(20));
        assertThat(run("--mail", mail.toString(), "--blocking", "--stabilityDelayMillis", "0")).isEqualTo(1);
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("1 rejected");
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("BLOCKING").contains("blocking=true");
    }

    @Test
    void theModeInForceIsSaidAtStartup() {
        assertThat(run("--mail", mail.toString(), "--stabilityDelayMillis", "0")).isZero();
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("REPORTING");
    }

    @Test
    void anUnknownOptionAbortsTheStart() throws Exception {
        deliver("a.json", "All good here.");
        assertThat(run("--mail", mail.toString(), "--blockng")).isEqualTo(2);
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("blockng");
        assertThat(mail.resolve("incoming/a.json")).exists();
    }

    @Test
    void aSecondInstanceRefusesAndNamesTheFirst() throws Exception {
        deliver("a.json", "All good here.");
        try (DirectoryLock held = DirectoryLock.acquire(mail.resolve("filter/.lock"))) {
            assertThat(run("--mail", mail.toString(), "--stabilityDelayMillis", "0")).isEqualTo(2);
        }
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("Another instance").contains("pid");
        assertThat(mail.resolve("incoming/a.json")).exists();
    }

    @Test
    void theAgentCardDescribesThisInstanceAndMovesNothing() throws Exception {
        deliver("a.json", "All good here.");

        assertThat(run("--agent-card", "--mail", mail.toString())).isZero();

        final com.fasterxml.jackson.databind.JsonNode card = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(out.toString(StandardCharsets.UTF_8));
        assertThat(card.get("name").asText()).isEqualTo("sokar-message-sluice-filter");
        assertThat(card.at("/supportedInterfaces/0/url").asText())
                .isEqualTo(mail.resolve("incoming").toUri().toString());
        assertThat(card.at("/skills/0/id").asText()).isEqualTo("data-leak-check");
        assertThat(card.at("/skills/0/description").asText()).contains("only reports");
        assertThat(card.get("defaultInputModes").toString()).isEqualTo("[\"text/plain\"]");
        assertThat(mail.resolve("incoming/a.json")).exists();

        out.reset();
        assertThat(run("--agent-card", "--mail", mail.toString(), "--blocking")).isZero();
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("This instance refuses.");
    }

    @Test
    void anUncheckedFailureIsATechnicalErrorAndNamesOnlyItsType() throws Exception {
        deliver("a.json", "All good here.");

        final int code = Main.run(new String[] {"--mail", mail.toString(), "--stabilityDelayMillis", "0"},
                failingOnPrintln(new IllegalStateException("content QUJDQUJDQUJD")),
                new PrintStream(err, true, StandardCharsets.UTF_8));

        assertThat(code).isEqualTo(2);
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("IllegalStateException")
                .doesNotContain("QUJDQUJDQUJD");
    }

    @Test
    void anErrorIsATechnicalErrorAndNotARefusal() throws Exception {
        deliver("a.json", "All good here.");

        final int code = Main.run(new String[] {"--mail", mail.toString(), "--stabilityDelayMillis", "0"},
                failingOnPrintln(new StackOverflowError("content QUJDQUJDQUJD")),
                new PrintStream(err, true, StandardCharsets.UTF_8));

        assertThat(code).isEqualTo(2);
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("StackOverflowError").doesNotContain("QUJDQUJDQUJD");
    }

    /** Stands in for any component that fails unchecked in the middle of a run. */
    static PrintStream failingOnPrintln(final Throwable failure) {
        return new PrintStream(java.io.OutputStream.nullOutputStream()) {

            @Override
            public void println(final String line) {
                if (failure instanceof RuntimeException ex) {
                    throw ex;
                }
                throw (Error) failure;
            }
        };
    }

    @Test
    void aDryRunMovesNothing() throws Exception {
        deliver("b.json", "Take this: " + "QUJD".repeat(20));
        assertThat(run("--dry-run", "--file", mail.resolve("incoming/b.json").toString(), "--blocking")).isEqualTo(1);
        assertThat(mail.resolve("incoming/b.json")).exists();
        assertThat(mail.resolve("filter/feedback")).isEmptyDirectory();
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("ENCODING/LONG_TOKEN").doesNotContain("QUJDQUJD");
    }

}
