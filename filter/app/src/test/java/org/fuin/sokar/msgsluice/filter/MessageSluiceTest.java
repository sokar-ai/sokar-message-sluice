package org.fuin.sokar.msgsluice.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.fuin.sokar.msgsluice.filter.Mailbox.message;

import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.fuin.sokar.msgsluice.filter.io.SshSignature;
import org.fuin.sokar.msgsluice.filter.MessageSluice.Outcome;
import org.fuin.sokar.msgsluice.filter.a2a.A2aReader;
import org.fuin.sokar.msgsluice.filter.a2a.CheckConfig;
import org.fuin.sokar.msgsluice.filter.a2a.EnvelopeCheck;
import org.fuin.sokar.msgsluice.filter.a2a.EnvelopeResult;
import org.fuin.sokar.msgsluice.filter.decision.Finding;
import org.fuin.sokar.msgsluice.filter.decision.Redactor;
import org.fuin.sokar.msgsluice.filter.decision.Severity;
import org.fuin.sokar.msgsluice.filter.decision.Stage;
import org.fuin.sokar.msgsluice.filter.detect.ContentDetector;
import org.fuin.sokar.msgsluice.filter.detect.DetectorFinding;
import org.fuin.sokar.msgsluice.filter.detect.DetectorRunner;
import org.fuin.sokar.msgsluice.filter.detect.LongTokenDetector;
import org.fuin.sokar.msgsluice.filter.detect.TextUnderCheck;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.JsonNode;

/** What must be proven to fail, asserted on where files end up rather than on wording. */
class MessageSluiceTest {

    /** 64 characters of base64: a payload by any measure, and nothing a real key. */
    static final String PAYLOAD = "UEsDBBQAAAAIAGx0Mlt3b3JkL2RvY3VtZW50LnhtbKxVS27bMBC9C8E7RVJ2m9qw";

    static final String PROSE = "Please review the summary below. The quarterly numbers are in line with the "
            + "forecast, and the team would like to discuss the hiring plan on Thursday.";

    @TempDir
    Path tmp;

    @Test
    void cleanProseIsAcceptedUnchangedWithItsSignatureAndAReceipt() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        final Path file = mail.deliver("msg-1.json", message(PROSE));
        Files.write(file.resolveSibling("msg-1.json.sig"), sokarSignature());
        final String before = Redactor.sha256(Files.readAllBytes(file));

        final MessageSluice.RunSummary summary = mail.sluice("blocking", "true").runOnce();

        assertThat(summary.exitCode()).isZero();
        assertThat(Redactor.sha256(Files.readAllBytes(mail.accepted().resolve("msg-1.json")))).isEqualTo(before);
        assertThat(mail.accepted().resolve("msg-1.json.sig")).hasBinaryContent(sokarSignature());
        assertThat(mail.files(mail.incoming())).isEmpty();
        assertThat(mail.files(mail.feedback())).hasSize(1);
        final JsonNode receipt = readAnswer(mail.files(mail.feedback()).get(0));
        assertThat(receipt.at("/parts/1/data/decision").asText()).isEqualTo("approved");
        assertThat(receipt.at("/parts/1/data/mode").asText()).isEqualTo("blocking");
        assertThat(receipt.at("/metadata/inReplyToMessageId").asText())
                .isEqualTo("msg-7f6c8f6e-7f2e-4d5f-bf8c-1f3c50a29f12");
    }

    @Test
    void aVersion03MessageIsRefusedNotConvertedWhileThe10FormIsChecked() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("old.json", """
                {"kind":"message","messageId":"m-1","role":"agent","parts":[{"kind":"text","text":"Hello there."}]}""");
        mail.deliver("new.json", """
                {"messageId":"m-2","role":"ROLE_AGENT","parts":[{"text":"Hello there."}]}""");

        final MessageSluice.RunSummary summary = mail.sluice("blocking", "true").runOnce();

        assertThat(mail.error().resolve("old.json")).exists();
        assertThat(mail.error().resolve("old.json.error.txt")).content()
                .contains("UNPROCESSABLE/UNSUPPORTED_PROTOCOL_VERSION");
        assertThat(mail.accepted().resolve("new.json")).exists();
        assertThat(summary.count(Outcome.UNPROCESSABLE)).isEqualTo(1);
        assertThat(summary.exitCode()).isEqualTo(1);
    }

    @Test
    void aPartWithTextAndRawIsRefusedEvenWhileOnlyReporting() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("m.json", """
                {"messageId":"m-1","role":"ROLE_AGENT","parts":[{"text":"Hello.","raw":"UEsDBBQAAAAI"}]}""");

        mail.sluice().runOnce();

        assertThat(mail.rejected().resolve("m.json")).exists();
        assertThat(mail.files(mail.accepted())).isEmpty();
        assertThat(ruleIds(readAnswer(mail.files(mail.feedback()).get(0))))
                .contains("ENVELOPE/AMBIGUOUS_PART", "ENVELOPE/RAW_PART_NOT_ALLOWED");
    }

    @Test
    void aFindingInMetadataRefusesLikeOneInAText() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("m.json", """
                {"messageId":"m-1","role":"ROLE_AGENT","parts":[{"text":"Hello."}],
                 "metadata":{"note":{"deeper":["%s"]}}}""".formatted(PAYLOAD));

        mail.sluice("blocking", "true").runOnce();

        assertThat(mail.rejected().resolve("m.json")).exists();
        final JsonNode rejection = readAnswer(mail.files(mail.feedback()).get(0));
        assertThat(rejection.at("/parts/1/data/findings/0/location").asText()).isEqualTo("metadata.#0.#0[0]");
    }

    @Test
    void anUnknownFieldIsHeldToTheSameDepthAndSizeAsMetadata() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        final String nine = "[".repeat(9) + "\"" + PAYLOAD + "\"" + "]".repeat(9);
        mail.deliver("deep.json", """
                {"messageId":"m-1","role":"ROLE_AGENT","parts":[{"text":"Hello."}],"x":%s}""".formatted(nine));
        mail.deliver("deep-task.json", """
                {"id":"task-1","status":{"state":"TASK_STATE_COMPLETED","zz":%s}}""".formatted(nine));
        mail.deliver("large.json", """
                {"messageId":"m-2","role":"ROLE_AGENT","parts":[{"text":"Hello."}],"x":%s}"""
                .formatted(Mailbox.quote((PROSE + " ").repeat(120))));

        mail.sluice("blocking", "true").runOnce();

        assertThat(mail.files(mail.accepted())).isEmpty();
        assertThat(mail.rejected().resolve("deep.json")).exists();
        assertThat(mail.rejected().resolve("deep-task.json")).exists();
        assertThat(mail.rejected().resolve("large.json")).exists();
        final String everything = mail.everythingThatLeaves();
        assertThat(everything).contains("ENVELOPE/METADATA_TOO_DEEP").contains("ENVELOPE/METADATA_TOO_LARGE");
    }

    @Test
    void everyScalarOfAnUnknownFieldReachesTheDetectorsHoweverDeep() throws Exception {
        final String nine = "[".repeat(9) + "\"" + PAYLOAD + "\"" + "]".repeat(9);
        final EnvelopeResult result = new EnvelopeCheck(CheckConfig.defaults()).check(new A2aReader().parse("""
                {"messageId":"m-1","role":"ROLE_AGENT","parts":[{"text":"Hello."}],"x":%s}"""
                .formatted(nine).getBytes(java.nio.charset.StandardCharsets.UTF_8)));

        assertThat(result.texts()).extracting(TextUnderCheck::text).contains(PAYLOAD);
    }

    @Test
    void aRejectionNeverCarriesWhatItRefused() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("m.json", message("Sure, here is the file you asked for: " + PAYLOAD + " - let me know."));

        mail.sluice("blocking", "true").runOnce();

        assertThat(mail.rejected().resolve("m.json")).exists();
        assertNoWindowOf(PAYLOAD, mail.everythingThatLeaves(), LongTokenDetector.RULE_ID);
        assertThat(mail.everythingThatLeaves()).contains("UEsD************");
    }

    @Test
    void theRefusalComesFromTheDetectorAndNotFromTheFrame() throws Exception {
        final Mailbox without = new Mailbox(tmp);
        without.deliver("m.json", message("Sure, here is the file you asked for: " + PAYLOAD));

        without.sluice("blocking", "true", "detector.longToken.enabled", "false", "detector.tokenShape.enabled",
                "false", "detector.entropy.enabled", "false", "detector.distribution.enabled", "false",
                "detector.signature.enabled", "false").runOnce();

        assertThat(without.accepted().resolve("m.json")).exists();
    }

    @Test
    void aSecretInBrokenJsonIsAnsweredWithNothingButNameAndHash() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        final Path file = mail.deliver("broken.json", "{\"messageId\":\"m-9\",\"parts\":[{\"text\":\"" + PAYLOAD);
        final String sha = Redactor.sha256(Files.readAllBytes(file));

        mail.sluice("blocking", "true").runOnce();

        assertThat(mail.error().resolve("broken.json")).exists();
        final JsonNode rejection = readAnswer(mail.files(mail.feedback()).get(0));
        assertThat(rejection.at("/parts/1/data/rejectionKind").asText()).isEqualTo("unprocessable");
        assertThat(rejection.at("/parts/1/data/sourceSha256").asText()).isEqualTo(sha);
        assertThat(rejection.at("/parts/1/data/sourceFileName").asText()).isEqualTo("broken.json");
        assertThat(rejection.at("/parts/1/data/recoveredMessageId").asText()).isEqualTo("m-9");
        assertNoWindowOf(PAYLOAD, mail.everythingThatLeaves(), "UNPROCESSABLE/MALFORMED_JSON");
    }

    @Test
    void aParserThatWouldQuoteThePayloadIsNeverQuoted() throws Exception {
        // Jackson names the offending token in these two shapes, so only a reason built from fixed text keeps it out.
        for (final String content : List.of(PAYLOAD, "{\"a\":1} " + PAYLOAD, "{\"a\":1}\n" + PAYLOAD + "\n")) {
            final Mailbox mail = new Mailbox(tmp.resolve("case-" + content.length()));
            mail.deliver("m.json", content);

            mail.sluice("blocking", "true").runOnce();

            assertThat(mail.error().resolve("m.json")).exists();
            assertNoWindowOf(PAYLOAD, mail.everythingThatLeaves() + Files.readString(mail.error()
                    .resolve("m.json.error.txt")), "UNPROCESSABLE/MALFORMED_JSON");
        }
    }

    @Test
    void onlyStrictUtf8IsRead() throws Exception {
        final byte[] bom = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
        // An overlong encoding of U+002C inside a string: a lenient decoder reads a comma, a strict one nothing.
        final byte[] withOverlong = concat(concat(
                "{\"messageId\":\"m-o\",\"role\":\"ROLE_AGENT\",\"parts\":[{\"text\":\"Hello".getBytes(
                        java.nio.charset.StandardCharsets.US_ASCII), new byte[] {(byte) 0xC0, (byte) 0xAC}),
                "\"}]}".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        final java.util.Map<String, byte[]> files = new java.util.LinkedHashMap<>();
        // Each its own id, so that a duplicate is not what refuses it.
        files.put("utf16be.json", message(PROSE).replace("msg-", "m16-")
                .getBytes(java.nio.charset.StandardCharsets.UTF_16BE));
        files.put("utf32le.json", message(PROSE).replace("msg-", "m32-")
                .getBytes(java.nio.charset.Charset.forName("UTF-32LE")));
        files.put("bom.json", concat(bom, message(PROSE).replace("msg-", "bom-")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        files.put("overlong.json", withOverlong);
        files.put("latin1.json", message("Caf\u00e9 au lait.").replace("msg-", "l1-")
                .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));

        final Mailbox mail = new Mailbox(tmp);
        for (final java.util.Map.Entry<String, byte[]> e : files.entrySet()) {
            Files.write(mail.incoming().resolve(e.getKey()), e.getValue());
        }
        mail.sluice("blocking", "true").runOnce();

        assertThat(mail.files(mail.accepted())).isEmpty();
        for (final String name : files.keySet()) {
            assertThat(mail.error().resolve(name + ".error.txt")).as(name).content().contains("UNPROCESSABLE/NOT_UTF8");
        }
    }

    static byte[] concat(final byte[] a, final byte[] b) {
        final byte[] out = java.util.Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    @Test
    void longCapitalsAndLongNumberListsAreAcceptedWhileOnlyReporting() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("capitals.json", message("PLEASE READ THE STATUS REPORT. ".repeat(2000)).replace("msg-", "c-"));
        mail.deliver("numbers.json", message("12, 34, ".repeat(8000)).replace("msg-", "n-"));

        final MessageSluice.RunSummary summary = mail.sluice().runOnce();

        assertThat(summary.results()).allSatisfy(r -> assertThat(r.findings()).as(r.name())
                .extracting(Finding::ruleId).doesNotContain(DetectorRunner.DETECTOR_FAILED));
        assertThat(mail.accepted().resolve("capitals.json")).exists();
        assertThat(mail.accepted().resolve("numbers.json")).exists();
    }

    @Test
    void aDetectorThatThrowsStopsTheMessageEvenWhileOnlyReporting() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("m.json", message(PROSE));

        mail.sluice(List.of(stub(t -> {
            throw new IllegalStateException("secret " + PAYLOAD);
        }))).runOnce();

        assertThat(mail.files(mail.accepted())).isEmpty();
        // The detector failed on the file name too, so not even the name counts as checked: it is kept hashed.
        assertThat(mail.files(mail.rejected())).singleElement().satisfies(p -> assertThat(p.getFileName().toString())
                .isEqualTo(MessageSluice.hashedName("m.json")));
        assertThat(ruleIds(readAnswer(mail.files(mail.feedback()).get(0)))).contains(DetectorRunner.DETECTOR_FAILED);
        assertNoWindowOf(PAYLOAD, mail.everythingThatLeaves(), DetectorRunner.DETECTOR_FAILED);
    }

    @Test
    void aFindingThatCannotBeRedactedRefusesRatherThanAppears() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("m.json", message(PROSE));

        mail.sluice(List.of(stub(t -> List.of(new DetectorFinding("STUB/HIT", Stage.TEXT, Severity.INFO, "STUB", 5,
                10_000, "out of range"))))).runOnce();

        assertThat(mail.files(mail.accepted())).isEmpty();
        assertThat(ruleIds(readAnswer(mail.files(mail.feedback()).get(0)))).contains(DetectorRunner.UNREDACTABLE);
    }

    @Test
    void anExplanationQuotingTheMatchRefusesRatherThanAppears() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("m.json", message("The code is " + PAYLOAD));

        mail.sluice(List.of(stub(t -> List.of(new DetectorFinding("STUB/HIT", Stage.TEXT, Severity.INFO, "STUB",
                t.text().indexOf(PAYLOAD), t.text().length(), "found " + PAYLOAD))))).runOnce();

        assertThat(mail.files(mail.accepted())).isEmpty();
        assertNoWindowOf(PAYLOAD, mail.everythingThatLeaves(), DetectorRunner.UNREDACTABLE);
    }

    @Test
    void aDetectorFindingNothingDoesNotOverrideTheEnvelope() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("m.json", """
                {"messageId":"m-1","role":"ROLE_AGENT","parts":[{"data":{"rows":[1,2,3]}}]}""");

        mail.sluice(List.of(stub(t -> List.of()))).runOnce();

        assertThat(mail.rejected().resolve("m.json")).exists();
    }

    @Test
    void reportingModeAcceptsAndNamesWhatBlockingModeRefuses() throws Exception {
        final Mailbox reporting = new Mailbox(tmp.resolve("reporting"));
        reporting.deliver("m.json", message("Here it is: " + PAYLOAD));
        final Mailbox blocking = new Mailbox(tmp.resolve("blocking"));
        blocking.deliver("m.json", message("Here it is: " + PAYLOAD));

        assertThat(reporting.sluice().runOnce().exitCode()).isZero();
        assertThat(blocking.sluice("blocking", "true").runOnce().exitCode()).isEqualTo(1);

        assertThat(reporting.accepted().resolve("m.json")).exists();
        final JsonNode receipt = readAnswer(reporting.files(reporting.feedback()).get(0));
        assertThat(receipt.at("/parts/1/data/decision").asText()).isEqualTo("approved");
        assertThat(receipt.at("/parts/1/data/mode").asText()).isEqualTo("reporting");
        assertThat(receipt.at("/parts/1/data/wouldReject").asBoolean()).isTrue();
        assertThat(ruleIds(receipt)).contains(LongTokenDetector.RULE_ID);
        assertThat(blocking.rejected().resolve("m.json")).exists();
    }

    @Test
    void aPersonMayWriteButARoleNobodyHasIsRefusedAndAUserInATasksHistoryIsFine() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("person.json", """
                {"messageId":"m-0","role":"ROLE_USER","parts":[{"text":"Hello from a person."}]}""");
        mail.deliver("person-payload.json", """
                {"messageId":"m-4","role":"ROLE_USER","parts":[{"text":"Here: %s"}]}""".formatted(PAYLOAD));
        mail.deliver("user.json", """
                {"messageId":"m-1","role":"ROLE_UNSPECIFIED","parts":[{"text":"Hello."}]}""");
        mail.deliver("task.json", """
                {"id":"task-1","contextId":"ctx-1","status":{"state":"TASK_STATE_COMPLETED"},
                 "history":[{"messageId":"m-2","role":"ROLE_USER","parts":[{"text":"Please summarize it."}]},
                            {"messageId":"m-3","role":"ROLE_AGENT","parts":[{"text":"Here is the summary."}]}]}""");

        mail.sluice("blocking", "true").runOnce();

        assertThat(mail.accepted().resolve("person.json")).exists();
        // A person's message is checked like an agent's.
        assertThat(mail.rejected().resolve("person-payload.json")).exists();
        assertThat(mail.rejected().resolve("user.json")).exists();
        assertThat(mail.accepted().resolve("task.json")).exists();
    }

    /** 64 bytes in hex: a well-formed id by its alphabet and length, and a payload by any other measure. */
    static final String HEX_ID = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            + "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";

    @Test
    void everyIdIsCheckedAsTextAndAnIdThatIsAPayloadIsNeverEchoed() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("messageId.json", """
                {"messageId":"%s","contextId":"ctx-1","taskId":"task-1","role":"ROLE_AGENT",
                 "parts":[{"text":"Hello."}]}""".formatted(HEX_ID));
        mail.deliver("contextId.json", """
                {"messageId":"m-c","contextId":"%s","taskId":"task-1","role":"ROLE_AGENT",
                 "parts":[{"text":"Hello."}]}""".formatted(HEX_ID));
        mail.deliver("taskId.json", """
                {"messageId":"m-t","contextId":"ctx-1","taskId":"%s","role":"ROLE_AGENT",
                 "parts":[{"text":"Hello."}]}""".formatted(HEX_ID));
        mail.deliver("reference.json", """
                {"messageId":"m-r","role":"ROLE_AGENT","parts":[{"text":"Hello."}],"referenceTaskIds":["%s"]}"""
                .formatted(HEX_ID));
        mail.deliver("task.json", """
                {"id":"%s","status":{"state":"TASK_STATE_COMPLETED"},
                 "artifacts":[{"artifactId":"a-1","parts":[{"text":"Hi."}]}]}""".formatted(HEX_ID));
        mail.deliver("broken.json", "{\"messageId\":\"" + HEX_ID + "\",\"parts\":[");

        mail.sluice("blocking", "true").runOnce();

        assertThat(mail.files(mail.accepted())).isEmpty();
        assertThat(mail.files(mail.feedback())).hasSize(6);
        final String everything = mail.everythingThatLeaves();
        assertThat(everything).contains("ENCODING/HEX").contains("UNPROCESSABLE/MALFORMED_JSON");
        assertNoWindowOf(HEX_ID, everything, "ENCODING/HEX");
    }

    @Test
    void idsThatAreUuidsPassCleanly() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("m.json", """
                {"messageId":"0b1c7a52-5d0e-4c43-9a55-3f0d2f6f1e11","contextId":"6f1a2b3c-4d5e-4f60-8a1b-2c3d4e5f6a7b",
                 "taskId":"task-7d9e2c4a-1b3f-4e5d-9c8b-7a6f5e4d3c2b","role":"ROLE_AGENT",
                 "referenceTaskIds":["c9d8e7f6-a5b4-4c3d-8e2f-1a0b9c8d7e6f","f0e1d2c3-b4a5-4968-8776-655443322110"],
                 "parts":[{"text":%s}]}""".formatted(Mailbox.quote(PROSE)));

        final MessageSluice.RunSummary summary = mail.sluice("blocking", "true").runOnce();

        assertThat(summary.results()).singleElement().satisfies(r -> assertThat(r.findings()).isEmpty());
        assertThat(mail.accepted().resolve("m.json")).exists();
    }

    @Test
    void referenceTaskIdsAreCounted() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        final String refs = String.join(",", java.util.stream.IntStream.range(0, 33)
                .mapToObj(i -> "\"task-" + i + "\"").toList());
        mail.deliver("many.json", """
                {"messageId":"m-1","role":"ROLE_AGENT","parts":[{"text":"Hello."}],"referenceTaskIds":[%s]}"""
                .formatted(refs));
        mail.deliver("few.json", """
                {"messageId":"m-2","role":"ROLE_AGENT","parts":[{"text":"Hello."}],"referenceTaskIds":[%s]}"""
                .formatted(refs.substring(refs.indexOf(',') + 1)));

        mail.sluice("blocking", "true").runOnce();

        assertThat(mail.accepted().resolve("few.json")).exists();
        assertThat(mail.rejected().resolve("many.json")).exists();
        assertThat(mail.everythingThatLeaves()).contains("ENVELOPE/TOO_MANY_REFERENCES");
    }

    @Test
    void aRoleA2aDoesNotHaveIsNeverAcceptedEvenWhenAnyRoleIs() throws Exception {
        for (final String allowed : new String[] {"", "ROLE_AGENT,ROLE_USER"}) {
            final Mailbox mail = new Mailbox(tmp.resolve("allowed-" + allowed.length()));
            mail.deliver("m.json", """
                    {"messageId":"m-1","role":"ROLE_%s","parts":[{"text":"Hello."}]}""".formatted(PAYLOAD));

            mail.sluice("blocking", "true", "check.allowedRoles", allowed).runOnce();

            assertThat(mail.files(mail.accepted())).as(allowed).isEmpty();
            assertThat(mail.error().resolve("m.json")).as(allowed).exists();
            assertThat(mail.error().resolve("m.json.error.txt")).content()
                    .contains("UNPROCESSABLE/SCHEMA_VIOLATION");
            assertNoWindowOf(PAYLOAD, mail.everythingThatLeaves(), "UNPROCESSABLE/SCHEMA_VIOLATION");
        }
    }

    @Test
    void aPeerIsNamedByItsSigningPrincipalAndNothingElse() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("ok.json", """
                {"messageId":"m-1","role":"ROLE_AGENT","parts":[{"text":"Hello."}],
                 "metadata":{"to":"sokar@test-ubuntu-vm","from":"ops@example.org"}}""");
        mail.deliver("bad.json", """
                {"messageId":"m-2","role":"ROLE_AGENT","parts":[{"text":"Hello."}],
                 "metadata":{"to":"@../../etc/passwd"}}""");

        mail.sluice("blocking", "true").runOnce();

        assertThat(mail.accepted().resolve("ok.json")).exists();
        assertThat(mail.rejected().resolve("bad.json")).exists();
    }

    @Test
    void aMessageIdIsNotProcessedTwice() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("first.json", message(PROSE));
        mail.sluice("blocking", "true").runOnce();
        mail.deliver("again.json", message(PROSE));

        mail.sluice("blocking", "true").runOnce();

        assertThat(mail.accepted().resolve("first.json")).exists();
        assertThat(mail.rejected().resolve("again.json")).exists();
    }

    @Test
    void unfinishedAndHiddenFilesAreLeftAlone() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("m.json.part", "{\"messageId\":");
        mail.deliver(".m.json", "{\"messageId\":");
        mail.deliver("m.tmp", "{\"messageId\":");

        final MessageSluice.RunSummary summary = mail.sluice().runOnce();

        assertThat(summary.results()).isEmpty();
        assertThat(mail.files(mail.incoming())).hasSize(3);
    }

    @Test
    void aFileStillGrowingIsSetAsideRatherThanParsed() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        final Path file = mail.deliver("m.json", "{\"messageId\":\"m-1\",");
        final Settings settings = mail.settings("stabilityDelayMillis", "400");
        // The writer appends exactly between the two samples of the file's size, never by chance.
        final MessageSluice sluice = new MessageSluice(settings.config(), settings.detectors(), Mailbox.clock(),
                mail.log::add, delay -> {
                    try {
                        Files.writeString(file, "\"role\":\"ROLE_AGENT\"", java.nio.file.StandardOpenOption.APPEND);
                    } catch (final java.io.IOException ex) {
                        throw new java.io.UncheckedIOException(ex);
                    }
                });

        final MessageSluice.RunSummary summary = sluice.runOnce();

        assertThat(summary.results()).singleElement()
                .satisfies(r -> assertThat(r.outcome()).isEqualTo(Outcome.SET_ASIDE));
        assertThat(file).exists();
        assertThat(mail.files(mail.error())).isEmpty();
    }

    @Test
    void aCrashBetweenAnswerAndMoveMeansTheMessageIsProcessedAgainNotLost() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("m.json", message(PROSE));
        // What a crash after the answer and before the move leaves behind: an answer, and the message still there.
        Files.writeString(mail.feedback().resolve("earlier-answer.json"), "{}");

        mail.sluice("blocking", "true").runOnce();

        assertThat(mail.accepted().resolve("m.json")).exists();
        assertThat(mail.files(mail.feedback())).hasSize(2);
    }

    @Test
    void anUnknownFieldIsReportedAndAnUnprintableNameIsNotRepeated() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("m.json", """
                {"messageId":"m-1","role":"ROLE_AGENT","parts":[{"text":"Hello."}],"%s":"x","priority":"high"}"""
                .formatted(PAYLOAD));

        mail.sluice("blocking", "true").runOnce();

        final JsonNode answer = readAnswer(mail.files(mail.feedback()).get(0));
        // Both are named by position: a field's name is text its writer chose, so it is never repeated in clear.
        assertThat(answer.toString()).contains("ENVELOPE/UNKNOWN_FIELD").contains("#3").contains("#4")
                .doesNotContain("priority");
        assertNoWindowOf(PAYLOAD, mail.everythingThatLeaves(), "ENVELOPE/UNKNOWN_FIELD");
    }

    /** Short and plain enough to have been shown as a field name, and a payload to the detectors. */
    static final String KEY = "ZX9QK3LM8VB2NP7RT5WY";

    @Test
    void aKeyARuleMatchedIsNamedByItsPositionOnly() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("metadata.json", """
                {"messageId":"m-1","role":"ROLE_AGENT","parts":[{"text":"Hello."}],
                 "metadata":{"note":"%s","%s":{"inner":"%s"}}}""".formatted(PAYLOAD, KEY, PAYLOAD));
        mail.deliver("unknown.json", """
                {"messageId":"m-2","role":"ROLE_AGENT","parts":[{"text":"Hello."}],"%s":"x"}""".formatted(KEY));
        // Refused by the envelope before any detector runs, so nothing says whether the name is a payload.
        mail.deliver("unchecked.json", """
                {"messageId":"m-3","role":"ROLE_AGENT","parts":[{"raw":"AAAA"}],"%s":"x"}""".formatted(KEY));

        mail.sluice("blocking", "true").runOnce();

        assertThat(mail.files(mail.rejected())).hasSize(3);
        final String everything = mail.everythingThatLeaves();
        assertThat(everything).contains("metadata.#1(key)").contains("metadata.#1.#0")
                .contains("ENVELOPE/UNKNOWN_FIELD").contains("ENVELOPE/RAW_PART_NOT_ALLOWED")
                .contains("metadata.#0").doesNotContain("metadata.note").doesNotContain(".inner");
        assertNoWindowOf(KEY, everything, "ENVELOPE/UNKNOWN_FIELD");
    }

    /** Codex's review: a key the detectors passed was still shown in clear above a finding below it. */
    @Test
    void aKeyAboveAFindingIsNamedByItsPositionToo() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("nested.json", """
                {"messageId":"m-1","role":"ROLE_AGENT","parts":[{"text":"Hello."}],
                 "metadata":{"the bank pin is four four one two":{"list":["%s"]}}}""".formatted(PAYLOAD));

        mail.sluice("blocking", "true").runOnce();

        assertThat(mail.files(mail.rejected())).hasSize(1);
        final String everything = mail.everythingThatLeaves();
        assertThat(everything).contains("metadata.#0.#0[0]").doesNotContain("bank pin").doesNotContain(".list");
    }

    @Test
    void everyAnswerReadsBackAndPassesTheCheckButForItsDataPart() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("a.json", message(PROSE));
        mail.deliver("b.json", message("Here it is: " + PAYLOAD));
        mail.deliver("c.json", "not json at all " + PAYLOAD);
        mail.sluice("blocking", "true").runOnce();

        final A2aReader reader = new A2aReader();
        final EnvelopeCheck check = new EnvelopeCheck(CheckConfig.defaults());
        // Every detector of the default configuration, not only the first one there was.
        final DetectorRunner detectors = new DetectorRunner(mail.settings().detectors(),
                new Redactor(Redactor.Mode.PARTIAL));
        assertThat(mail.files(mail.feedback())).hasSize(3);
        for (final Path answer : mail.files(mail.feedback())) {
            final EnvelopeResult result = check.check(reader.parse(Files.readAllBytes(answer)));
            assertThat(result.findings()).extracting(Finding::ruleId)
                    .containsExactly("ENVELOPE/DATA_PART_NOT_ALLOWED");
            assertThat(detectors.run(result.texts())).isEmpty();
            assertThat(Files.readString(answer)).doesNotContain("\"kind\"");
        }
    }

    @Test
    void aTechnicalErrorLeavesTheMessageWhereItWasAndSaysSo() throws Exception {
        Assumptions.assumeFalse(isRoot(tmp), "root writes a directory whatever its permissions");
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("m.json", message(PROSE));
        mail.feedback().toFile().setWritable(false);
        try {
            final MessageSluice.RunSummary summary = mail.sluice("blocking", "true").runOnce();

            assertThat(summary.exitCode()).isEqualTo(2);
            assertThat(mail.incoming().resolve("m.json")).exists();
            assertThat(mail.files(mail.accepted())).isEmpty();
        } finally {
            mail.feedback().toFile().setWritable(true);
        }
    }

    @Test
    void aDirectoryHoldingRefusedOriginalsMustBeOwnerOnly() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        Files.setPosixFilePermissions(mail.rejected(),
                PosixFilePermissions.fromString("rwxr-xr-x"));

        final MessageSluice sluice = mail.sluice();

        assertThatThrownBy(sluice::checkDirectories)
                .isInstanceOf(ConfigException.class).hasMessageContaining("0700");
    }

    @Test
    void theErrorDirectoryMustBeOwnerOnlyToo() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        Files.setPosixFilePermissions(mail.error(), PosixFilePermissions.fromString("rwx---r-x"));

        assertThatThrownBy(mail.sluice()::checkDirectories)
                .isInstanceOf(ConfigException.class).hasMessageContaining("0700").hasMessageContaining("error");
    }

    @Test
    void aMissingDirectoryStopsTheStart() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        Files.delete(mail.feedback());

        assertThatThrownBy(mail.sluice()::checkDirectories)
                .isInstanceOf(ConfigException.class).hasMessageContaining("feedback");
    }

    @Test
    void aDirectoryHoldingRefusedOriginalsMustNotBeALink() throws Exception {
        final Mailbox mail = new Mailbox(tmp.resolve("mail"));
        final Path elsewhere = Files.createDirectories(tmp.resolve("elsewhere"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Files.delete(mail.rejected());
        Files.createSymbolicLink(mail.rejected(), elsewhere);

        assertThatThrownBy(mail.sluice()::checkDirectories)
                .isInstanceOf(ConfigException.class).hasMessageContaining("rejected");
    }

    /**
     * Codex's contract review: Sokar sends what is in accepted/ after an exit 2 too. That is safe because
     * accepted/ only ever holds what was checked and passed: a file that met a technical error is not judged,
     * nothing of it is filed, and it stays in incoming/ for the next pass.
     */
    @Test
    void aTechnicalErrorFilesNothingAndLeavesTheMessageWhereItWas() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        Assumptions.assumeFalse(isRoot(tmp), "root writes into a directory whatever its permissions");
        mail.deliver("good.json", message(PROSE));
        mail.deliver("bad.json", message("Here it is: " + PAYLOAD).replace("msg-7f6c8f6e", "msg-0a1b2c3d"));
        Files.setPosixFilePermissions(mail.accepted(), PosixFilePermissions.fromString("r-x------"));
        try {
            final MessageSluice.RunSummary summary = mail.sluice("blocking", "true").runOnce();

            assertThat(summary.exitCode()).isEqualTo(2);
            assertThat(summary.count(Outcome.ERROR)).isEqualTo(1);
            assertThat(mail.files(mail.rejected())).hasSize(1);
        } finally {
            Files.setPosixFilePermissions(mail.accepted(), PosixFilePermissions.fromString("rwx------"));
        }
        assertThat(mail.files(mail.accepted())).isEmpty();
        assertThat(mail.incoming().resolve("good.json")).exists();
    }

    /**
     * With receipts for clean messages switched off, a message only reporting lets through but blocking would have
     * refused is still answered: that answer is how the host learns it was flagged and holds it for a person.
     */
    @Test
    void aFlaggedMessageIsAnsweredEvenWithReceiptsOff() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("clean.json", message(PROSE));
        mail.deliver("flagged.json", message("Here it is: " + PAYLOAD).replace("msg-7f6c8f6e", "msg-0a1b2c3d"));

        mail.sluice("blocking", "false", "receiptOnApproval", "false").runOnce();

        assertThat(mail.files(mail.accepted())).hasSize(2);
        final List<Path> answers = mail.files(mail.feedback());
        assertThat(answers).hasSize(1);
        final JsonNode answer = readAnswer(answers.get(0));
        assertThat(answer.at("/parts/1/data/wouldReject").asBoolean()).isTrue();
        assertThat(answer.at("/metadata/inReplyToMessageId").asText()).startsWith("msg-0a1b2c3d");
    }

    /** Codex's review: only rejected/ and error/ were checked without following a link. */
    @Test
    void noMailboxDirectoryMayBeALink() throws Exception {
        final Mailbox mail = new Mailbox(tmp.resolve("mail"));
        final Path elsewhere = Files.createDirectories(tmp.resolve("elsewhere"));
        Files.delete(mail.accepted());
        Files.createSymbolicLink(mail.accepted(), elsewhere);

        assertThatThrownBy(mail.sluice()::checkDirectories)
                .isInstanceOf(ConfigException.class).hasMessageContaining("accepted").hasMessageContaining("link");
    }

    @Test
    void aDirectoryReplacedSinceTheStartStopsThePassBeforeAnythingIsFiled() throws Exception {
        final Mailbox mail = new Mailbox(tmp.resolve("mail"));
        final MessageSluice sluice = mail.sluice("blocking", "true");
        sluice.checkDirectories();
        mail.deliver("m.json", message(PROSE));
        final Path elsewhere = Files.createDirectories(tmp.resolve("elsewhere"));
        Files.delete(mail.accepted());
        Files.createSymbolicLink(mail.accepted(), elsewhere);

        assertThatThrownBy(sluice::runOnce).isInstanceOf(IOException.class).hasMessageContaining("replaced");
        assertThat(elsewhere).isEmptyDirectory();
        assertThat(mail.incoming().resolve("m.json")).exists();
    }

    @Test
    void aDirectoryHoldingRefusedOriginalsMustBeOwnedByTheUserTheFilterRunsAs() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        final MessageSluice sluice = mail.sluice();
        Assumptions.assumeFalse(isRoot(tmp), "as root, the directories are owned by the user this pretends to be");
        final String me = System.getProperty("user.name");
        System.setProperty("user.name", "root");
        try {
            assertThatThrownBy(sluice::checkDirectories)
                    .isInstanceOf(ConfigException.class).hasMessageContaining("owned");
        } finally {
            System.setProperty("user.name", me);
        }
    }

    @Test
    void whereNoPermissionsCanBeReadTheStartIsRefused() throws Exception {
        try (FileSystem zip = FileSystems.newFileSystem(tmp.resolve("mail.zip"), Map.of("create", "true"))) {
            final Path root = zip.getPath("/");
            for (final String dir : List.of("incoming", "accepted", "sent", "feedback", "rejected", "error")) {
                Files.createDirectories(root.resolve(dir));
            }
            // The premise: this filesystem has directories but no POSIX permissions.
            assertThat(Files.getFileAttributeView(root.resolve("rejected"), PosixFileAttributeView.class)).isNull();
            final FilterConfig base = new Mailbox(tmp.resolve("base")).settings().config();
            final FilterConfig config = new FilterConfig(root.resolve("incoming"), root.resolve("accepted"),
                    root.resolve("sent"), root.resolve("feedback"), root.resolve("rejected"), root.resolve("error"),
                    root.resolve(".lock"), base.check(), base.decision(), base.redaction(), base.blocking(),
                    base.receiptOnApproval(), base.stabilityDelay(), base.watchInterval());

            final MessageSluice sluice = new MessageSluice(config, List.of(), Mailbox.clock(), line -> { });

            assertThatThrownBy(sluice::checkDirectories)
                    .isInstanceOf(ConfigException.class).hasMessageContaining("permissions");
        }
    }

    @Test
    void watchingRunsAPassWhenAFileArrivesAndStopsWhenInterrupted() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        final MessageSluice sluice = mail.sluice("watchIntervalMillis", "50");
        final BlockingQueue<MessageSluice.RunSummary> passes = new LinkedBlockingQueue<>();
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final Thread watcher = new Thread(() -> {
            try {
                sluice.watch(passes::add);
            } catch (final Throwable ex) {
                failure.set(ex);
            }
        });
        watcher.start();
        try {
            mail.deliver("m.json", message(PROSE));

            final MessageSluice.RunSummary pass = passes.poll(10, TimeUnit.SECONDS);

            assertThat(pass).isNotNull();
            assertThat(pass.count(Outcome.ACCEPTED)).isEqualTo(1);
            assertThat(mail.accepted().resolve("m.json")).exists();
        } finally {
            watcher.interrupt();
            watcher.join(10_000);
        }
        assertThat(watcher.isAlive()).isFalse();
        assertThat(failure.get()).isNull();
    }

    @Test
    void aPassThatFailsOnADirectoryEndsTheWatch() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        final MessageSluice sluice = mail.sluice("watchIntervalMillis", "50");
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final Thread watcher = new Thread(() -> {
            try {
                sluice.watch(summary -> { });
            } catch (final Throwable ex) {
                failure.set(ex);
            }
        });
        watcher.start();
        try {
            // The corpus is where a duplicate id is looked up; without it, a pass would check less.
            Files.delete(mail.root.resolve("sent"));

            watcher.join(10_000);

            assertThat(watcher.isAlive()).isFalse();
            assertThat(failure.get()).isInstanceOf(java.nio.file.NoSuchFileException.class);
        } finally {
            watcher.interrupt();
            watcher.join(10_000);
        }
    }

    @Test
    void aLinkInIncomingIsUnprocessableAndNothingIsReadThroughIt() throws Exception {
        final Mailbox mail = new Mailbox(tmp.resolve("mail"));
        final Path outside = Files.writeString(tmp.resolve("outside.json"), message(PROSE));
        Files.createSymbolicLink(mail.incoming().resolve("link.json"), outside);

        final MessageSluice.RunSummary summary = mail.sluice("blocking", "true").runOnce();

        assertThat(mail.files(mail.accepted())).isEmpty();
        assertThat(summary.count(Outcome.UNPROCESSABLE)).isEqualTo(1);
        assertThat(ruleId(mail)).isEqualTo("UNPROCESSABLE/NOT_A_PLAIN_FILE");
        assertThat(outside).hasContent(message(PROSE));
    }

    @Test
    void aHardLinkedFileIsUnprocessable() throws Exception {
        final Mailbox mail = new Mailbox(tmp.resolve("mail"));
        final Path outside = Files.writeString(tmp.resolve("outside.json"), message(PROSE));
        Files.createLink(mail.incoming().resolve("m.json"), outside);

        final MessageSluice.RunSummary summary = mail.sluice("blocking", "true").runOnce();

        assertThat(mail.files(mail.accepted())).isEmpty();
        assertThat(summary.count(Outcome.UNPROCESSABLE)).isEqualTo(1);
        assertThat(ruleId(mail)).isEqualTo("UNPROCESSABLE/NOT_A_PLAIN_FILE");
    }

    @Test
    void whatLandsInAcceptedIsWhatWasCheckedEvenIfTheFileIsRewrittenMeanwhile() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        final Path file = mail.deliver("m.json", message(PROSE));
        final byte[] checked = Files.readAllBytes(file);

        // The detectors run between reading the file and filing it: the moment a rewrite would be unseen.
        mail.sluice(List.of(stub(t -> {
            try {
                Files.writeString(file, message("Here it is: " + PAYLOAD));
            } catch (final java.io.IOException ex) {
                throw new java.io.UncheckedIOException(ex);
            }
            return List.of();
        })), "blocking", "true").runOnce();

        assertThat(Files.readAllBytes(mail.accepted().resolve("m.json"))).isEqualTo(checked);
        // What changed after the check was not checked: it stays for the next pass rather than being dropped.
        assertThat(file).content().contains(PAYLOAD);
    }

    @Test
    void aFileNameOutsideThePatternIsUnprocessableAndNeverRepeated() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("report-" + PAYLOAD + "-" + PAYLOAD + "-" + PAYLOAD + ".json", message(PROSE));
        mail.deliver("with space.json", message(PROSE));

        final MessageSluice.RunSummary summary = mail.sluice("blocking", "true").runOnce();

        assertThat(mail.files(mail.accepted())).isEmpty();
        assertThat(summary.count(Outcome.UNPROCESSABLE)).isEqualTo(2);
        for (final Path answer : mail.files(mail.feedback())) {
            assertThat(readAnswer(answer).at("/parts/1/data/ruleId").asText()).isEqualTo("UNPROCESSABLE/FILE_NAME");
            assertThat(readAnswer(answer).at("/parts/1/data/sourceFileName").asText()).startsWith("sha256-");
        }
        assertNoWindowOf(PAYLOAD, mail.everythingThatLeaves(), "UNPROCESSABLE/FILE_NAME");
    }

    @Test
    void aSecretInAPlainFileNameIsRefusedLikeOneInATextAndNeverRepeated() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver(PAYLOAD.substring(0, 40) + ".json", message(PROSE));

        mail.sluice("blocking", "true").runOnce();

        assertThat(mail.files(mail.accepted())).isEmpty();
        assertThat(mail.files(mail.rejected())).hasSize(1);
        assertThat(readAnswer(mail.files(mail.feedback()).get(0)).at("/parts/1/data/findings/0/location").asText())
                .isEqualTo("fileName");
        assertNoWindowOf(PAYLOAD.substring(0, 40), mail.everythingThatLeaves(), "fileName");
    }

    @Test
    void theNamesHostsAndTransportsGiveAreAccepted() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        final List<String> names = List.of("msg-1.json", "a_b.c-d.json",
                "bob--2026-09-18T06-00-00Z--msg-7f6c8f6e-7f2e-4d5f-bf8c-1f3c50a29f12.json",
                "2026-09-30T07-39-00Z--matrix-5b0c8a52-9f0e-3c4a-8d1e-6a7b2c3d4e5f.json");
        for (int i = 0; i < names.size(); i++) {
            mail.deliver(names.get(i), """
                    {"messageId":"m-%d","role":"ROLE_AGENT","parts":[{"text":"Hello there."}]}""".formatted(i));
        }

        mail.sluice("blocking", "true").runOnce();

        for (final String name : names) {
            assertThat(mail.accepted().resolve(name)).exists();
        }
    }

    @Test
    void aSignatureThatIsALinkOrTooLargeMakesItsMessageUnprocessable() throws Exception {
        final Mailbox mail = new Mailbox(tmp.resolve("mail"));
        final Path outside = Files.writeString(tmp.resolve("outside.txt"), "not ours");
        mail.deliver("a.json", message(PROSE));
        Files.createSymbolicLink(mail.incoming().resolve("a.json.sig"), outside);
        mail.deliver("b.json", message(PROSE));
        Files.writeString(mail.incoming().resolve("b.json.sig"), "x".repeat(SshSignature.MAX_BYTES + 1));

        final MessageSluice.RunSummary summary = mail.sluice("blocking", "true").runOnce();

        assertThat(mail.files(mail.accepted())).isEmpty();
        assertThat(summary.count(Outcome.UNPROCESSABLE)).isEqualTo(2);
        for (final Path answer : mail.files(mail.feedback())) {
            assertThat(readAnswer(answer).at("/parts/1/data/ruleId").asText())
                    .isEqualTo("UNPROCESSABLE/SIGNATURE_UNUSABLE");
        }
    }

    @Test
    void onlyTheSignatureSokarWritesTravelsBesideAMessage() throws Exception {
        final byte[] real = sokarSignature();
        final Mailbox mail = new Mailbox(tmp.resolve("mail"));
        mail.deliver("good.json", message(PROSE));
        Files.write(mail.incoming().resolve("good.json.sig"), real);
        mail.deliver("smuggled.json", message(PROSE));
        final byte[] extra = (new String(real, java.nio.charset.StandardCharsets.US_ASCII) + PAYLOAD)
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        Files.write(mail.incoming().resolve("smuggled.json.sig"), extra);
        mail.deliver("small.json", message(PROSE));
        Files.writeString(mail.incoming().resolve("small.json.sig"), PAYLOAD);

        final MessageSluice.RunSummary summary = mail.sluice("blocking", "true").runOnce();

        assertThat(mail.files(mail.accepted())).extracting(p -> p.getFileName().toString())
                .containsExactlyInAnyOrder("good.json", "good.json.sig");
        assertThat(mail.accepted().resolve("good.json.sig")).hasBinaryContent(real);
        assertThat(summary.count(Outcome.UNPROCESSABLE)).isEqualTo(2);
        assertNoWindowOf(PAYLOAD, mail.everythingThatLeaves(), "UNPROCESSABLE/SIGNATURE_UNUSABLE");
    }

    @Test
    void aMessageThatCannotBeFiledIsAnsweredOnceHoweverOftenItIsTried() throws Exception {
        Assumptions.assumeFalse(isRoot(tmp), "root writes a directory whatever its permissions");
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("m.json", message(PROSE));
        final MessageSluice sluice = mail.sluice("blocking", "true");
        mail.accepted().toFile().setWritable(false);
        try {
            assertThat(sluice.runOnce().exitCode()).isEqualTo(2);
            assertThat(sluice.runOnce().exitCode()).isEqualTo(2);

            assertThat(mail.files(mail.feedback())).hasSize(1);
            assertThat(mail.incoming().resolve("m.json")).exists();
        } finally {
            mail.accepted().toFile().setWritable(true);
        }
    }

    @Test
    void aFileGoneBeforeItsTurnIsGoneAndNotAnError() throws Exception {
        final Mailbox mail = new Mailbox(tmp);
        mail.deliver("a.json", message(PROSE));
        final Path second = mail.deliver("b.json", """
                {"messageId":"m-2","role":"ROLE_AGENT","parts":[{"text":"Hello there."}]}""");

        final MessageSluice.RunSummary summary = mail.sluice(List.of(stub(t -> {
            try {
                Files.deleteIfExists(second);
            } catch (final java.io.IOException ex) {
                throw new java.io.UncheckedIOException(ex);
            }
            return List.of();
        }))).runOnce();

        assertThat(summary.exitCode()).isZero();
        assertThat(summary.results()).extracting(MessageSluice.FileResult::name).containsExactly("a.json");
    }

    static String ruleId(final Mailbox mail) throws Exception {
        return readAnswer(mail.files(mail.feedback()).get(0)).at("/parts/1/data/ruleId").asText();
    }

    static boolean isRoot(final Path dir) throws java.io.IOException {
        return Integer.valueOf(0).equals(Files.getAttribute(dir, "unix:uid"));
    }

    static JsonNode readAnswer(final Path file) throws Exception {
        return new A2aReader().parse(Files.readAllBytes(file));
    }

    static List<String> ruleIds(final JsonNode answer) {
        return answer.at("/parts/1/data/findings").findValuesAsText("ruleId");
    }

    /**
     * Neither the whole secret nor any eight characters of it in a row - in a haystack proven first to hold the
     * refusal, so that an empty or unrelated one cannot pass.
     */
    /** A signature as Sokar writes it; the filter checks its shape and never verifies it. */
    static byte[] sokarSignature() throws java.io.IOException {
        try (java.io.InputStream in = MessageSluiceTest.class.getResourceAsStream("/signatures/sokar-ed25519.sig")) {
            return in.readAllBytes();
        }
    }

    static void assertNoWindowOf(final String secret, final String haystack, final String expectedRule) {
        assertThat(haystack).as("what left the filter").isNotBlank().contains(expectedRule);
        for (int i = 0; i + 8 <= secret.length(); i++) {
            assertThat(haystack).doesNotContain(secret.substring(i, i + 8));
        }
    }

    interface Inspect {
        List<DetectorFinding> inspect(TextUnderCheck text);
    }

    static ContentDetector stub(final Inspect inspect) {
        return new ContentDetector() {

            @Override
            public String id() {
                return "test/stub@1";
            }

            @Override
            public Set<String> ruleIds() {
                return Set.of("STUB/HIT");
            }

            @Override
            public Set<String> categories() {
                return Set.of("STUB");
            }

            @Override
            public List<DetectorFinding> inspect(final TextUnderCheck text) {
                return inspect.inspect(text);
            }
        };
    }

}
