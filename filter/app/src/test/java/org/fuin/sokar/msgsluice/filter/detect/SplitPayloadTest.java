package org.fuin.sokar.msgsluice.filter.detect;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.function.Function;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * A payload cut into pieces by whitespace is the payload. Measured before the fix with the installed filter in
 * blocking mode: hex of 24 to 48 bytes in groups of 4 to 12 passed every time, base32 and base64 in short groups
 * mostly.
 */
class SplitPayloadTest {

    private static final List<String> SEPARATORS = List.of(" ", "\n", "\t", " \n ", "\\n", "\\r\\n");

    @ParameterizedTest
    @ValueSource(strings = {"base64", "base32", "base58", "hex"})
    void aPayloadCutIntoGroupsIsRefused(final String encoding) {
        final Function<Random, String> generator = Payloads.generators(64).get(encoding);
        final Random random = new Random(11);
        final List<String> missed = new ArrayList<>();
        int samples = 0;
        for (final int length : new int[] {32, 48, 64}) {
            for (final int group : new int[] {2, 4, 8, 12, 16, 24}) {
                for (final String separator : SEPARATORS) {
                    for (int i = 0; i < 10; i++) {
                        final String payload = Payloads.cut(generator.apply(random), length);
                        final String text = "Here it is: " + cut(payload, group, separator) + " - thanks.";
                        samples++;
                        if (EncodedPayloadRatesTest.judge(text).accepted()) {
                            missed.add(text);
                        }
                    }
                }
            }
        }
        System.out.printf("%s cut into groups: %d samples, %d missed%n", encoding, samples, missed.size());
        // The same bar as a contiguous run: under 1 % missed.
        assertThat(missed.size()).as("missed %s", missed).isLessThan(samples / 100 + 1);
    }

    @Test
    void theRuleNamesTheEncodingAndThatItWasCut() {
        final String hex = "3fa9c210 77b4e0d1 9c02aa5f 1e6b38c4 d05f7e92 6a1c4b08";
        final List<DetectorFinding> findings = new EncodingSignatureDetector(32)
                .inspect(new TextUnderCheck("t", 0, "Here it is: " + hex + " - thanks."));
        assertThat(findings).extracting(DetectorFinding::ruleId).contains(EncodingSignatureDetector.HEX);
        assertThat(findings).extracting(DetectorFinding::reason).anyMatch(r -> r.contains("cut into pieces"));
    }

    @Test
    void threeShortCommitHashesInARowAreIdsAndFiveArePayload() {
        // Measured on 13342 paragraphs agents wrote to each other: never more than three in a row.
        assertThat(EncodedPayloadRatesTest.judge("Pushed c22783a 150a9e3 aff037c today.").accepted()).isTrue();
        assertThat(EncodedPayloadRatesTest.judge("Pushed c22783a 150a9e3 aff037c 805cd21 8a2fbb1 today.")
                .accepted()).isFalse();
    }

    @Test
    void proseWithNumbersFlagsAndIdentifiersIsNotJoined() {
        for (final String text : List.of(
                "Run 283 had 2 of 214 red in B76 and B85 on the VM, both fixed in run 284 at 04:17Z today.",
                "deploy --vm sluice --key claude_key --repo handover/sokar/10f032b1 --skip-build --account",
                "TaskRunner VaultProxy NftRuleset EnvelopeCheck MessageArchive Calibration FileOps MessageSluice",
                "The legs took 15 30 and 19 21 minutes; 20 20 16 4 were served by the cache in 4 accounts.",
                "see MX12 MX13 MX14 B92 B93 B94 B96 F76 F79 F80 SL07 SL08 PJ18 PJ19 in the index")) {
            assertThat(EncodedPayloadRatesTest.judge(text).accepted()).as(text).isTrue();
        }
    }

    private static String cut(final String payload, final int group, final String separator) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < payload.length(); i += group) {
            if (i > 0) {
                sb.append(separator);
            }
            sb.append(payload, i, Math.min(payload.length(), i + group));
        }
        return sb.toString();
    }

}
