package org.fuin.sokar.msgsluice.filter.detect;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;

import org.fuin.sokar.msgsluice.filter.decision.Finding;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

/** One negative sample per encoding, embedded in an ordinary sentence, and what must pass. */
class EncodingSignatureDetectorTest {

    @ParameterizedTest
    @ValueSource(strings = {"base64", "base64url", "base32", "base58", "base85", "hex", "url-encoding",
            "quoted-printable", "uuencode", "pem", "data-uri", "binary", "ciphertext"})
    void everyEncodingInASentenceIsRefused(final String encoding) {
        final Map<String, Function<Random, String>> generators = Payloads.generators(48);
        final String payload = generators.get(encoding).apply(new Random(7));
        final String text = "Sure, here is the file you asked for: " + payload + " - let me know if it opens.";

        assertThat(EncodedPayloadRatesTest.judge(text).accepted()).as(payload).isFalse();
    }

    @Test
    void theEncodingIsNamed() {
        final List<DetectorFinding> findings = new EncodingSignatureDetector(32).inspect(new TextUnderCheck("t", 0,
                "Here: UEsDBBQAAAAIAGx0Mlt3b3JkL2RvY3VtZW50LnhtbKxVS27bMBC9C8E7RVJ2m9qw thanks."));
        assertThat(findings).extracting(DetectorFinding::ruleId).containsExactly(EncodingSignatureDetector.BASE64);
    }

    @Test
    void aChainOfUuidsIsHex() {
        final List<DetectorFinding> findings = new EncodingSignatureDetector(32).inspect(new TextUnderCheck("t", 0,
                "7f6c8f6e-7f2e-4d5f-bf8c-1f3c50a29f12-7f6c8f6e-7f2e-4d5f-bf8c-1f3c50a29f12"));
        assertThat(findings).extracting(DetectorFinding::ruleId).contains(EncodingSignatureDetector.HEX);
    }

    @Test
    void identifiersFileNamesPathsAndVersionsAreNotEncodings() {
        for (final String text : List.of("Read Q4-What-The-Build-Trusts-To-Run-Beside-Its-Secrets.md first.",
                "The class is org.fuin.sokar.msgsluice.filter.cli.Main in the jar.",
                "Set SOKAR_E2E_HOST=agent@192.0.2.10 and SOKAR_E2E_KEY=~/.ssh/test_key there.",
                "Set `SOKAR_E2E_HOST=agent@192.0.2.10`, `SOKAR_E2E_KEY=~/.ssh/test_key`. Now.",
                "The wrappers go to $XDG_DATA_HOME/sokar/filter/ and $XDG_DATA_HOME/sokar/transports/ now.",
                "The rest still read 2026.9.6 (16), 2026.9.10 (16) and 2026.9.11 (10), as before.",
                "Pushed as 90847bf, a3b7255 and 0601e3f; the build for 7b10bad is green.",
                "The answer went to feedback/20260916T082314Z--msg-b1d4a2c0.json and the original to rejected/.")) {
            final List<Finding> findings = EncodedPayloadRatesTest.RUNNER.run(List.of(new TextUnderCheck("t", 0,
                    text)));
            assertThat(EncodedPayloadRatesTest.judge(text).accepted()).as(text + " " + findings).isTrue();
        }
    }

}
