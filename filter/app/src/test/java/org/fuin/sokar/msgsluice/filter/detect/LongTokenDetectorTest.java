package org.fuin.sokar.msgsluice.filter.detect;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

/** A token no English word could be. */
class LongTokenDetectorTest {

    private final LongTokenDetector detector = new LongTokenDetector(LongTokenDetector.DEFAULT_MAX_TOKEN_LENGTH);

    private List<DetectorFinding> inspect(final String text) {
        return detector.inspect(new TextUnderCheck("parts[0].text", 0, text));
    }

    @Test
    void base64InASentenceIsFoundWithItsOffsets() {
        final String payload = "UEsDBBQAAAAIAGx0Mlt3b3JkL2RvY3VtZW50LnhtbKxVS27bMBC9C8E7RVJ2m9qw";
        final String text = "Here is the file: " + payload + " thanks.";

        final List<DetectorFinding> findings = inspect(text);

        assertThat(findings).singleElement().satisfies(f -> {
            assertThat(f.ruleId()).isEqualTo(LongTokenDetector.RULE_ID);
            assertThat(text.substring(f.start(), f.end())).isEqualTo(payload);
            assertThat(f.reason()).doesNotContain(payload.substring(0, 8));
        });
    }

    @Test
    void ordinaryProseAndTheLongestWordsPass() {
        assertThat(inspect("The internationalization of counterrevolutionaries is incomprehensibilities.")).isEmpty();
        assertThat(inspect("")).isEmpty();
        assertThat(inspect("   \n\t ")).isEmpty();
    }

    @Test
    void aUrlWithoutQueryPassesButItsQueryIsChecked() {
        assertThat(inspect("See https://docs.example.com/guides/configuration/advanced/networking/proxies.html "
                + "for the details.")).isEmpty();

        final String text = "See https://example.com/a?q=UEsDBBQAAAAIAGx0Mlt3b3JkL2RvY3VtZW50LnhtbKxV for it.";
        assertThat(inspect(text)).singleElement()
                .satisfies(f -> assertThat(text.substring(f.start(), f.end())).startsWith("UEsD"));
    }

    @Test
    void pathsFileNamesAndIdsAreNotLongTokens() {
        assertThat(inspect("It is msg-7f6c8f6e-7f2e-4d5f-bf8c-1f3c50a29f12 in the log.")).isEmpty();
        assertThat(inspect("See filter/src/test/resources/fixtures/README.md and "
                + "[the design](006-Refuse-Encoded-Payloads_design.md).")).isEmpty();
    }

    @Test
    void theThresholdIsTheConfiguredOne() {
        final String token = "a".repeat(36);
        assertThat(inspect(token)).hasSize(1);
        assertThat(new LongTokenDetector(36).inspect(new TextUnderCheck("x", 0, token))).isEmpty();
    }

}
