package org.fuin.sokar.msgsluice.filter.detect;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.fuin.sokar.msgsluice.filter.decision.Finding;
import org.fuin.sokar.msgsluice.filter.decision.Severity;
import org.junit.jupiter.api.Test;

/** What hides behind invisible characters and look-alikes is found, at its place in the original. */
class NormalizerTest {

    static final String PAYLOAD = "UEsDBBQAAAAIAGx0Mlt3b3JkL2RvY3VtZW50LnhtbKxVS27bMBC9C8E7RVJ2m9qw";

    @Test
    void aPayloadCutByZeroWidthCharactersIsFoundAndPointsIntoTheOriginal() {
        final StringBuilder hidden = new StringBuilder();
        for (int i = 0; i < PAYLOAD.length(); i += 6) {
            hidden.append(PAYLOAD, i, Math.min(PAYLOAD.length(), i + 6)).append('​');
        }
        final String original = "Here is the note: " + hidden + " and nothing else.";

        final List<Finding> findings = EncodedPayloadRatesTest.RUNNER
                .run(List.of(new TextUnderCheck("parts[0].text", 0, original)));

        assertThat(findings).extracting(Finding::ruleId).contains(Normalizer.INVISIBLE,
                EncodingSignatureDetector.BASE64);
        final Finding base64 = findings.stream().filter(f -> f.ruleId().equals(EncodingSignatureDetector.BASE64))
                .findFirst().orElseThrow();
        assertThat(original.substring(base64.start(), base64.end()).replace("​", "")).isEqualTo(PAYLOAD);
        assertThat(findings).filteredOn(f -> f.ruleId().equals(Normalizer.INVISIBLE))
                .allSatisfy(f -> assertThat(f.severity()).isEqualTo(Severity.BLOCKING));
        assertThat(EncodedPayloadRatesTest.judge(original).accepted()).isFalse();
    }

    @Test
    void lookAlikeLettersAreFoldedAndReported() {
        final Normalizer.Normalized n = Normalizer.normalize("Send the раssword now");

        assertThat(n.text()).isEqualTo("Send the password now");
        assertThat(n.findings()).extracting(DetectorFinding::ruleId).containsExactly(Normalizer.MIXED_SCRIPT);
        assertThat(n.findings().get(0).start()).isEqualTo(9);
    }

    @Test
    void emojiJoinersAndLineEndingsAreNotFindings() {
        final Normalizer.Normalized n = Normalizer.normalize("Thanks ❤️ and 👨‍💻!\r\nBye.");

        assertThat(n.findings()).isEmpty();
        assertThat(n.text()).contains("\nBye.").doesNotContain("\r");
        final int bye = n.text().indexOf("Bye");
        assertThat(n.toOriginal(bye, bye + 3)[0]).isEqualTo(n.original().indexOf("Bye"));
    }

    @Test
    void aCharacterThatNormalizesToAnInvisibleOneIsReported() {
        final Normalizer.Normalized n = Normalizer.normalize("Helloﾠthere.");

        assertThat(n.findings()).extracting(DetectorFinding::ruleId).containsExactly(Normalizer.INVISIBLE);
        assertThat(n.findings().get(0).start()).isEqualTo(5);
        assertThat(n.text()).isEqualTo("Hellothere.");
    }

    @Test
    void aTextPresentationSelectorAfterASymbolIsReported() {
        final StringBuilder bits = new StringBuilder("Weather today:");
        for (int i = 0; i < 10; i++) {
            bits.append(" ☃").append(i % 2 == 0 ? '︎' : '️');
        }

        final Normalizer.Normalized n = Normalizer.normalize(bits.toString());

        assertThat(n.findings()).extracting(DetectorFinding::ruleId).containsOnly(Normalizer.INVISIBLE).hasSize(10);
        assertThat(n.findings()).allSatisfy(f -> assertThat(f.severity()).isEqualTo(Severity.BLOCKING));
    }

    @Test
    void theSameSymbolWithAndWithoutEmojiPresentationIsReported() {
        final String bits = "Weather: ☃️ ☃ ☃️ ☃️ ☃ ☃ ☃️.";

        final Normalizer.Normalized n = Normalizer.normalize(bits);

        assertThat(n.findings()).extracting(DetectorFinding::ruleId).containsOnly(Normalizer.INVISIBLE).hasSize(4);
    }

    @Test
    void aSingleZeroWidthCharacterIsOnlySuspicious() {
        final Normalizer.Normalized n = Normalizer.normalize("Hello​there.");
        assertThat(n.findings()).singleElement().satisfies(f -> assertThat(f.severity()).isEqualTo(Severity.SUSPICIOUS));
        assertThat(n.text()).isEqualTo("Hellothere.");
    }

}
