package org.fuin.sokar.msgsluice.filter.detect;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * What only the entropy catches: an encoding nobody named, cut into word-sized pieces so no token is long and no
 * alphabet check fires.
 */
class EntropyDetectorTest {

    static String chunkedBase36(final long seed) {
        final byte[] bytes = new byte[96];
        new Random(seed).nextBytes(bytes);
        final String b36 = new BigInteger(1, bytes).toString(36).substring(0, 120);
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b36.length(); i += 10) {
            sb.append(b36, i, i + 10).append(' ');
        }
        return sb.toString().strip();
    }

    @Test
    void anUnnamedEncodingInWordSizedPiecesIsFound() {
        final String text = "Here are the numbers: " + chunkedBase36(5) + " as agreed.";

        assertThat(new EntropyDetector(4.5, 64, 16, 64).inspect(new TextUnderCheck("t", 0, text)))
                .extracting(DetectorFinding::ruleId).contains(EntropyDetector.RULE_ID);
        assertThat(EncodedPayloadRatesTest.judge(text).accepted()).isFalse();
        // No other detector sees it: this is the entropy's own catch.
        assertThat(EncodedPayloadRatesTest.RUNNER.run(List.of(new TextUnderCheck("t", 0, text))))
                .extracting(f -> f.ruleId()).containsOnly(EntropyDetector.RULE_ID);
    }

    @Test
    void longTechnicalProseIsNot() throws Exception {
        for (final String text : EncodedPayloadRatesTest.englishCorpus()) {
            assertThat(new EntropyDetector(4.5, 64, 16, 64).inspect(new TextUnderCheck("t", 0, text))).as(text)
                    .isEmpty();
        }
    }

}
