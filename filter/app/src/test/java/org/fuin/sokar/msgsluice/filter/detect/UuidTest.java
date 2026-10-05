package org.fuin.sokar.msgsluice.filter.detect;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Random;
import java.util.UUID;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * A few UUIDs are ids and pass; many are data, however they are separated. Found in practice: a list of 50
 * UUIDs separated by ", " passed, because each one counted as isolated and was masked - 800 bytes in one message.
 */
class UuidTest {

    static String ids(final int n, final String separator, final long seed) {
        final Random random = new Random(seed);
        final StringBuilder sb = new StringBuilder("The ids are ");
        for (int i = 0; i < n; i++) {
            sb.append(i == 0 ? "" : separator).append(new UUID(random.nextLong(), random.nextLong()));
        }
        return sb.append(" as requested.").toString();
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {"1|', '|true", "4|', '|true", "4|' and '|true", "5|', '|false",
            "5|' and '|false", "50|', '|false", "50|'; '|false", "2|' '|false", "2|'-'|false"})
    void aFewIdsPassAndManyDoNot(final int n, final String separator, final boolean accepted) {
        final String text = ids(n, separator, n);
        assertThat(EncodedPayloadRatesTest.judge(text).accepted()).as(text).isEqualTo(accepted);
    }

}
